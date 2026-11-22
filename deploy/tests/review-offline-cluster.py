"""Actual native stop with both production replica schedulers running; hosted CI only."""
import hashlib
import http.server
import json
import os
import threading
import time
from urllib.parse import urlencode


def run(*, repo, sql, api, ok, until, command, ports, admin, native, agent, processes):
    assert os.environ.get('GITHUB_ACTIONS') == 'true' and os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
    output = repo / '.tmp/review-offline-cluster'
    output.mkdir(exist_ok=False)
    observations, notifications = [], []

    class Sink(http.server.BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def do_POST(self):
            size = int(self.headers.get('Content-Length', '0'))
            assert self.path == '/notify' and 0 <= size <= 256 * 1024
            notifications.append({'atMillis': int(time.time() * 1000), 'idempotencyKey': self.headers.get('Idempotency-Key'),
                                  'body': json.loads(self.rfile.read(size))})
            self.send_response(200); self.end_headers()

    sink = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Sink)
    thread = threading.Thread(target=sink.serve_forever, daemon=True); thread.start()
    channel = None

    def facts(label):
        value = json.loads(sql(f"""SELECT json_build_object(
          'observedMillis',floor(extract(epoch FROM clock_timestamp())*1000)::bigint,
          'hosts',(SELECT json_agg(json_build_object('status',status,'lastHeartbeatMillis',floor(extract(epoch FROM last_heartbeat)*1000)::bigint,
                    'maintenanceUntil',maintenance_until,'offlineAlerted',offline_alerted)) FROM t_agent WHERE agent_id='{agent}'),
          'alerts',(SELECT COALESCE(json_agg(to_jsonb(t)), '[]') FROM t_alert t WHERE agent_id='{agent}' AND event_type='host_offline'),
          'deliveries',(SELECT COALESCE(json_agg(to_jsonb(d)), '[]') FROM t_alert_notify_delivery d WHERE alert_no IN
                    (SELECT alert_no FROM t_alert WHERE agent_id='{agent}' AND event_type='host_offline')))
        """))
        observations.append({'label': label, 'facts': value})
        assert all(process.poll() is None for process in processes), 'Both production replica schedulers must stay running'
        return value

    result = {'passed': False, 'releaseOrDeployment': False,
              'source': command(['git', 'rev-parse', 'HEAD']), 'arch': os.environ['GOARCH'],
              'agentId': agent, 'observations': observations}
    try:
        channel = int(sql(f"INSERT INTO t_notify_channel(name,type,webhook_url,min_severity,enabled) VALUES('review-offline-local','webhook','http://127.0.0.1:{sink.server_port}/notify',3,TRUE) RETURNING id").splitlines()[0])
        # Earlier scale traffic may deliberately disconnect this host. Establish a fresh incident boundary.
        online = until(lambda: (v if (v := facts('online'))['hosts'][0]['status'] == 1 and not v['hosts'][0]['offlineAlerted'] else None), 'Native online before scheduled offline test', 35)
        baseline = {row['alert_no'] for row in online['alerts']}
        result.update(online=online, baselineAlertNos=sorted(baseline))
        stopped = int(time.time() * 1000)
        result['stoppedAtMillis'] = stopped
        command(['docker', 'stop', '--time', '10', native], timeout=30)
        def incident():
            value = facts('offline-poll')
            rows = [row for row in value['alerts'] if row['alert_no'] not in baseline]
            return value if len(rows) == 1 and any(row['alert_no'] == rows[0]['alert_no'] and row['delivered_at'] for row in value['deliveries']) else None
        offline = until(incident, 'Two production schedulers record and notify one actual native outage', 110)
        result['offline'] = offline
        new = [row for row in offline['alerts'] if row['alert_no'] not in baseline]
        assert len(new) == 1 and new[0]['count'] == 1
        elapsed = offline['observedMillis'] - online['hosts'][0]['lastHeartbeatMillis']
        assert 59_000 <= elapsed <= 105_000, elapsed
        # The preceding 200-client scale run can produce more than one page of
        # unrelated offline alerts. Use the production filters to inspect this
        # host's incident, while retaining the global page as diagnostic evidence.
        unfiltered = [api(port, '/api/alerts?page=1&size=100', token=admin) for port in ports]
        result['unfilteredVisibleResponses'] = unfiltered
        visibility_query = '/api/alerts?' + urlencode({'agentId': agent, 'eventType': 'host_offline', 'page': 1, 'size': 100})
        visible = [api(port, visibility_query, token=admin) for port in ports]
        result.update(visibilityQuery=visibility_query, visibleResponses=visible)
        for response in visible:
            assert response['code'] == 0 and new[0]['alert_no'] in {row['alert_no'] for row in response['data']['list']}
            assert all(row['agent_id'] == agent and row['event_type'] == 'host_offline' for row in response['data']['list'])
        until(lambda: facts('next-scan-wait')['observedMillis'] >= offline['observedMillis'] + 31_000, 'Repeated real scans do not duplicate the incident', 40)
        repeated = facts('after-next-scan')
        assert len(repeated['alerts']) == len(offline['alerts']) and next(row for row in repeated['alerts'] if row['alert_no'] == new[0]['alert_no'])['count'] == 1
        own = [row for row in notifications if row['body'].get('alinksec', {}).get('agentId') == agent]
        assert len(own) == 1 and own[0]['idempotencyKey']
        command(['docker', 'start', native])
        recovered = until(lambda: (v if (v := facts('reconnect-poll'))['hosts'][0]['status'] == 1 and all(row['status'] == 2 for row in v['alerts']) else None), 'Native reconnect closes the offline incident', 35)
        ok(ports[0], '/api/hosts/' + agent + '/maintenance', admin, {'seconds': 3600})
        planned = int(time.time() * 1000); command(['docker', 'stop', '--time', '10', native], timeout=30)
        until(lambda: facts('maintenance-wait')['observedMillis'] >= planned + 95_000, 'Both schedulers suppress a real planned shutdown', 105)
        maintenance = facts('maintenance-complete')
        assert maintenance['hosts'][0]['status'] == 2 and len(maintenance['alerts']) == len(offline['alerts']) and all(row['status'] == 2 for row in maintenance['alerts'])
        assert len([row for row in notifications if row['body'].get('alinksec', {}).get('agentId') == agent]) == 1
        # Recover while maintenance still applies, then remove it for the existing failover checks.
        command(['docker', 'start', native])
        until(lambda: facts('final-reconnect')['hosts'][0]['status'] == 1, 'Native heartbeat after maintenance', 35)
        ok(ports[0], '/api/hosts/' + agent + '/maintenance', admin, {'seconds': 0})
        result.update(passed=True, source=command(['git', 'rev-parse', 'HEAD']), arch=os.environ['GOARCH'], agentId=agent,
                      heartbeatIntervalSeconds=1, offlineThresholdSeconds=60, scanSeconds=30, stoppedAtMillis=stopped,
                      online=online, offline=offline, afterNextScan=repeated, recovered=recovered, maintenance=maintenance,
                      plannedStoppedAtMillis=planned, baselineAlertNos=sorted(baseline), visibleResponses=visible,
                      observations=observations, notifications=notifications, bothReplicaProcessesAlive=True,
                      nativeSHA256=hashlib.sha256((repo / '.tmp/alinksec-agent').read_bytes()).hexdigest(),
                      scope='actual-native-agent-production-schedulers-two-replicas-local-test-webhook')
    finally:
        result['notifications'] = notifications
        if channel is not None:
            sql(f'DELETE FROM t_alert_notify_delivery WHERE channel_id={channel}')
            sql(f'DELETE FROM t_notify_channel WHERE id={channel}')
        sink.shutdown(); sink.server_close(); thread.join(timeout=3)
        (output / 'offline.json').write_text(json.dumps(result, indent=2) + '\n')
    return result
