#!/usr/bin/env python3
"""Verify original HTTP, protobufs, database facts, native timing and browser bindings."""
import argparse
import base64
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qs, urlsplit


def verify_offline(value, baseline=()):
    agent = value['agentId']; baseline = set(baseline)
    online, offline, repeated, recovered, maintenance = [value[key] for key in ['online', 'offline', 'afterNextScan', 'recovered', 'maintenance']]
    def alerts(facts): return [row for row in facts['alerts'] if row['alert_no'] not in baseline]
    incident = alerts(offline)
    assert len(incident) == 1 and incident[0]['count'] == 1 and incident[0]['status'] in [0, 1]
    number = incident[0]['alert_no']
    assert online['hosts'][0]['status'] == 1 and offline['hosts'][0]['status'] == 2
    assert 59_000 <= offline['observedMillis'] - online['hosts'][0]['lastHeartbeatMillis'] <= 105_000
    assert value['stoppedAtMillis'] >= online['hosts'][0]['lastHeartbeatMillis']
    assert repeated['observedMillis'] >= offline['observedMillis'] + 31_000
    assert len(alerts(repeated)) == 1 and alerts(repeated)[0]['count'] == 1
    assert recovered['hosts'][0]['status'] == 1 and alerts(recovered)[0]['status'] == 2
    assert maintenance['observedMillis'] >= value['plannedStoppedAtMillis'] + 95_000
    assert maintenance['hosts'][0]['status'] == 2 and maintenance['hosts'][0]['maintenanceUntil'] * 1000 > maintenance['observedMillis']
    assert len(alerts(maintenance)) == 1 and alerts(maintenance)[0]['status'] == 2
    for facts in [offline, repeated, recovered, maintenance]:
        delivery = [row for row in facts['deliveries'] if row['alert_no'] == number]
        assert len(delivery) == 1 and delivery[0]['delivered_at'] and delivery[0]['attempts'] == 1
    notices = [row for row in value['notifications'] if row['body'].get('alinksec', {}).get('agentId') == agent]
    assert len(notices) == 1 and notices[0]['body']['alinksec']['eventType'] == 'host_offline' and notices[0]['idempotencyKey']
    assert (value['offlineThresholdSeconds'], value['scanSeconds']) == (60, 30)


def protobuf(data):
    """Minimal independent protobuf wire reader for the retained fixture messages."""
    offset = 0; result = {}
    def varint():
        nonlocal offset
        value = 0
        for shift in range(0, 70, 7):
            byte = data[offset]; offset += 1; value |= (byte & 127) << shift
            if byte < 128: return value
        raise AssertionError('invalid varint')
    while offset < len(data):
        tag = varint(); field, wire = tag >> 3, tag & 7
        assert field not in result and field > 0
        if wire == 0: value = varint()
        elif wire == 2:
            size = varint(); value = data[offset:offset + size]; offset += size
            assert len(value) == size
        else: raise AssertionError('unexpected fixture wire type')
        result[field] = value
    assert offset == len(data)
    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('root', type=Path); parser.add_argument('source')
    parser.add_argument('--allow-working-tree', action='store_true'); parser.add_argument('--backend-only', action='store_true')
    parser.add_argument('--cluster', action='store_true'); parser.add_argument('--maintenance', action='store_true')
    args = parser.parse_args(); assert not (args.cluster and args.maintenance)
    root = args.root
    def read(name):
        path = root / name; assert 0 < path.stat().st_size < 32 * 1024 * 1024
        return json.loads(path.read_text())
    def digest(name): return hashlib.sha256((root / name).read_bytes()).hexdigest()
    if args.maintenance:
        result, raw = read('result.json'), read('restore-observations.json')
        assert result['passed'] and raw['source'] == args.source and raw['mode'] == result['mode']
        assert len(result['checks']) == 7 and result['sameExistingContainerIds'] and result['persistedJwtPreserved']
        assert result['remainingHelpers'] == 0 and result['metadataPermissions'] == 'private'
        before = result['identityBefore']
        assert all(re.fullmatch('[a-f0-9]{64}', value) for value in before.values()) and before['caSHA256'] == result['caSha256']
        assert [row['expected'] for row in raw['observations']] == ['before', 'before-interruption', 'before-interruption', 'after-automatic-checkpoint', 'before-interruption']
        for row in raw['observations']:
            assert row['expected'] == row['databaseValue'] and len(row['files']) == 2
            assert all(file['value'] == row['expected'] and file['ownership'] == '1001:1001:640' for file in row['files'])
            assert all(row[key] == before[key] for key in before)
            assert row['coreHostSQL'] == row['coreHostHTTP']['hostname'] == 'operations-before' and row['coreHostHTTP']['agent_id'] == 'ops-maintenance'
            assert row['coreHostResponse']['code'] == 0 and row['coreHostResponse']['data']['list'] == [row['coreHostHTTP']]
            if result['mode'] == 'postgres': assert row['restrictedPrivilegesSQL'] == 't'
        verdict = {'accepted': True, 'source': args.source, 'database': result['mode'], 'realRestoreObservations': len(raw['observations']),
                   'originalSessionAndCoreHostVerified': True, 'rawSHA256': digest('restore-observations.json')}
    elif args.cluster:
        value = read('offline.json'); cluster = read('cluster-result.json')
        assert value['passed'] and value['source'] == cluster['head'] == args.source
        assert value['bothReplicaProcessesAlive'] and value['heartbeatIntervalSeconds'] == 1
        assert cluster['passed'] and cluster['remainingOwnedContainers'] == cluster['remainingJavaProcesses'] == 0
        assert value['nativeSHA256'] == cluster['agentSha256'] and not value['releaseOrDeployment']
        verify_offline(value, value['baselineAlertNos'])
        number = next(row['alert_no'] for row in value['offline']['alerts'] if row['alert_no'] not in value['baselineAlertNos'])
        assert len(value['visibleResponses']) == 2
        query = urlsplit(value['visibilityQuery'])
        assert query.path == '/api/alerts' and parse_qs(query.query) == {
            'agentId': [value['agentId']], 'eventType': ['host_offline'], 'page': ['1'], 'size': ['100']}
        for response in value['visibleResponses']:
            assert response['code'] == 0 and number in {row['alert_no'] for row in response['data']['list']}
            assert all(row['agent_id'] == value['agentId'] and row['event_type'] == 'host_offline' for row in response['data']['list'])
        assert len(value['unfilteredVisibleResponses']) == 2
        for response in value['unfilteredVisibleResponses']:
            assert response['code'] == 0 and len(response['data']['list']) <= 100
            assert response['data']['total'] >= len(response['data']['list'])
        verdict = {'accepted': True, 'source': args.source, 'replicas': 2, 'actualNativeStop': True, 'offlineSHA256': digest('offline.json')}
    else:
        result, provenance = read('result.json'), read('provenance.json')
        assert result['passed'] and not result['releaseOrDeployment'] and not result['remainingOwnedContainers']
        assert not result.get('cleanupErrors', 0)
        assert result['privateDirectoryRemoved'] and result['cleanupVerified'] and result['credentialsCompared'] >= 5
        assert provenance['source'] == args.source and (provenance['clean'] or args.allow_working_tree)
        assert not provenance['productionJarContainsFixture'] and provenance['fixtureClasses']
        assert all(re.fullmatch('[a-f0-9]{64}', value) for value in [*provenance['binaries'].values(), *provenance['fixtureClasses'].values()])
        cleanup = read('cleanup.json')
        assert all(not row['running'] and not row['oomKilled'] and row['exitCode'] == row['expectedExitCode'] for row in cleanup)
        assert sum(row['termination'] == 'SIGTERM' and row['expectedExitCode'] == 143 for row in cleanup) == 1
        assert all(row['expectedExitCode'] == 0 for row in cleanup if row['termination'] != 'SIGTERM')
        assert all(row['availableMiB'] >= 384 and row['fullPSI'] <= 10 for row in read('resources.json'))
        http = read('http.json'); captures = read('captures.json'); stages = read('engine-stages.json')
        assert len(http) == result['actualHttpTransactions'] and all(row['index'] == i for i, row in enumerate(http))
        def data(row):
            assert row['status'] == 200 and row['response'].get('code', 0) == 0
            return row['response'].get('data', row['response'])
        def labelled(name): return [row for row in http if row['label'] == name]
        down = labelled('dependency-down-readiness'); assert len(down) == 16
        assert all(row['status'] == 503 and row['response']['ready'] is False and row['durationMillis'] < 5000 for row in down)
        assert labelled('dependency-down-liveness')[0]['status'] == 200
        readiness = read('readiness.json'); bounds = readiness['probeResourcesDuringOutage']
        assert bounds['maximumPool'] == 1 and bounds['probeWorkers'] <= 1 and bounds['probeQueue'] <= 1
        assert readiness['identityBefore'] == readiness['identityAfter'] and any(name.endswith('ca.crt') for name in readiness['identityBefore'])
        assert 'jwt.secret' in readiness['identityBefore']
        assert labelled('dependency-recovered-core-query')[0]['status'] == 200
        data(labelled('dependency-recovered-core-query')[0])
        if result['database'] == 'postgres':
            failure = labelled('dependency-down-core-query')[0]
            assert failure['status'] != 200 or failure['response'].get('code', 0) != 0
        offline = read('offline.json'); verify_offline(offline)
        maintenance_request = labelled('actual-maintenance-window')[0]
        data(maintenance_request)
        assert maintenance_request['path'] == '/api/hosts/' + offline['agentId'] + '/maintenance' and maintenance_request['request'] == {'seconds': 3600}
        assert [row for row in read('notifications.json') if row['body'].get('alinksec', {}).get('agentId') == offline['agentId']] == offline['notifications']
        assert offline['heartbeatIntervalSeconds'] == 10 and offline['agentStop'] == {'exitCode': 0, 'oomKilled': False}
        assert len(offline['maintenance']['excludedFixtures']) == 3 and all(row['alerts'] == 0 for row in offline['maintenance']['excludedFixtures'])
        visible = data(labelled('native-offline-visible-alert')[0])
        assert offline['offline']['alerts'][0]['alert_no'] in {row['alert_no'] for row in visible['list']}
        fixtures = read('response-facts.json'); facts = fixtures['facts']; reports = fixtures['reports']
        assert len(reports) == 64 and len({row['reportId'] for row in reports}) == 64
        for i, row in enumerate(reports):
            wire = protobuf(base64.b64decode(row['protobufBase64'], validate=True)); event = protobuf(wire[15])
            assert wire[1] == b'ops-responses' and wire[2].decode() == row['reportId'] and wire[4] == 1 and event[6].decode() == row['action']
            assert row['dispatches'] == 2
            assert row['action'] == (('killed' if i % 2 == 0 else 'alert_only') if i < 60 else ['kill_failed', 'queued', 'sent', 'running'][i - 60])
            matching = [fact for fact in facts if fact['report_id'] == row['reportId']]
            assert len(matching) == (1 if row['action'] == 'killed' else 0)
        isolation = fixtures['isolation']; assert len(isolation) == 4
        for i, row in enumerate(isolation):
            pulse = protobuf(base64.b64decode(row['pulseBase64'], validate=True))
            assert pulse[8] == 1 and pulse[6] == (b'applying' if i == 0 else b'active')
            assert bool(pulse.get(7, 0)) == (i >= 2) and len(row['facts']) == (1 if i >= 2 else 0)
        assert isolation[2]['facts'] == isolation[3]['facts']
        assert sorted(row['status'] for row in fixtures['commands']) == [0, 1, 4, 5]
        assert len(facts) == 34 and len({(row['agent_id'], row['report_id']) for row in facts}) == len(facts)
        independent = read('response-sql.json'); window = independent['window']
        start, through = window['automated30dFrom'], window['automated30dThrough']
        assert through - start == 30 * 24 * 3600 * 1000
        assert facts == independent['sql']['facts']
        counted = [row for row in facts if start <= row['received_at'] <= through]
        assert len(counted) == window['automated30d'] == independent['sql']['count'] == result['successfulResponseCount'] > 20
        assert 'ops-future' not in {row['report_id'] for row in counted} and len(counted) == len(facts) - 4
        midnight = {row['report_id']: row['received_at'] for row in facts if 'midnight' in row['report_id']}
        assert midnight['ops-at-midnight'] - midnight['ops-before-midnight'] == 1
        zone = timezone(timedelta(hours=8))
        bucket = lambda millis: datetime.fromtimestamp(millis / 1000, zone).date().isoformat()
        assert bucket(midnight['ops-at-midnight']) != bucket(midnight['ops-before-midnight'])
        assert len(captures) == 59 and len(stages) == 58
        names = {capture['name']: capture for capture in captures}; assert len(names) == 59
        engine_keys = ['file_watch', 'windows_login', 'clamav', 'yara', 'scap']
        assert {(stage['key'], stage['stage']) for stage in stages} == {('file_watch', stage) for stage in ['empty', 'healthy', 'linux-only']} | {
            (key, stage) for key in engine_keys for stage in ['missing', 'failed', 'disabled', 'unsupported', 'stale-received', 'stale-probe', 'future-received', 'offline', 'global-off', 'partial', 'beyond-page']}
        for capture in captures:
            rows = [http[index] for index in capture['responses']]; assert len(rows) == 8
            for row in rows: data(row)
            summary = data(rows[0])['alerts']; assert summary['automated30d'] == len(counted)
            trend = data(rows[1]); expected = Counter(bucket(row['received_at'])[-5:] for row in facts if row['received_at'] <= rows[1]['atMillis'] + rows[1]['durationMillis'])
            assert len(trend) == 7 and all(row['blocked'] == expected[row['date']] for row in trend)
        for stage in stages:
            raw = data(http[stage['seedObservation']]); capture = names[stage['captured']]
            engines = {row['key']: row for row in data(http[capture['responses'][6]])}
            assert len(engines) == 9 and raw['stage'] == stage['stage'] and raw['engine'] == stage['key']
            assert all(engines[key]['status'] != 'ready' and engines[key]['ready'] == 0 for key in ['process', 'file_tamper', 'login', 'decoy'])
            assert all(engines[key]['status'] == ('offline' if stage['stage'] == 'offline' else 'unknown') for key in ['process', 'file_tamper', 'login', 'decoy'])
            count = len(raw['hosts']); assert count == (0 if stage['stage'] == 'empty' else 121 if stage['stage'] == 'beyond-page' else 2)
            if stage['stage'] == 'global-off': assert all(not row['protect_enabled'] for row in raw['hosts'])
            for key in engine_keys:
                engine = engines[key]
                rows = raw['facts'][key]; assert all(row['agent_id'] in {host['agent_id'] for host in raw['hosts']} for row in rows)
                if stage['stage'] == 'linux-only' and key == 'windows_login':
                    assert engine['total'] == engine['ready'] == engine['coverage'] == 0 and engine['status'] == 'unknown'
                    assert all(host['os_type'] == 1 for host in raw['hosts']) and all(row['contract'] == 0 for row in rows)
                    continue
                assert engine['total'] == count and sum(engine['counts'].values()) == count
                assert engine['coverage'] == (engine['ready'] * 100 // count if count else 0)
                negative = stage['stage'] not in ['empty', 'healthy', 'linux-only', 'global-off'] and (key == stage['key'] or stage['stage'] == 'offline')
                if stage['stage'] == 'empty': assert engine['status'] == 'unknown' and not rows
                elif not negative:
                    assert engine['status'] == 'ready' and engine['ready'] == count and len(rows) == count
                    for row in rows:
                        assert row['contract'] == 1
                        coverage = json.loads(row['coverage'])
                        assert coverage['state'] == ('watching' if key == 'file_watch' else 'polling' if key == 'windows_login' else 'ready')
                        if key == 'file_watch': assert coverage['roots'] > 0 and coverage['watches'] > 0
                        if key == 'windows_login': assert coverage['audit_success'] and coverage['audit_failure']
                        if key in ['clamav', 'yara', 'scap']: assert coverage['version']
                else:
                    assert engine['status'] != 'ready'
                    if stage['stage'] in ['partial', 'beyond-page']:
                        assert engine['status'] == 'partial' and engine['ready'] == count - 1 and len(rows) == count - 1
                    elif stage['stage'] == 'missing': assert not rows and engine['status'] == 'unknown'
                    else:
                        assert len(rows) == count and engine['ready'] == 0
                        if stage['stage'] == 'unsupported': assert all(row['contract'] == 0 for row in rows)
                        if stage['stage'] == 'offline': assert all(row['status'] == 2 for row in raw['hosts'])
                        expected_state = {'disabled': 'disabled', 'unsupported': 'unsupported', 'stale-received': 'stale', 'future-received': 'stale',
                                          'offline': 'offline', 'stale-probe': 'stalled' if key in ['file_watch', 'windows_login'] else 'stale',
                                          'failed': 'degraded' if key == 'file_watch' else 'failed' if key == 'windows_login' else 'unavailable'}[stage['stage']]
                        assert engine['status'] == expected_state
                        at = http[capture['responses'][6]]['atMillis']
                        if stage['stage'] == 'stale-received': assert all(at - row['observed_at'] > 90_000 for row in rows)
                        if stage['stage'] == 'future-received': assert all(row['observed_at'] > at + 30_000 for row in rows)
                        if stage['stage'] in ['failed', 'disabled']:
                            assert all(json.loads(row['coverage'])['state'] == (expected_state if stage['stage'] == 'failed' else 'disabled') for row in rows)
                        if stage['stage'] == 'stale-probe':
                            field = 'last_sync_at' if key == 'file_watch' else 'last_poll_at' if key == 'windows_login' else 'observed_at'
                            scale = 1 if key in ['file_watch', 'windows_login'] else 1000
                            assert all(at - json.loads(row['coverage'])[field] * scale > (360_000 if key == 'scap' else 90_000) for row in rows)
        verdict = {'accepted': True, 'source': args.source, 'database': result['database'], 'actualHttp': len(http), 'engineStages': len(stages),
                   'confirmedResponses': len(counted), 'httpSHA256': digest('http.json'), 'browserVerified': False}
        if not args.backend_only:
            browser = read('browser/result.json')
            assert browser['passed'] and not browser['errors'] and not browser['backendBrowserOverlap']
            assert browser['scope'] in (['production-bundle', 'current-source-routed-preview'] if args.allow_working_tree else ['production-bundle'])
            assert browser['httpSHA256'] == digest('http.json') and browser['capturesSHA256'] == digest('captures.json')
            assert set(browser['checks']) == set(names) | {'poll-failure-clears-readiness-and-recovery-restores-captured-state', 'hung-poll-times-out-and-clears-readiness'}
            assert len(browser['screenshots']) == 7
            for row in browser['screenshots']: assert row['sha256'] == digest('browser/' + row['name'])
            for row in browser['requests']:
                if row.get('injectedTransportFailure'): continue
                original = http[row['index']]
                def js_numbers(value):
                    if isinstance(value, float) and value.is_integer(): return int(value)
                    if isinstance(value, dict): return {key: js_numbers(item) for key, item in value.items()}
                    if isinstance(value, list): return [js_numbers(item) for item in value]
                    return value
                canonical = json.dumps(js_numbers(original['response']), ensure_ascii=False, separators=(',', ':')).encode()
                assert row['index'] in names[row['capture']]['responses'] and row['responseSHA256'] == hashlib.sha256(canonical).hexdigest()
            assert all({row['index'] for row in browser['requests'] if row['capture'] == capture['name'] and not row.get('injectedTransportFailure')} == set(capture['responses']) for capture in captures)
            verdict['browserVerified'] = True
    (root / 'verdict.json').write_text(json.dumps(verdict, indent=2) + '\n'); print(json.dumps(verdict))


if __name__ == '__main__': main()
