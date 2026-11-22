#!/usr/bin/env python3
"""Bounded, disposable real-process acceptance. Never starts a Compose stack."""
import argparse
import collections
import contextlib
import hashlib
import http.server
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('--database', choices=['sqlite', 'postgres'], required=True)
args = parser.parse_args()
REPO = Path(__file__).resolve().parents[2]
OUTPUT = REPO / '.tmp/review-runtime' / args.database
PRIVATE = REPO / ('.tmp/review-runtime-private-' + uuid.uuid4().hex)
OUTPUT.mkdir(parents=True, exist_ok=False)
PRIVATE.mkdir(mode=0o700)
CONTROL = PRIVATE / 'control'
CONTROL.mkdir()
DATA = PRIVATE / 'data'
DATA.mkdir()
WORK = PRIVATE / 'agent'
WORK.mkdir(mode=0o700)
JAVA_IMAGE = 'maven:3.9.9-eclipse-temurin-21'
AGENT_IMAGE = 'ubuntu:24.04'
containers, child_processes, observations = [], [], []
prefix = 'alinksec-review-' + uuid.uuid4().hex[:10]
password, enroll_token, owner_password, app_password = [secrets.token_urlsafe(24) for _ in range(4)]
masked = [password, enroll_token, owner_password, app_password]
if os.environ.get('GITHUB_ACTIONS') == 'true':
    for secret in masked:
        print('::add-mask::' + secret, flush=True)
passed = False
result = {}
server_count = agent_count = 0
native = REPO / '.tmp/alinksec-agent'
fixture = REPO / '.tmp/review-runtime-fixture'
jar = REPO / 'server/alinksec-bootstrap/target/alinksec-bootstrap.jar'


def redact(value):
    for secret in masked:
        value = value.replace(secret, '[redacted]')
    return value


def command(argv, *, timeout=90, log=None):
    completed = subprocess.run([str(a) for a in argv], capture_output=True, text=True, timeout=timeout)
    if log:
        (OUTPUT / log).write_text(redact(completed.stdout + completed.stderr))
    if completed.returncode:
        raise RuntimeError(redact(str(argv[0]) + ': ' + (completed.stdout + completed.stderr)[-1800:]))
    return completed.stdout.strip()


def until(predicate, label, timeout=60):
    deadline = time.monotonic() + timeout
    failure = None
    while time.monotonic() < deadline:
        try:
            value = predicate()
            if value:
                return value
        except (OSError, ValueError, RuntimeError, AssertionError) as error:
            failure = error
        time.sleep(.1)
    raise AssertionError(label + ': ' + redact(str(failure)))


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def api(path, token=None, body=None, *, method=None, expected=200, target=None):
    available = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))) // 1024
    pressure = next(line for line in Path('/proc/pressure/memory').read_text().splitlines() if line.startswith('full '))
    full = float(next(value.split('=')[1] for value in pressure.split() if value.startswith('avg10=')))
    if available < 384 or full > 10:
        raise MemoryError(f'resource watchdog: availableMiB={available}, fullPSI={full}')
    request = urllib.request.Request(f'http://127.0.0.1:{target or http_port}' + path,
            data=None if body is None else json.dumps(body).encode(), method=method,
            headers={'Content-Type': 'application/json', **({'Authorization': 'Bearer ' + token} if token else {})})
    try:
        response = urllib.request.urlopen(request, timeout=8)
    except urllib.error.HTTPError as error:
        response = error
    with response:
        value = json.load(response)
        assert response.status == expected, (path, response.status, expected)
        if expected == 200 and 'code' in value:
            assert value['code'] == 0, (path, value['code'])
            return value.get('data')
        return value


def login():
    return api('/api/auth/login', body={'username': 'admin', 'password': password})['token']


def container(name, image, parameters=(), *, memory=256, environment=None, root=False, entrypoint=None):
    argv = ['docker', 'run', '-d', '--name', name, '--network=host', f'--memory={memory}m', f'--memory-swap={memory}m',
            '--cpus=1', '--pids-limit=256', '--label', 'alinksec.review-runtime=' + prefix,
            '-v', f'{REPO}:{REPO}', '-w', str(PRIVATE)]
    if not root:
        argv += ['--user', f'{os.getuid()}:{os.getgid()}']
    if entrypoint:
        argv += ['--entrypoint', entrypoint]
    for key, value in (environment or {}).items():
        argv += ['-e', key + '=' + value]
    ident = command([*argv, image, *parameters], timeout=180)
    containers.append(ident)
    return ident


def state(ident):
    return json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', ident]))


def stop(ident, *, kill=False):
    before = state(ident)
    if before['Running']:
        command(['docker', 'kill', '--signal=KILL', ident] if kill else ['docker', 'stop', '-t', '8', ident])
    after = state(ident)
    assert not after['OOMKilled'], after
    if kill:
        assert after['ExitCode'] == 137, after
    return {'beforePid': before['Pid'], 'exitCode': after['ExitCode'], 'oomKilled': after['OOMKilled']}


def start_server():
    global server_count
    server_count += 1
    with contextlib.suppress(FileNotFoundError):
        (CONTROL / 'ready.json').unlink()
    ident = container(prefix + '-java-' + str(server_count), JAVA_IMAGE,
            ['-Xmx256m', '-Xss512k', '-XX:MaxMetaspaceSize=160m', '-XX:MaxDirectMemorySize=96m',
             '-XX:ReservedCodeCacheSize=48m', '-XX:ActiveProcessorCount=1',
             '-Dloader.main=review.runtime.RuntimeFixtureServer',
             '-Dloader.path=' + str(PRIVATE / 'fixture-classes'),
             '-cp', jar, 'org.springframework.boot.loader.launch.PropertiesLauncher',
             '--server.address=127.0.0.1', '--server.port=' + str(http_port), '--alinksec.server.port=' + str(grpc_port),
             '--alinksec.metrics.vm-base-url=http://127.0.0.1:' + str(downstream.server_port)],
            memory=640, environment=environment, entrypoint='java')
    until(lambda: (CONTROL / 'ready.json').is_file() and state(ident)['Running'] and api('/api/health') is None, 'actual JVM startup and seed completion', 90)
    return ident


def probe(agent, report='', source=''):
    return api('/api/review-runtime/probe?' + urllib.parse.urlencode({'agent': agent, 'report': report, 'source': source}), admin)


def start_agent():
    global agent_count
    agent_count += 1
    return container(prefix + '-agent-' + str(agent_count), AGENT_IMAGE,
            ['sh', PRIVATE / 'agent-entry.sh'], memory=192,
            environment={'GOMEMLIMIT': '96MiB', 'GOMAXPROCS': '1', 'ALINKSEC_TEST_TOKEN': enroll_token})


def seed(report, source):
    cfg = PRIVATE / 'spool.json'
    cfg.write_text(json.dumps({'Mode': 'spool', 'Workdir': str(WORK), 'ReportID': report, 'Source': source, 'RecordFile': str(PRIVATE / (report + '.pb'))}))
    cfg.chmod(0o600)
    return json.loads(command([fixture, '--config', cfg]))


def queued(report):
    path = WORK / 'queue/pending.jsonl'
    if not path.exists():
        return False
    return any(json.loads(line).get('reportId') == report for line in path.read_text().splitlines() if line)


class Downstream(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass

    def do_POST(self):
        declared = int(self.headers['Content-Length'])
        body = self.rfile.read(min(declared, 256 * 1024 + 1))
        at = time.time_ns() // 1_000_000
        mode = downstream_mode[0]
        with downstream_lock:
            downstream_requests.append({'at': at, 'mode': mode, 'bytes': declared, 'lines': body.count(b'\n'),
                                        'sha256': hashlib.sha256(body).hexdigest()})
            if self.path != '/api/v1/import/prometheus' or declared != len(body) or not 0 < declared <= 256 * 1024:
                downstream_errors.append({'path': self.path, 'declaredBytes': declared, 'readBytes': len(body)})
        if downstream_errors:
            self.send_response(413)
            self.end_headers()
            return
        if mode == 'slow':
            time.sleep(6.2)  # Exceeds the unmodified production 5-second timeout.
        with contextlib.suppress(BrokenPipeError, ConnectionResetError):
            self.send_response(204)
            self.end_headers()


downstream_mode = ['healthy']
downstream_requests = []
downstream_errors = []
downstream_lock = threading.Lock()
downstream = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Downstream)
downstream.daemon_threads = True
threading.Thread(target=downstream.serve_forever, daemon=True).start()
http_port, grpc_port = port(), port()
environment = {'SPRING_PROFILES_ACTIVE': args.database, 'ALINKSEC_METRICS_ENABLED': 'true', 'ALINKSEC_CLUSTER_ENABLED': 'false',
        'ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD': password, 'ALINKSEC_BOOTSTRAP_ENROLL_TOKEN': enroll_token,
        'ALINKSEC_SQLITE_PATH': str(DATA / 'alinksec.db'), 'ALINKSEC_JWT_SECRET': '',
        'ALINKSEC_CERT_DIR': str(DATA / 'certs'), 'ALINKSEC_WEB_TLS_DIR': str(DATA / 'web-tls'),
        'ALINKSEC_LIBRARY_WORK_DIR': str(DATA / 'libraries'), 'ALINKSEC_REVIEW_CONTROL_DIR': str(CONTROL),
        'SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE': '4',
        'ALINKSEC_METRICS_VM_BASE_URL': 'http://127.0.0.1:' + str(downstream.server_port)}

try:
    assert native.is_file() and fixture.is_file() and jar.is_file()
    with zipfile.ZipFile(jar) as packaged:
        assert not any(name.startswith('BOOT-INF/classes/review/runtime/') for name in packaged.namelist()), 'fault control must not enter the production jar'
    shutil.copytree(REPO / 'server/alinksec-bootstrap/target/test-classes/review/runtime', PRIVATE / 'fixture-classes/review/runtime')
    (OUTPUT / 'binary-provenance.json').write_text(json.dumps({
        'productionJarContainsFaultControl': False,
        'sha256': {str(path.relative_to(REPO)): hashlib.sha256(path.read_bytes()).hexdigest() for path in [native, fixture, jar]},
        'fixtureClasses': {str(path.relative_to(PRIVATE / 'fixture-classes')): hashlib.sha256(path.read_bytes()).hexdigest()
                           for path in sorted((PRIVATE / 'fixture-classes').rglob('*.class'))}}, indent=2) + '\n')
    available = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))) // 1024
    assert available >= 1408, ('insufficient memory for bounded runtime scenario', available)
    (OUTPUT / 'resource-start.json').write_text(json.dumps({'availableMiB': available, 'memoryPSI': Path('/proc/pressure/memory').read_text(),
            'limitsMiB': {'server': 640, 'agent': 192, 'postgres': 256}, 'javaHeapMiB': 256, 'workersPerProcess': 1}) + '\n')
    if args.database == 'postgres':
        pg_port = port()
        # Initialize from the tracked schema, then apply the tracked migration history and restricted role.
        pg = container(prefix + '-pg', 'postgres:17', ['-p', str(pg_port), '-c', 'listen_addresses=127.0.0.1', '-c', 'shared_buffers=32MB', '-c', 'max_connections=20'],
                root=True, environment={'POSTGRES_USER': 'alinksec', 'POSTGRES_PASSWORD': owner_password, 'POSTGRES_DB': 'alinksec'})
        until(lambda: command(['docker', 'exec', pg, 'pg_isready', '-h', '127.0.0.1', '-p', str(pg_port), '-U', 'alinksec']), 'isolated PostgreSQL final TCP startup')
        for schema in sorted((REPO / 'deploy/sql').glob('*.sql')):
            command(['docker', 'exec', pg, 'psql', '-p', str(pg_port), '-U', 'alinksec', '-d', 'alinksec', '-v', 'ON_ERROR_STOP=1', '-f', schema], log='schema-' + schema.name + '.log')
        migration_environment = {'PGHOST': '127.0.0.1', 'PGPORT': str(pg_port), 'PGDATABASE': 'alinksec', 'PGUSER': 'alinksec', 'PGPASSWORD': owner_password,
                'ALINKSEC_APP_DB_USER': 'alinksec_app', 'ALINKSEC_APP_DB_PASSWORD': app_password,
                'ALINKSEC_BIND_ADDRESS': '127.0.0.1', 'ALINKSEC_MIGRATIONS_DIR': str(REPO / 'deploy/migrations')}
        options = [part for key, value in migration_environment.items() for part in ['-e', key + '=' + value]]
        command(['docker', 'exec', *options, pg, 'bash', REPO / 'deploy/migrations/run-migrations.sh'], log='migrations.log')
        environment.update(PG_HOST='127.0.0.1', PG_PORT=str(pg_port), PG_USER='alinksec_app', PG_PASSWORD=app_password)
    server = start_server()
    admin = login()
    # Keep native Agent actions scoped to harmless collection in its disposable container.
    for rule in api('/api/protect/rules', admin):
        api('/api/protect/rules/' + rule['rule_id'], admin, {'enabled': False}, method='PUT')
    spec = importlib.util.spec_from_file_location('review_sessions', REPO / 'deploy/tests/review-sessions.py')
    sessions = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(sessions)

    def restart_session_server():
        global server
        key = DATA / 'jwt.secret'
        before = hashlib.sha256(key.read_bytes()).hexdigest()
        old = stop(server)
        server = start_server()
        after = hashlib.sha256(key.read_bytes()).hexdigest()
        return {'beforePid': old['beforePid'], 'afterPid': state(server)['Pid'], 'signingKeyUnchanged': before == after,
                'signingKeyBeforeSHA256': before, 'signingKeyAfterSHA256': after}

    session_result = sessions.verify([http_port], admin, password, restart_session_server)
    (OUTPUT / 'sessions.json').write_text(json.dumps(session_result, indent=2) + '\n')
    config = PRIVATE / 'agent.yml'
    config.write_text(f'server_addr: 127.0.0.1:{grpc_port}\nheartbeat_interval: 1s\ncollect_interval: 24h\ndecoy:\n  enabled: false\n')
    entry = PRIVATE / 'agent-entry.sh'
    entry.write_text('set -eu\n' + f'if [ ! -f {WORK}/certs/client.crt ]; then {native} install --server 127.0.0.1:{grpc_port} --token "$ALINKSEC_TEST_TOKEN" --ca-file {DATA}/certs/ca.crt --workdir {WORK}; fi\n' +
            f'{native} config apply --from {config} --workdir {WORK}\nexec {native} run --workdir {WORK}\n')
    agent_process = start_agent()
    agent = until(lambda: next((line.split(': ', 1)[1] for line in (WORK / 'state.yml').read_text().splitlines() if line.startswith('agent_id: ')), None), 'native Agent enrollment')
    assert str(uuid.UUID(agent)) == agent
    until(lambda: probe(agent)['heartbeat'], 'native heartbeat')
    stop(agent_process)
    crash_results = []
    for phase in ['precommit', 'postcommit']:
        report, source = str(uuid.uuid4()), 'review-' + phase + '-' + secrets.token_hex(4)
        seeded = seed(report, source)
        shutil.copy2(PRIVATE / (report + '.pb'), OUTPUT / (phase + '-report.pb'))
        assert queued(report)
        (CONTROL / 'armed.json').write_text(json.dumps({'phase': phase, 'agentId': agent, 'reportId': report, 'source': source}))
        agent_process = start_agent()
        marker = until(lambda: json.loads((CONTROL / 'reached.json').read_text()), phase + ' exact transaction gate')
        assert marker['phase'] == phase and marker['transactionActive'] == (phase == 'precommit')
        assert marker['businessRowsInside'] == marker['dedupRowsInside'] == 1 and queued(report)
        before = probe(agent, report, source)
        expected = int(phase == 'postcommit')
        assert before['business'] == before['dedup'] == expected, before
        killed = stop(server, kill=True)
        stop(agent_process, kill=True)
        (CONTROL / 'armed.json').unlink()
        (CONTROL / 'reached.json').unlink()
        server = start_server()
        after = probe(agent, report, source)
        assert after['business'] == after['dedup'] == expected and queued(report)
        agent_process = start_agent()
        def replayed():
            row = probe(agent, report, source)
            return row if row['business'] == row['dedup'] == 1 and not queued(report) else None
        replay = until(replayed, 'native spool replay and durable receipt')
        stop(agent_process)
        duplicate_seed = seed(report, source)  # Replay the exact original protobuf bytes.
        assert duplicate_seed == seeded
        agent_process = start_agent()
        duplicate = until(replayed, 'duplicate native spool replay')
        stop(agent_process)
        crash_results.append({'phase': phase, 'seed': seeded, 'gate': marker, 'externalBeforeCrash': before,
                'kill': killed, 'afterActualJvmRestart': after, 'afterAgentRestartAndReplay': replay, 'duplicateSeed': duplicate_seed, 'afterDuplicateReplay': duplicate})
        (OUTPUT / 'crash-replay.json').write_text(json.dumps(crash_results, indent=2) + '\n')

    agent_process = start_agent()
    until(lambda: probe(agent)['heartbeat'], 'control Agent reconnects')
    load_cfg = PRIVATE / 'load.json'
    load_cfg.write_text(json.dumps({'Mode': 'load', 'Address': f'127.0.0.1:{grpc_port}', 'CA': str(DATA / 'certs/ca.crt'), 'Token': enroll_token, 'DurationSeconds': 30}))
    load_cfg.chmod(0o600)
    downstream_mode[0] = 'slow'
    load_start = time.monotonic()
    load_start_wall = time.time_ns() // 1_000_000
    load_output = (OUTPUT / 'load.jsonl').open('w')
    load = subprocess.Popen([str(fixture), '--config', str(load_cfg)], stdout=load_output, stderr=load_output,
            env={**os.environ, 'GOMEMLIMIT': '96MiB', 'GOMAXPROCS': '1'})
    load_output.close()
    child_processes.append(load)
    latency, heartbeat_changes = [], []
    previous_heartbeat = None
    command_id = None
    command_started = None
    command_latency = None
    recovery_at = None
    while load.poll() is None:
        elapsed = time.monotonic() - load_start
        assert elapsed < 65, 'load fixture deadline'
        if elapsed >= 15 and recovery_at is None:
            downstream_mode[0] = 'healthy'
            recovery_at = time.time_ns() // 1_000_000
        started = time.monotonic()
        current_admin = login()
        admin = current_admin
        latency.append((time.monotonic() - started) * 1000)
        snapshot = probe(agent)
        if snapshot['heartbeat'] != previous_heartbeat:
            heartbeat_changes.append(time.monotonic())
            previous_heartbeat = snapshot['heartbeat']
        if command_id is None and elapsed >= 5:
            previous = {row['cmd_id'] for row in snapshot['commands']}
            command_started = time.monotonic()
            api('/api/hosts/' + agent + '/collect', current_admin, {})
            command_id = until(lambda: next((row['cmd_id'] for row in probe(agent)['commands'] if row['cmd_id'] not in previous), None), 'native collect command')
        if command_id is not None and command_latency is None:
            if any(row['cmd_id'] == command_id and row['status'] == 4 for row in snapshot['commands']):
                command_latency = (time.monotonic() - command_started) * 1000
        assert not state(server)['OOMKilled']
        time.sleep(.5)
    assert load.wait() == 0, 'synthetic load failed; see original load.jsonl'
    until(lambda: probe(agent)['metrics']['records'] == 0, 'export recovery drains bounded queue', 15)
    final = probe(agent)['metrics']
    assert final['dropped'] > 0 and final['rejected'] > 0 and final['failed'] > 0, final
    samples = [json.loads(line) for line in (CONTROL / 'metrics.jsonl').read_text().splitlines()]
    assert all(0 <= row['statistics']['records'] <= 4096 and 0 <= row['statistics']['bytes'] <= 8 * 1024 * 1024 for row in samples)
    assert max(row['statistics']['bytes'] for row in samples) >= 7 * 1024 * 1024
    with downstream_lock:
        requests = list(downstream_requests)
        assert not downstream_errors, downstream_errors
    assert any(row['mode'] == 'slow' for row in requests) and any(row['mode'] == 'healthy' and row['at'] >= recovery_at for row in requests)
    assert all(0 < row['bytes'] <= 256 * 1024 for row in requests)
    events = [json.loads(line) for line in (OUTPUT / 'load.jsonl').read_text().splitlines()]
    producers = [row for row in events if 'producer' in row]
    assert len(producers) == 2 and all(row['elapsedMillis'] >= 30000 and row['batches'] >= 100 and row['batchBytes'] > 256 * 1024 for row in producers)
    sent = {row['reportId']: row for row in events if row.get('kind') == 'business-sent'}
    receipts = {row['reportId']: row for row in events if row.get('kind') == 'business-receipt'}
    assert sent.keys() == receipts.keys() and len(sent) >= 4
    report_latency = [receipts[key]['at'] - row['at'] for key, row in sent.items()]
    expected_business = collections.Counter(row['agentId'] for row in sent.values())
    business_facts = []
    for row in sent.values():
        fact = probe(row['agentId'], row['reportId'], 'runtime-load')
        assert fact['dedup'] == 1 and fact['business'] == expected_business[row['agentId']]
        business_facts.append({'agentId': row['agentId'], 'reportId': row['reportId'], 'business': fact['business'], 'dedup': fact['dedup']})
    def p95(values):
        return sorted(values)[max(0, (95 * len(values) + 99) // 100 - 1)]
    boundaries = [load_start, *heartbeat_changes, time.monotonic()]
    gaps = [(b - a) * 1000 for a, b in zip(boundaries, boundaries[1:])]
    assert len(latency) >= 10 and len(heartbeat_changes) >= 10 and gaps
    assert p95(latency) <= 3000 and max(latency) <= 8000 and p95(report_latency) <= 3000 and max(report_latency) <= 8000
    assert max(gaps) <= 8000 and command_latency is not None and command_latency <= 8000
    overload = {'accepted': True, 'profile': {'producers': 2, 'durationSeconds': 30, 'samplesPerBatch': 257, 'periodMillis': 100,
            'loginAndBusinessP95Millis': 3000, 'loginBusinessCommandMaxMillis': 8000, 'heartbeatGapMaxMillis': 8000},
            'loginMillis': latency, 'businessMillis': report_latency, 'heartbeatGapsMillis': gaps, 'nativeCommandMillis': command_latency,
            'businessFacts': business_facts,
            'loadStartUnixMillis': load_start_wall, 'loadEndUnixMillis': time.time_ns() // 1_000_000,
            'downstreamErrors': list(downstream_errors),
            'finalStatistics': final, 'recoveredAt': recovery_at, 'downstream': requests, 'producers': producers}
    (OUTPUT / 'overload.json').write_text(json.dumps(overload, indent=2) + '\n')
    shutil.copy2(CONTROL / 'metrics.jsonl', OUTPUT / 'metrics.jsonl')
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        regressions = OUTPUT / 'regressions'
        regressions.mkdir()
        for suite in ['ReviewDefectsIntegrationTest', 'AgentChannelSecurityIntegrationTest']:
            report = REPO / ('server/alinksec-bootstrap/target/surefire-reports/TEST-com.alinksec.bootstrap.' + suite + '.xml')
            shutil.copy2(report, regressions / report.name)
        if args.database == 'sqlite':
            selected = {'TestQueueAppendAfterInterruptedWritePreservesNewReports', 'TestQueueAppendDelimitsCompleteTailWhileAwaitingReceipt',
                    'TestQueueTailSeparatorCannotExceedCapacity', 'TestQueuePeekFailureCompactionAndRestart',
                    'TestQueueLargeBacklogAndMalformedOversizePreservesSource', 'TestOfflineQueuePrunesExpiredReportsBeforeReachingCapacity',
                    'TestTerminalAckCannotOvertakeDurableResult', 'TestBusinessReportPersistsBeforeSendAndNeedsMatchingReceipt',
                    'TestSenderRetainsSuccessfulSendsUntilDurableReceipt', 'TestQueueCompactionContentionDoesNotBlockHeartbeat'}
            with (REPO / '.tmp/review-runtime-go.jsonl').open() as source_file, (regressions / 'go-queue.jsonl').open('w') as target_file:
                for line in source_file:
                    record = json.loads(line)
                    if record.get('Test', '').split('/')[0] in selected and record.get('Package', '').endswith('/internal/comm'):
                        target_file.write(line)
    result = {'passed': True, 'database': args.database, 'source': command(['git', '-C', REPO, 'rev-parse', 'HEAD']),
              'worktreeClean': command(['git', '-C', REPO, 'status', '--porcelain']) == '',
              'sessionRevocation': True, 'precommitAndPostcommitJvmKill': True, 'actualNativeAgentSpoolReplay': True,
              'metricsTimeoutOverloadAndRecovery': True, 'releaseOrDeployment': False}
    passed = True
finally:
    for process in child_processes:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=10)
    downstream.shutdown()
    downstream.server_close()
    states = []
    for index, ident in enumerate(reversed(containers)):
        with contextlib.suppress(Exception):
            command(['docker', 'logs', ident], log=f'container-{index}.log')
            snapshot = state(ident)
            if snapshot['Running']:
                stop(ident)
            states.append({'container': ident, **state(ident)})
            command(['docker', 'rm', '-fv', ident])
    remaining = command(['docker', 'ps', '-aq', '--filter', 'label=alinksec.review-runtime=' + prefix]).splitlines()
    result.update(passed=passed, database=args.database, remainingOwnedContainers=len(remaining),
                  oomKilled=any(row['OOMKilled'] for row in states), containerExitStates=states)
    (OUTPUT / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    shutil.rmtree(PRIVATE)
assert passed and not remaining and not result['oomKilled']
print(json.dumps({'passed': True, 'database': args.database, 'cleanup': True}))
