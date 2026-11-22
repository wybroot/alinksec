#!/usr/bin/env python3
"""Capture real console HTTP transactions in bounded, disposable database processes."""
import argparse
import contextlib
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import time
import uuid
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('--database', choices=['sqlite', 'postgres'], required=True)
args = parser.parse_args()
repo = Path(__file__).resolve().parents[2]
output = repo / '.tmp/review-console' / args.database
output.mkdir(parents=True, exist_ok=False)
private = repo / ('.tmp/review-console-private-' + uuid.uuid4().hex)
private.mkdir(mode=0o700)
control = private / 'control'
control.mkdir()
data = private / 'data'
data.mkdir()
prefix = 'alinksec-console-' + uuid.uuid4().hex[:10]
containers, samples = [], []
password, owner_password, app_password = [secrets.token_urlsafe(24) for _ in range(3)]
masked = [password, owner_password, app_password]
result = {'accepted': False, 'database': args.database, 'releaseOrDeployment': False}
if os.environ.get('GITHUB_ACTIONS') == 'true':
    for value in masked:
        print('::add-mask::' + value, flush=True)


def redact(value):
    for secret in masked:
        value = value.replace(secret, '[removed]')
    return value


def command(argv, timeout=90):
    run = subprocess.run([str(item) for item in argv], capture_output=True, text=True, timeout=timeout)
    if run.returncode:
        raise RuntimeError(redact(str(argv[0]) + ': ' + (run.stdout + run.stderr)[-1200:]))
    return run.stdout.strip()


def write(name, value):
    (output / name).write_text(json.dumps(value, indent=2) + '\n')


def resources():
    available = int(next(line.split()[1] for line in Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))) // 1024
    full = float(next(line.split('avg10=')[1].split()[0] for line in Path('/proc/pressure/memory').read_text().splitlines() if line.startswith('full ')))
    sample = {'availableMiB': available, 'fullPSI': full}
    samples.append(sample)
    assert available >= 384 and full <= 10, ('resource watchdog', sample)
    return available


def container(suffix, image, parameters, *, memory, environment, java=False):
    argv = ['docker', 'run', '-d', '--name', prefix + suffix, '--network=host', '--memory=' + str(memory) + 'm',
            '--memory-swap=' + str(memory) + 'm', '--cpus=1', '--pids-limit=256', '--label', 'alinksec.review-console=' + prefix,
            '-v', f'{repo}:{repo}', '-w', str(private)]
    if java:
        argv += ['--user', f'{os.getuid()}:{os.getgid()}', '--entrypoint', 'java']
    for key, value in environment.items():
        argv += ['-e', key + '=' + value]
    ident = command([*argv, image, *parameters], timeout=180)
    containers.append(ident)
    return ident


def state(ident):
    return json.loads(command(['docker', 'inspect', '--format', '{{json .State}}', ident]))


try:
    available = resources()
    assert available >= 1408, ('insufficient memory for smallest bounded console scenario', available)
    write('resource-start.json', {'availableMiB': available, 'limitsMiB': {'java': 640, 'postgres': 256},
                                 'javaHeapMiB': 256, 'workersPerProcess': 1, 'browserOverlapsBackend': False})
    jar = repo / 'server/alinksec-bootstrap/target/alinksec-bootstrap.jar'
    classes = repo / 'server/alinksec-bootstrap/target/test-classes/review/console'
    with zipfile.ZipFile(jar) as archive:
        assert not any(name.startswith('BOOT-INF/classes/review/console/') for name in archive.namelist())
    shutil.copytree(classes, private / 'fixture-classes/review/console')
    source = command(['git', 'rev-parse', 'HEAD'])
    clean = not command(['git', 'status', '--porcelain', '--untracked-files=normal'])
    if os.environ.get('GITHUB_ACTIONS') == 'true':
        assert source == os.environ['GITHUB_SHA'] and clean
    write('binary-provenance.json', {'source': source, 'worktreeClean': clean, 'productionJarContainsAcceptanceControl': False,
          'productionJarSHA256': hashlib.sha256(jar.read_bytes()).hexdigest(),
          'fixtureClasses': {str(path.relative_to(classes)): hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(classes.rglob('*.class'))}})
    environment = {'SPRING_PROFILES_ACTIVE': args.database, 'ALINKSEC_METRICS_ENABLED': 'false', 'ALINKSEC_CLUSTER_ENABLED': 'false',
          'ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD': password, 'ALINKSEC_BOOTSTRAP_ENROLL_TOKEN': '',
          'ALINKSEC_SQLITE_PATH': str(data / 'alinksec.db'), 'ALINKSEC_JWT_SECRET': '',
          'ALINKSEC_CERT_DIR': str(data / 'certs'), 'ALINKSEC_WEB_TLS_DIR': str(data / 'web-tls'),
          'ALINKSEC_LIBRARY_WORK_DIR': str(data / 'libraries'), 'ALINKSEC_CONSOLE_CONTROL_DIR': str(control),
          'SPRING_DATASOURCE_HIKARI_MAXIMUM_POOL_SIZE': '4'}
    if args.database == 'postgres':
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            pg_port = sock.getsockname()[1]
        pg = container('-pg', 'postgres:17', ['-p', str(pg_port), '-c', 'listen_addresses=127.0.0.1', '-c', 'shared_buffers=32MB', '-c', 'max_connections=20'],
             memory=256, environment={'POSTGRES_USER': 'alinksec', 'POSTGRES_PASSWORD': owner_password, 'POSTGRES_DB': 'alinksec'})
        deadline = time.monotonic() + 90
        while True:
            resources()
            try:
                command(['docker', 'exec', pg, 'pg_isready', '-h', '127.0.0.1', '-p', str(pg_port), '-U', 'alinksec'])
                break
            except RuntimeError:
                assert time.monotonic() < deadline, 'PostgreSQL TCP startup timeout'
                time.sleep(.5)
        for schema in sorted((repo / 'deploy/sql').glob('*.sql')):
            (output / ('schema-' + schema.name + '.log')).write_text(command(['docker', 'exec', pg, 'psql', '-p', str(pg_port), '-U', 'alinksec', '-d', 'alinksec', '-v', 'ON_ERROR_STOP=1', '-f', schema]))
        migration_environment = {'PGHOST': '127.0.0.1', 'PGPORT': str(pg_port), 'PGDATABASE': 'alinksec', 'PGUSER': 'alinksec', 'PGPASSWORD': owner_password,
              'ALINKSEC_APP_DB_USER': 'alinksec_app', 'ALINKSEC_APP_DB_PASSWORD': app_password,
              'ALINKSEC_BIND_ADDRESS': '127.0.0.1', 'ALINKSEC_MIGRATIONS_DIR': str(repo / 'deploy/migrations')}
        options = [part for key, value in migration_environment.items() for part in ['-e', key + '=' + value]]
        (output / 'migrations.log').write_text(redact(command(['docker', 'exec', *options, pg, 'bash', repo / 'deploy/migrations/run-migrations.sh'])))
        environment.update(PG_HOST='127.0.0.1', PG_PORT=str(pg_port), PG_USER='alinksec_app', PG_PASSWORD=app_password)
    java = container('-java', 'maven:3.9.9-eclipse-temurin-21',
          ['-Xmx256m', '-Xss512k', '-XX:MaxMetaspaceSize=160m', '-XX:MaxDirectMemorySize=96m', '-XX:ReservedCodeCacheSize=48m', '-XX:ActiveProcessorCount=1',
           '-Dloader.main=review.console.ConsoleAcceptance', '-Dloader.path=' + str(private / 'fixture-classes'),
           '-cp', jar, 'org.springframework.boot.loader.launch.PropertiesLauncher', '--server.address=127.0.0.1', '--server.port=0', '--alinksec.server.port=0',
           '--server.tomcat.threads.max=8', '--server.tomcat.threads.min-spare=1', '--server.tomcat.accept-count=4'],
          memory=640, environment=environment, java=True)
    deadline = time.monotonic() + 300
    while state(java)['Running']:
        resources()
        assert time.monotonic() < deadline, 'console acceptance timed out'
        time.sleep(1)
    final = state(java)
    result.update(exitCode=final['ExitCode'], oomKilled=final['OOMKilled'])
    if (control / 'secrets.json').is_file():
        masked.extend(json.loads((control / 'secrets.json').read_text()))
    raw_logs = subprocess.run(['docker', 'logs', java], capture_output=True, text=True, timeout=30)
    assert raw_logs.returncode == 0
    logs = raw_logs.stdout + raw_logs.stderr
    (output / 'container.log').write_text(redact(logs))
    assert all(value not in logs for value in masked), 'credential found in raw container logging'
    assert final['ExitCode'] == 0 and not final['OOMKilled'], 'real HTTP acceptance failed; inspect sanitized container.log'
    assert (control / 'secrets.json').is_file(), 'private credential comparison set missing'
    for path in sorted((control / 'public').iterdir()):
        assert path.is_file() and path.stat().st_size <= 8 * 1024 * 1024
        assert all(value.encode() not in path.read_bytes() for value in masked), 'credential found in public evidence'
        shutil.copy2(path, output / path.name)
    assert json.loads((output / 'accepted.json').read_text())['accepted']
    result.update(accepted=True, rawContainerLogCredentialValuesChecked=len(masked), rawContainerLogCredentialLeakDetected=False)
except BaseException as error:
    result['failure'] = redact(type(error).__name__ + ': ' + str(error))
    raise
finally:
    states = []
    for ident in reversed(containers):
        try:
            if state(ident)['Running']:
                command(['docker', 'stop', '-t', '8', ident])
            final = state(ident)
            states.append({'exitCode': final['ExitCode'], 'oomKilled': final['OOMKilled'], 'running': final['Running']})
            command(['docker', 'rm', '-v', ident])
        except Exception as error:
            result['cleanupFailure'] = redact(str(error))
            result['accepted'] = False
    result['containerStates'] = states
    result['remainingOwnedContainers'] = command(['docker', 'ps', '-aq', '--filter', 'label=alinksec.review-console=' + prefix]).splitlines()
    result['accepted'] &= not result['remainingOwnedContainers'] and not any(row['oomKilled'] or row['running'] for row in states)
    write('runner-result.json', result)
    write('resource-samples.json', samples)
    shutil.rmtree(private)
assert result['accepted'], 'console evidence or cleanup rejected'
print('Real console HTTP acceptance passed: ' + args.database, flush=True)
