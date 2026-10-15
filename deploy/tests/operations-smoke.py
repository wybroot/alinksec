#!/usr/bin/env python3
"""Full maintenance against disposable CI Compose services; never run on user stacks."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

assert os.environ.get('ALINKSEC_SMOKE_ALLOW_FIXTURES') == 'true'
assert os.environ.get('GITHUB_ACTIONS') == 'true', 'Full-stack maintenance validation runs only on disposable GitHub runners'
os.umask(0o077)
repo = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('operations', repo / 'deploy/operations.py')
ops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ops)
parser = argparse.ArgumentParser()
parser.add_argument('--mode', choices=['sqlite', 'postgres'], required=True)
options = parser.parse_args()
mode = options.mode
evidence = repo / '.tmp' / ('operations-native-' + mode)
evidence.mkdir(exist_ok=True)
result = {'mode': mode, 'passed': False, 'checks': []}


def checked(name):
    result['checks'].append(name)
    print('ok - ' + name, flush=True)


with tempfile.TemporaryDirectory(prefix='alinksec-operations-ci-') as directory:
    root = Path(directory)
    env_file = root / 'environment.env'
    env_file.write_text('')
    compose_file = repo / 'deploy/docker' / ('docker-compose.lite.yml' if mode == 'sqlite' else 'docker-compose.yml')
    args = argparse.Namespace(compose_file=compose_file, env_file=env_file, state_dir=root / 'state', timeout=60)
    deployment = ops.Deployment(args)
    assert deployment.mode == mode
    base = [sys.executable, '-B', str(repo / 'deploy/operations.py'), '--compose-file', str(compose_file),
            '--env-file', str(env_file), '--state-dir', str(args.state_dir), '--timeout', '60']

    def cli(*arguments, expected=0, env=None):
        completed = subprocess.run([*base, *map(str, arguments)], capture_output=True, text=True,
                                   timeout=300, env=env)
        assert completed.returncode == expected, (arguments[0], completed.returncode, completed.stderr)
        # Artifacts and logs contain only public status/errors, never raw snapshot payloads.
        for key in ('ALINKSEC_POSTGRES_PASSWORD', 'ALINKSEC_POSTGRES_APP_PASSWORD', 'ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD'):
            secret = os.environ.get(key)
            assert not secret or secret not in completed.stdout + completed.stderr
        return completed

    def sql(statement):
        if mode == 'sqlite':
            return ops.run(deployment.compose + ['--profile', 'maintenance', 'run', '--rm', '-T', '--no-deps',
                'sqlite-maintenance', '/data/alinksec.db', statement]).strip()
        owner, database = deployment.pg_settings()
        return deployment.pg('psql', '-X', '-U', owner, '--dbname', database,
                             '-v', 'ON_ERROR_STOP=1', '-Atc', statement).strip()

    def server(*command):
        return deployment.docker('exec', deployment.containers['server']['Id'], *command).strip()

    probe = '/app/data/operations probe 数据.txt'
    obsolete = '/app/data/operations-obsolete'
    tls_probe = '/app/web-tls/operations-probe'

    def write_probe(value):
        for path in (probe, tls_probe):
            server('/bin/sh', '-c', 'printf %s "$1" > "$2"; chmod 640 "$2"; chown 1001:1001 "$2"', 'fixture', value, path)
        sql("UPDATE ci_operations_probe SET value='" + value + "'")

    def assert_probe(value):
        assert sql('SELECT value FROM ci_operations_probe') == value
        for path in (probe, tls_probe):
            assert server('cat', path) == value
            assert server('stat', '-c', '%u:%g:%a', path) == '1001:1001:640'
        assert server('sha256sum', '/app/data/certs/ca.crt').split()[0] == ca_hash
        if jwt_hash:
            assert server('sha256sum', '/app/data/jwt.secret').split()[0] == jwt_hash
        if mode == 'postgres':
            assert sql("SELECT NOT has_schema_privilege('alinksec_app','public','CREATE') AND "
                       "has_table_privilege('alinksec_app','public.t_agent','SELECT,INSERT,UPDATE,DELETE') AND "
                       "NOT has_table_privilege('alinksec_app','public.t_schema_migration','SELECT')") == 't'

    def reseal(snapshot):
        manifest = json.loads((snapshot / 'manifest.json').read_text())
        for name in manifest['files']:
            manifest['files'][name] = {'size': (snapshot / name).stat().st_size, 'sha256': ops.digest(snapshot / name)}
        ops.atomic_json(snapshot / 'manifest.json', manifest)

    try:
        cli('check')
        checked('existing deployment preflight; no builds, pulls or implicit dependency startup')
        sql('CREATE TABLE ci_operations_probe(value TEXT NOT NULL); INSERT INTO ci_operations_probe VALUES (\'before\')')
        write_probe('before')
        ca_hash = server('sha256sum', '/app/data/certs/ca.crt').split()[0]
        jwt_hash = server('/bin/sh', '-c', 'if test -f /app/data/jwt.secret; then sha256sum /app/data/jwt.secret; fi').split()
        jwt_hash = jwt_hash[0] if jwt_hash else None
        assert jwt_hash, 'CI must exercise persisted JWT secrets'
        if mode == 'postgres':
            sql("REVOKE CONNECT ON DATABASE alinksec FROM PUBLIC; GRANT CONNECT ON DATABASE alinksec TO alinksec_app; "
                "ALTER DATABASE alinksec SET statement_timeout='3min'; COMMENT ON DATABASE alinksec IS 'operations-before'; "
                "ALTER ROLE alinksec_app IN DATABASE alinksec SET idle_in_transaction_session_timeout='12s'")
        snapshot = root / 'backups' / 'accepted'
        cli('backup', snapshot)
        cli('verify', snapshot)
        checked('sealed database, certificates, persisted JWT, uploaded material and TLS snapshot; offline verification')
        assert snapshot.stat().st_mode & 0o777 == 0o700
        assert all(entry.stat().st_mode & 0o077 == 0 for entry in snapshot.iterdir())
        write_probe('after')
        server('touch', obsolete)
        sql('CREATE TABLE ci_operations_obsolete(value TEXT)')
        if mode == 'postgres':
            sql("GRANT CONNECT ON DATABASE alinksec TO PUBLIC; ALTER DATABASE alinksec SET statement_timeout='4min'; "
                "COMMENT ON DATABASE alinksec IS 'operations-after'")
        cli('restore', snapshot, '--yes')
        assert_probe('before')
        server('test', '!', '-e', obsolete)
        if mode == 'postgres':
            assert sql("SELECT to_regclass('ci_operations_obsolete') IS NULL") == 't'
            assert sql("SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname='alinksec'") == 'operations-before'
            assert sql("SELECT NOT EXISTS(SELECT 1 FROM pg_database d, LATERAL aclexplode(d.datacl) a "
                       "WHERE d.datname='alinksec' AND a.grantee=0 AND a.privilege_type='CONNECT')") == 't'
            assert sql("SELECT count(*) FROM pg_db_role_setting WHERE setdatabase=(SELECT oid FROM pg_database WHERE datname='alinksec') "
                       "AND (setconfig @> ARRAY['statement_timeout=3min'] OR setconfig @> ARRAY['idle_in_transaction_session_timeout=12s'])") == '2'
        else:
            assert sql("SELECT count(*) FROM sqlite_master WHERE name='ci_operations_obsolete'") == '0'
        checked('complete restore removes later files/tables and preserves UID/GID/mode, CA, JWT and database privileges/settings')

        invalid = root / 'backups' / 'checksum-invalid'
        shutil.copytree(snapshot, invalid)
        (invalid / 'environment.env').write_text('modified')
        before = deployment.docker('inspect', '--format', '{{.State.StartedAt}}', deployment.containers['server']['Id'])
        cli('restore', invalid, '--yes', expected=1)
        assert deployment.docker('inspect', '--format', '{{.State.StartedAt}}', deployment.containers['server']['Id']) == before
        checked('checksum failure refused before service downtime')

        # Kill the actual CLI after the first restored volume: no Python cleanup can run.
        write_probe('before-interruption')
        wrapper = root / 'bin'
        wrapper.mkdir()
        real_docker = shutil.which('docker')
        marker = root / 'killed-after-first-volume'
        wrapper_script = wrapper / 'docker'
        wrapper_script.write_text('#!' + sys.executable + '\n' +
            'import os,signal,subprocess,sys\n' +
            'args=sys.argv[1:]\n' +
            f'real={real_docker!r}\n' +
            "if args[:2]==['cp','-'] and args[-1].endswith(':/app/data'):\n" +
            ' subprocess.run([real,*args],check=True)\n' +
            f' open({str(marker)!r},"x").close()\n' +
            ' os.kill(os.getppid(),signal.SIGKILL)\n' +
            ' sys.exit(0)\n' +
            'os.execv(real,[real,*args])\n')
        wrapper_script.chmod(0o700)
        interrupted = cli('restore', snapshot, '--yes', expected=-9,
                          env={**os.environ, 'PATH': str(wrapper) + os.pathsep + os.environ['PATH']})
        assert marker.exists() and (Path(args.state_dir) / 'pending.json').exists()
        for service in ('server', 'web'):
            assert deployment.docker('inspect', '--format', '{{.State.Running}}', deployment.containers[service]['Id']).strip() == 'false'
        cli('recover', '--yes')
        assert_probe('before-interruption')
        assert not (Path(args.state_dir) / 'pending.json').exists()
        checked('actual SIGKILL after first volume leaves services stopped; recover restores pre-operation database and both volumes')

        # Correct checksums do not prove the application will accept the restored material.
        broken = root / 'backups' / 'invalid-ca'
        shutil.copytree(snapshot, broken)
        replacement = root / 'bad-ca.tar'
        replaced = False
        with tarfile.open(broken / 'server-data.tar', 'r:') as old, tarfile.open(replacement, 'w:') as new:
            for member in old:
                data = b'invalid-certificate' if member.name.endswith('/certs/ca.crt') or member.name == 'certs/ca.crt' else None
                if data is not None:
                    replaced = True
                    member.size = len(data)
                new.addfile(member, io.BytesIO(data) if data is not None else (old.extractfile(member) if member.isfile() else None))
        assert replaced
        replacement.replace(broken / 'server-data.tar')
        reseal(broken)
        cli('verify', broken)
        failed = cli('restore', broken, '--yes', expected=1)
        assert 'original deployment recovered and healthy' in failed.stderr
        assert_probe('before-interruption')
        checked('real application rejects invalid CA; failed health automatically restores original DB, CA, JWT, TLS and files')
        cli('check')
        assert not (Path(args.state_dir) / 'pending.json').exists()
        assert deployment.docker('ps', '--all', '--quiet', '--filter', 'label=io.alinksec.maintenance.binding=' + deployment.binding).strip() == ''
        result.update(passed=True, sameExistingContainerIds=True, caSha256=ca_hash,
                      persistedJwtPreserved=True, safetySnapshots=len(list(snapshot.parent.glob('pre-restore-*'))),
                      metadataPermissions='private', remainingHelpers=0)
    finally:
        # Never upload snapshots, deployment.json or env files: they contain secrets.
        (evidence / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(result, ensure_ascii=False))
