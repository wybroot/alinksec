#!/usr/bin/env python3
"""Serial PostgreSQL and volume recovery: stop PostgreSQL while the helper runs."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import signal
import tempfile
import time
import uuid

assert os.environ.get('ALINKSEC_SMOKE_ALLOW_FIXTURES') == 'true'
os.umask(0o077)
repo = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('operations', repo / 'deploy/operations.py')
ops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ops)


def interrupted(_signal, _frame):
    raise ops.MaintenanceError('Validation interrupted')


for sig in (signal.SIGINT, signal.SIGTERM):
    signal.signal(sig, interrupted)


class SerialPostgres(ops.Deployment):
    def ready(self):
        for attempt in range(90):
            try:
                self.pg('psql', '-X', '-U', 'alinksec', '--dbname', 'alinksec', '-Atc', 'SELECT 1')
                return
            except ops.MaintenanceError:
                if attempt == 89:
                    raise
                time.sleep(0.5)

    def docker(self, *args, **kwargs):
        if args[0] == 'create':
            # Exactly one validation container runs: PostgreSQL OR the helper.
            super().docker('stop', '--time', '10', self.containers['postgres']['Id'])
        return super().docker(*args, **kwargs)

    def remove_helper(self):
        had_helper = self.journal.get('helper')
        super().remove_helper()
        if had_helper:
            super().docker('start', self.containers['postgres']['Id'])
            self.ready()


project = 'alinksec-operations-pg-' + uuid.uuid4().hex[:10]
evidence = repo / '.tmp/operations-postgres-local'
evidence.mkdir(exist_ok=True)
result = {'project': project, 'passed': False}
with tempfile.TemporaryDirectory(prefix=project + '-') as directory:
    root = Path(directory)
    compose_file, env_file = root / 'compose.json', root / 'env'
    env_file.write_text('')
    compose_file.write_text(json.dumps({'name': project, 'services': {
        'server': {'image': os.environ.get('ALINKSEC_OPERATIONS_TEST_IMAGE', 'alinksec-server-live-validation:latest'),
                   'entrypoint': ['/bin/true'], 'volumes': ['data:/app/data', 'tls:/app/web-tls']},
        'web': {'image': os.environ.get('ALINKSEC_OPERATIONS_WEB_IMAGE', 'nginx:1.27-alpine'),
                'entrypoint': ['/bin/true'], 'volumes': ['tls:/etc/nginx/tls:ro']},
        'postgres': {'image': os.environ.get('ALINKSEC_OPERATIONS_PG_IMAGE', 'public.ecr.aws/docker/library/postgres:17'),
            'environment': {'POSTGRES_USER': 'alinksec', 'POSTGRES_DB': 'alinksec', 'POSTGRES_PASSWORD': 'disposable-operation-test'},
            'command': ['postgres', '-c', 'shared_buffers=16MB', '-c', 'work_mem=1MB', '-c', 'max_connections=12'],
            'mem_limit': '192m', 'memswap_limit': '256m', 'cpus': 1, 'pids_limit': 64,
            'volumes': ['pg:/var/lib/postgresql/data']},
    }, 'volumes': {'data': {}, 'tls': {}, 'pg': {}}}))
    prefix = ['docker', 'compose', '--env-file', str(env_file), '-f', str(compose_file)]
    try:
        for service in ('server', 'web', 'postgres'):
            ops.run(prefix + ['create', '--no-build', service])
        ops.run(prefix + ['up', '-d', '--no-deps', '--no-build', 'postgres'])
        args = argparse.Namespace(compose_file=compose_file, env_file=env_file, state_dir=root / 'state', timeout=30)
        deployment = SerialPostgres(args)
        deployment.ready()

        def sql(statement):
            return deployment.pg('psql', '-X', '-U', 'alinksec', '--dbname', 'alinksec',
                                 '-v', 'ON_ERROR_STOP=1', '-Atc', statement).strip()

        sql("CREATE ROLE alinksec_app LOGIN; CREATE TABLE probe(value TEXT); INSERT INTO probe VALUES ('before'); "
            "REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO alinksec_app; "
            "GRANT SELECT ON probe TO alinksec_app; REVOKE CONNECT ON DATABASE alinksec FROM PUBLIC; "
            "GRANT CONNECT ON DATABASE alinksec TO alinksec_app; ALTER DATABASE alinksec SET statement_timeout='3min'; "
            "COMMENT ON DATABASE alinksec IS 'before'; ALTER ROLE alinksec_app IN DATABASE alinksec SET idle_in_transaction_session_timeout='12s'")
        with deployment.lock():
            assert sql("SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname='alinksec'") == 'before'
            snapshot = root / 'backups' / 'accepted'
            deployment.snapshot(snapshot)
            deployment.compatible(snapshot)
            sql("UPDATE probe SET value='after'; CREATE TABLE obsolete(value TEXT); "
                "GRANT CONNECT ON DATABASE alinksec TO PUBLIC; COMMENT ON DATABASE alinksec IS 'after'")
            deployment.begin('restore')
            deployment.record(safety=str(snapshot))
            deployment.apply(snapshot)
            assert sql('SELECT value FROM probe') == 'before'
            assert sql("SELECT to_regclass('obsolete') IS NULL") == 't'
            assert sql("SELECT shobj_description(oid,'pg_database') FROM pg_database WHERE datname='alinksec'") == 'before'
            assert sql("SELECT NOT EXISTS(SELECT 1 FROM pg_database d, LATERAL aclexplode(d.datacl) a "
                       "WHERE d.datname='alinksec' AND a.grantee=0 AND a.privilege_type='CONNECT')") == 't'
            assert sql("SELECT has_table_privilege('alinksec_app','probe','SELECT') AND NOT has_schema_privilege('alinksec_app','public','CREATE')") == 't'
            settings = sql("SELECT setrole::regrole::text||':'||setconfig::text FROM pg_db_role_setting "
                           "WHERE setdatabase=(SELECT oid FROM pg_database WHERE datname='alinksec') ORDER BY setrole")
            assert 'statement_timeout=3min' in settings and 'idle_in_transaction_session_timeout=12s' in settings
            deployment.finish()
            result.update(passed=True, databaseRecreated=True, obsoleteTableRemoved=True, tableAndDatabaseAclPreserved=True,
                          databaseAndRoleSettingsPreserved=True, databaseCommentPreserved=True,
                          runningValidationContainersMaximum=1, postgresMemoryMiB=192, helperMemoryMiB=64)
    finally:
        ops.run(prefix + ['down', '--volumes', '--remove-orphans'])
        (evidence / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(result, ensure_ascii=False))
