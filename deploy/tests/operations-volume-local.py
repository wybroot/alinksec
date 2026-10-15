#!/usr/bin/env python3
"""Real archive/UID/mode checks with only one bounded helper running at a time."""
import argparse
import importlib.util
import io
import json
import os
from pathlib import Path
import signal
import sqlite3
import tarfile
import tempfile
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

project = 'alinksec-operations-volume-' + uuid.uuid4().hex[:10]
evidence = repo / '.tmp/operations-volume-local'
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
    }, 'volumes': {'data': {}, 'tls': {}}}))
    prefix = ['docker', 'compose', '--env-file', str(env_file), '-f', str(compose_file)]
    try:
        # create does not start either application; apply starts only its 64 MiB helper.
        for service in ('server', 'web'):
            ops.run(prefix + ['create', '--no-build', service])
        args = argparse.Namespace(compose_file=compose_file, env_file=env_file, state_dir=root / 'state', timeout=30)
        deployment = ops.Deployment(args)
        database_file = root / 'source.db'
        connection = sqlite3.connect(database_file)
        connection.executescript("CREATE TABLE probe(value TEXT); INSERT INTO probe VALUES ('original');")
        connection.close()

        def populate(files, target):
            with tempfile.TemporaryFile() as stream:
                with tarfile.open(fileobj=stream, mode='w:') as archive:
                    for name, content in files.items():
                        entry = tarfile.TarInfo(name)
                        entry.size, entry.uid, entry.gid, entry.mode = len(content), 1001, 1001, 0o640
                        archive.addfile(entry, io.BytesIO(content))
                stream.seek(0)
                deployment.docker('cp', '-', deployment.containers['server']['Id'] + ':' + target, source=stream)

        with deployment.lock():
            populate({'alinksec.db': database_file.read_bytes(), 'probe 数据.txt': b'original'}, '/app/data')
            populate({'key': b'original-tls'}, '/app/web-tls')
            snapshot = root / 'backups' / 'accepted'
            deployment.snapshot(snapshot)
            populate({'probe 数据.txt': b'changed', 'obsolete': b'must-disappear'}, '/app/data')
            populate({'key': b'changed-tls'}, '/app/web-tls')
            deployment.begin('restore')
            deployment.record(safety=str(snapshot))
            deployment.compatible(snapshot)
            deployment.apply(snapshot)
            captured = root / 'restored.tar'
            with captured.open('wb') as stream:
                deployment.docker('cp', '-a', deployment.containers['server']['Id'] + ':/app/data/.', '-', destination=stream)
            members = {}
            result['files'] = members
            for archive, entry, name in ops.archive_members(captured):
                members[name] = {'uid': entry.uid, 'gid': entry.gid, 'mode': oct(entry.mode)}
                if name == 'probe 数据.txt':
                    assert archive.extractfile(entry).read() == b'original'
                    assert (entry.uid, entry.gid, entry.mode) == (1001, 1001, 0o640), (entry.uid, entry.gid, entry.mode)
            assert 'obsolete' not in members
            assert 'probe 数据.txt' in members and 'alinksec.db' in members
            deployment.finish()
            assert not deployment.journal_path.exists()
            result.update(passed=True, files=members, sqliteIntegrityVerified=True,
                          originalOwnershipAndModePreserved=True, obsoleteRemoved=True,
                          helperMemoryMiB=64, helperNetwork='none', runningValidationContainersMaximum=1)
    finally:
        ops.run(prefix + ['down', '--volumes', '--remove-orphans'])
        (evidence / 'result.json').write_text(json.dumps(result, ensure_ascii=False, indent=2) + '\n')
print(json.dumps(result, ensure_ascii=False))
