"""Maintenance state transitions and destructive failure boundaries, without Docker."""
import argparse
from contextlib import closing
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('operations', Path(__file__).parents[1] / 'operations.py')
ops = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ops)


class Fixture(ops.Deployment):
    def __init__(self, root, mode='sqlite'):
        self.root = root
        self.args = argparse.Namespace(timeout=1)
        self.project, self.mode = 'disposable-unit', mode
        self.state_dir = root / 'state'
        ops.private_directory(self.state_dir)
        self.lock_path = root / 'global.lock'
        self.journal_path = self.state_dir / 'pending.json'
        self.journal = None
        self.compose_file, self.env_file = root / 'compose.yaml', root / 'env'
        self.compose_file.write_text('services: {}')
        self.env_file.write_text('SECRET=do-not-print-me')
        self.data, self.tls = root / 'data', root / 'tls'
        self.data.mkdir()
        self.tls.mkdir()
        self.mounts = {'/app/data': {'Name': 'unit-data'}, '/app/web-tls': {'Name': 'unit-tls'}}
        self.config = {'services': {}}
        self.containers = {name: {'Id': name, 'Image': 'sha256:unit',
            'Config': {'Env': ['POSTGRES_USER=alinksec', 'POSTGRES_DB=alinksec']},
            'State': {'Running': True, 'Status': 'running'}} for name in ('server', 'web')}
        if mode == 'postgres':
            self.containers['postgres'] = {'Id': 'postgres', 'Image': 'sha256:postgres',
                'Config': {'Env': ['POSTGRES_USER=alinksec', 'POSTGRES_DB=alinksec']},
                'State': {'Running': True, 'Status': 'running'}}
        self.identity = {'project': self.project, 'mode': self.mode, 'volumes': {'data': 'unit-data'},
                         'runtime': {'server': {'env': ['SECRET=do-not-print-me']}}}
        self.binding = ops.fingerprint(self.identity)
        self.helpers, self.events, self.failures = {}, [], {}
        self.pg_value = 'before'
        self.foreign_writer = False
        self.set_value('before')
        (self.data / 'ca.crt').write_text('valid-ca')
        (self.tls / 'server.key').write_text('original-tls-key')
        (self.data / 'private').write_text('private-material')
        (self.data / 'private').chmod(0o600)

    def fault(self, point):
        count = self.failures.get(point, 0)
        if count:
            self.failures[point] = count - 1
            raise ops.MaintenanceError('Injected failure: ' + point)

    def set_value(self, value):
        with closing(sqlite3.connect(self.data / 'alinksec.db')) as database, database:
            database.execute('CREATE TABLE IF NOT EXISTS probe(value TEXT)')
            database.execute('DELETE FROM probe')
            database.execute('INSERT INTO probe VALUES (?)', (value,))
        self.pg_value = value

    def value(self):
        if self.mode == 'postgres':
            return self.pg_value
        with closing(sqlite3.connect(self.data / 'alinksec.db')) as database:
            return database.execute('SELECT value FROM probe').fetchone()[0]

    def health(self):
        self.events.append('health')
        self.fault('health')
        ops.require((self.data / 'ca.crt').read_text() == 'valid-ca', 'Application rejected invalid CA')

    def docker(self, *args, source=None, destination=None):
        self.events.append(tuple(args))
        if args[0] == 'stop':
            self.fault('stop-' + args[-1])
            self.containers[args[-1]]['State'].update(Running=False, Status='exited')
        elif args[0] == 'start' and args[-1] in self.containers:
            self.containers[args[-1]]['State'].update(Running=True, Status='running')
        elif args[:2] == ('start', '--attach'):
            for folder in (self.data, self.tls):
                for entry in folder.iterdir():
                    shutil.rmtree(entry) if entry.is_dir() else entry.unlink()
        elif args[0] == 'inspect':
            return json.dumps([self.helpers.get(args[1]) or self.containers[args[1]]])
        elif args[0] == 'create':
            name = args[args.index('--name') + 1]
            self.helpers[name] = {'State': {'ExitCode': 0},
                'Config': {'Labels': {'io.alinksec.maintenance.binding': self.binding}}}
            return name
        elif args[0] == 'rm':
            self.fault('helper-remove')
            del self.helpers[args[-1]]
        elif args[0] == 'ps':
            if args[-1].startswith('name='):
                return '\n'.join(self.helpers)
            return 'server\nweb\n' + ('foreign\n' if self.foreign_writer else '')
        elif args[0] == 'cp' and args[-1] != '-':
            folder = self.data if args[-1].endswith(':/app/data') else self.tls
            with tarfile.open(fileobj=source, mode='r:') as archive:
                # These archives contain only this fixture's own files, already validated by the CLI.
                for member in archive:
                    path = folder / member.name
                    if member.isdir():
                        path.mkdir(exist_ok=True, parents=True)
                    else:
                        path.parent.mkdir(exist_ok=True, parents=True)
                        with archive.extractfile(member) as stream:
                            path.write_bytes(stream.read())
                        path.chmod(member.mode)
            self.fault('restore-copy')
        elif args[0] == 'cp':
            self.fault('snapshot-copy')
            folder = self.data if ':/app/data/' in args[-2] else self.tls
            with tarfile.open(fileobj=destination, mode='w:') as archive:
                archive.add(folder, arcname='.')
        else:
            raise AssertionError(args)
        return ''

    def pg(self, *args, source=None, destination=None):
        self.events.append(('pg', *args))
        if args[0] == 'psql':
            return '0\n'
        if args[0] == 'pg_dump':
            self.fault('pg-dump')
            destination.write(b'PGDMP' + self.pg_value.encode())
        elif args[0] == 'dropdb':
            self.pg_value = None
        elif '--list' in args:
            return ';     dbname: alinksec\n'
        elif args[0] == 'pg_restore':
            self.pg_value = source.read()[5:].decode()
            self.fault('pg-restore')
        else:
            raise AssertionError(args)
        return ''


def reseal(path):
    manifest = json.loads((path / 'manifest.json').read_text())
    manifest['files'] = {name: {'size': (path / name).stat().st_size, 'sha256': ops.digest(path / name)}
                         for name in manifest['files']}
    ops.atomic_json(path / 'manifest.json', manifest)


class OperationsTest(unittest.TestCase):
    def setUp(self):
        self.mask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()
        os.umask(self.mask)

    def fixture(self, mode='sqlite'):
        directory = self.root / mode
        directory.mkdir()
        return Fixture(directory, mode)

    def backup(self, deployment):
        target = deployment.root / 'backups' / 'accepted'
        with deployment.lock():
            deployment.maintain('backup', target)
        return target

    def assert_running(self, deployment):
        self.assertTrue(all(item['State']['Running'] for item in deployment.containers.values()))
        self.assertFalse(deployment.journal_path.exists())
        self.assertFalse(deployment.helpers)

    def test_complete_backup_and_restore_both_databases(self):
        for mode in ('sqlite', 'postgres'):
            with self.subTest(mode=mode):
                deployment = self.fixture(mode)
                target = self.backup(deployment)
                self.assertEqual(ops.verify_snapshot(target)['mode'], mode)
                self.assertEqual(target.stat().st_mode & 0o777, 0o700)
                self.assertTrue(all(entry.stat().st_mode & 0o077 == 0 for entry in target.iterdir()))
                deployment.set_value('after')
                (deployment.data / 'obsolete').write_text('must disappear')
                (deployment.tls / 'server.key').write_text('changed')
                deployment.maintain('restore', target)
                self.assertEqual(deployment.value(), 'before')
                self.assertEqual((deployment.tls / 'server.key').read_text(), 'original-tls-key')
                self.assertEqual((deployment.data / 'private').stat().st_mode & 0o777, 0o600)
                self.assertFalse((deployment.data / 'obsolete').exists())
                self.assert_running(deployment)
                self.assertEqual(len(list(target.parent.glob('pre-restore-*'))), 1)

    def test_partial_volume_or_database_restore_rolls_back_original(self):
        for mode in ('sqlite', 'postgres'):
            with self.subTest(mode=mode):
                deployment = self.fixture(mode)
                target = self.backup(deployment)
                deployment.set_value('original-at-restore')
                (deployment.tls / 'server.key').write_text('current-tls')
                deployment.failures['pg-restore' if mode == 'postgres' else 'restore-copy'] = 1
                with self.assertRaisesRegex(ops.MaintenanceError, 'original deployment recovered'):
                    deployment.maintain('restore', target)
                self.assertEqual(deployment.value(), 'original-at-restore')
                self.assertEqual((deployment.tls / 'server.key').read_text(), 'current-tls')
                self.assert_running(deployment)

    def test_failed_health_rolls_back_and_keeps_safety_snapshot(self):
        deployment = self.fixture()
        target = self.backup(deployment)
        # Build an internally valid snapshot whose CA cannot be loaded by the application.
        source = target / 'server-data.tar'
        replacement = source.with_suffix('.new')
        with tarfile.open(source, 'r:') as old, tarfile.open(replacement, 'w:') as new:
            for member in old:
                content = b'invalid-ca' if member.name.endswith('/ca.crt') else None
                if content is not None:
                    member.size = len(content)
                new.addfile(member, io.BytesIO(content) if content is not None else
                            (old.extractfile(member) if member.isfile() else None))
        replacement.replace(source)
        reseal(target)
        deployment.set_value('current')
        with self.assertRaisesRegex(ops.MaintenanceError, 'original deployment recovered'):
            deployment.maintain('restore', target)
        self.assertEqual(deployment.value(), 'current')
        self.assertEqual((deployment.data / 'ca.crt').read_text(), 'valid-ca')
        self.assert_running(deployment)

    def test_recovery_failure_stays_stopped_and_can_be_retried(self):
        deployment = self.fixture()
        target = self.backup(deployment)
        deployment.set_value('current')
        deployment.failures['restore-copy'] = 2
        with self.assertRaisesRegex(ops.MaintenanceError, 'Automatic recovery incomplete'):
            deployment.maintain('restore', target)
        self.assertTrue(deployment.journal_path.exists())
        self.assertFalse(deployment.containers['server']['State']['Running'])
        self.assertFalse(deployment.containers['web']['State']['Running'])
        deployment.recover()
        self.assertEqual(deployment.value(), 'current')
        self.assert_running(deployment)

    def test_unavailable_safety_requires_an_explicit_verified_fallback(self):
        deployment = self.fixture()
        target = self.backup(deployment)
        deployment.set_value('current')
        deployment.failures['restore-copy'] = 2
        with self.assertRaises(ops.MaintenanceError):
            deployment.maintain('restore', target)
        safety = Path(json.loads(deployment.journal_path.read_text())['safety'])
        (safety / 'environment.env').write_text('corrupted')
        with self.assertRaisesRegex(ops.MaintenanceError, 'checksum mismatch'):
            deployment.recover()
        self.assertFalse(deployment.containers['server']['State']['Running'])
        self.assertTrue(deployment.journal_path.exists())
        deployment.recover(target)
        self.assertEqual(deployment.value(), 'before')
        self.assert_running(deployment)

    def test_manual_recovery_health_failure_keeps_services_stopped(self):
        deployment = self.fixture()
        deployment.begin('backup')
        deployment.stop()
        deployment.failures['health'] = 1
        with self.assertRaisesRegex(ops.MaintenanceError, 'Injected failure'):
            deployment.recover()
        self.assertTrue(deployment.journal_path.exists())
        self.assertFalse(deployment.containers['server']['State']['Running'])
        self.assertFalse(deployment.containers['web']['State']['Running'])
        deployment.recover()
        self.assert_running(deployment)

    def test_copy_or_stop_failure_resumes_original_without_applying(self):
        for failure in ('snapshot-copy', 'stop-server'):
            directory = self.root / failure
            directory.mkdir()
            deployment = Fixture(directory)
            deployment.failures[failure] = 1
            with self.assertRaisesRegex(ops.MaintenanceError, 'original deployment recovered'):
                deployment.maintain('backup', directory / 'backups' / 'failed')
            self.assertFalse((directory / 'backups' / 'failed').exists())
            self.assertEqual(deployment.value(), 'before')
            self.assert_running(deployment)

    def test_corrupt_or_foreign_snapshot_refused_before_stopping(self):
        deployment = self.fixture()
        target = self.backup(deployment)
        deployment.events.clear()
        (target / 'environment.env').write_text('corrupted')
        with self.assertRaisesRegex(ops.MaintenanceError, 'checksum mismatch'):
            deployment.maintain('restore', target)
        self.assertFalse(any(isinstance(event, tuple) and event[0] == 'stop' for event in deployment.events))
        reseal(target)
        deployment.binding = 'different-runtime'
        with self.assertRaisesRegex(ops.MaintenanceError, 'original project'):
            deployment.maintain('restore', target)
        self.assert_running(deployment)

    def test_stopped_or_foreign_writer_or_pending_operation_refused(self):
        deployment = self.fixture()
        deployment.containers['web']['State']['Running'] = False
        with self.assertRaisesRegex(ops.MaintenanceError, 'already be running'):
            deployment.preflight()
        deployment.containers['web']['State']['Running'] = True
        deployment.foreign_writer = True
        with self.assertRaisesRegex(ops.MaintenanceError, 'Another running container'):
            deployment.preflight()
        deployment.foreign_writer = False
        deployment.begin('backup')
        with self.assertRaisesRegex(ops.MaintenanceError, 'interrupted operation'):
            deployment.preflight()
        deployment.recover()
        self.assert_running(deployment)

    def test_lock_cannot_be_bypassed_with_another_state_directory(self):
        deployment = self.fixture()
        other = object.__new__(Fixture)
        other.__dict__ = deployment.__dict__.copy()
        other.state_dir = deployment.root / 'different-state'
        other.state_dir.mkdir(mode=0o700)
        with deployment.lock():
            with self.assertRaisesRegex(ops.MaintenanceError, 'holds the deployment lock'):
                with other.lock():
                    self.fail('Concurrent mutation admitted')

    def test_sqlite_wal_contains_committed_data(self):
        deployment = self.fixture()
        connection = sqlite3.connect(deployment.data / 'alinksec.db')
        try:
            connection.execute('PRAGMA journal_mode=WAL')
            connection.execute('PRAGMA wal_autocheckpoint=0')
            connection.execute("UPDATE probe SET value='committed-in-wal'")
            connection.commit()
            target = self.backup(deployment)
            self.assertGreater((deployment.data / 'alinksec.db-wal').stat().st_size, 32)
            self.assertEqual(ops.verify_snapshot(target)['mode'], 'sqlite')
        finally:
            connection.close()
        deployment.set_value('after')
        deployment.maintain('restore', target)
        self.assertEqual(deployment.value(), 'committed-in-wal')

    def test_unsafe_archive_entries_rejected_even_with_valid_hashes(self):
        deployment = self.fixture()
        target = self.backup(deployment)
        cases = [('../escape', tarfile.REGTYPE),
                 ('/absolute', tarfile.REGTYPE), ('link', tarfile.SYMTYPE),
                 ('hard', tarfile.LNKTYPE), ('fifo', tarfile.FIFOTYPE)]
        for name, kind in cases:
            with self.subTest(name=name):
                with tarfile.open(target / 'web-tls.tar', 'w:') as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    archive.addfile(member)
                reseal(target)
                with self.assertRaises(ops.MaintenanceError):
                    ops.verify_snapshot(target)
        for names in [('a', 'a'), ('a', 'a/b'), ('a/b', 'a')]:
            with self.subTest(names=names):
                with tarfile.open(target / 'web-tls.tar', 'w:') as archive:
                    for name in names:
                        archive.addfile(tarfile.TarInfo(name))
                reseal(target)
                with self.assertRaises(ops.MaintenanceError):
                    ops.verify_snapshot(target)

    def test_symlinked_payload_and_broad_directory_permissions_rejected(self):
        deployment = self.fixture()
        target = self.backup(deployment)
        original = target / 'environment.env'
        original.unlink()
        original.symlink_to(deployment.env_file)
        with self.assertRaisesRegex(ops.MaintenanceError, 'symbolic'):
            ops.verify_snapshot(target)
        directory = self.root / 'public'
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        with self.assertRaisesRegex(ops.MaintenanceError, 'mode 700'):
            ops.private_directory(directory)

    def test_command_errors_do_not_print_secret_output(self):
        secret = 'not-for-logs'
        with self.assertRaises(ops.MaintenanceError) as caught:
            ops.run([sys.executable, '-c', f'import sys; print({secret!r}, file=sys.stderr); sys.exit(7)'])
        self.assertNotIn(secret, str(caught.exception))


if __name__ == '__main__':
    unittest.main()
