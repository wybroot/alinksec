#!/usr/bin/env python3
"""Coordinated, offline backups for an existing single-node Linux Compose deployment.

Python 3.10+, Docker Compose v2. Never builds, pulls, recreates services or deletes
volumes. Backup directories contain secrets and must be stored on trusted media.
"""
import argparse
import contextlib
import datetime
try:
    import fcntl
except ImportError:
    fcntl = None
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid


class MaintenanceError(Exception):
    pass


def require(condition, message):
    if not condition:
        raise MaintenanceError(message)


def digest(path):
    h = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()


def atomic_json(path, value):
    temporary = path.with_name(path.name + '.new')
    with temporary.open('w', encoding='utf-8') as stream:
        json.dump(value, stream, ensure_ascii=False, indent=2)
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    sync_directory(path.parent)


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def private_directory(path):
    require(not path.is_symlink(), 'Private directory must not be a symlink')
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    info = path.stat()
    require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0,
            'State/backup directory must be owned by this user with mode 700')


def run(args, *, source=None, destination=None, timeout=180):
    # Never include captured output/argv in errors: Compose and SQL can contain secrets.
    try:
        with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
            result = subprocess.run(args, stdin=source, stdout=destination or output,
                                    stderr=errors, timeout=timeout, check=False)
            require(result.returncode == 0, f'{args[0]} command failed (exit {result.returncode}); services may need recovery')
            if destination is not None:
                return ''
            require(output.tell() <= 4 * 1024 * 1024, 'Command metadata exceeds 4 MiB')
            output.seek(0)
            return output.read().decode('utf-8')
    except (OSError, subprocess.TimeoutExpired) as error:
        raise MaintenanceError(f'{args[0]} unavailable or timed out') from error


def archive_members(path):
    """No extraction of untrusted paths, links, devices, duplicates or sparse files."""
    seen = {}
    required_directories = set()
    with tarfile.open(path, 'r|') as archive:
        for member in archive:
            name = PurePosixPath(member.name)
            require(not name.is_absolute() and '..' not in name.parts and
                    (member.isfile() or member.isdir()) and not member.issparse(),
                    'Archive contains unsupported paths or file types (only ordinary files/directories supported)')
            require(not member.mode & ~0o777 and 0 <= member.uid < 2**32 - 1 and 0 <= member.gid < 2**32 - 1,
                    'Archive contains unsupported permissions or ownership')
            require(set(member.pax_headers) <= {'path', 'size', 'uid', 'gid', 'uname', 'gname', 'mtime', 'atime', 'ctime'},
                    'Extended archive attributes are unsupported')
            normalized = str(name)
            require(len(normalized.encode()) <= 4096 and len(name.parts) <= 64, 'Archive path exceeds supported limits')
            require(normalized != '.' or member.isdir(), 'Archive root must be a directory')
            require(normalized not in seen, 'Archive contains duplicate paths')
            require(all(seen.get(str(parent), True) for parent in name.parents), 'Archive file is used as a parent directory')
            if member.isfile():
                require(normalized not in required_directories, 'Archive file replaces a parent directory')
            required_directories.update(str(parent) for parent in name.parents)
            seen[normalized] = member.isdir()
            require(len(seen) <= 100000, 'Archive exceeds the 100000 entry limit')
            yield archive, member, normalized


def verify_snapshot(path):
    require(path.is_dir() and not path.is_symlink(), 'Snapshot directory missing or symbolic')
    manifest_path = path / 'manifest.json'
    require(manifest_path.is_file() and not manifest_path.is_symlink(), 'Snapshot is not sealed')
    require(manifest_path.stat().st_size <= 1024 * 1024, 'Manifest is too large')
    manifest = json.loads(manifest_path.read_text())
    require(isinstance(manifest, dict) and manifest.get('format') == 1 and
            manifest.get('mode') in ('sqlite', 'postgres') and isinstance(manifest.get('files'), dict),
            'Unsupported snapshot format')
    expected = {'server-data.tar', 'web-tls.tar', 'deployment.json', 'compose.yaml', 'environment.env'}
    if manifest['mode'] == 'postgres':
        expected.add('database.dump')
    require(set(manifest.get('files', {})) == expected, 'Snapshot file set is incomplete')
    require({entry.name for entry in path.iterdir()} == expected | {'manifest.json'}, 'Unexpected snapshot entries')
    for name in sorted(expected):
        entry = path / name
        require(entry.is_file() and not entry.is_symlink(), 'Snapshot file missing or symbolic')
        metadata = manifest['files'][name]
        require(isinstance(metadata, dict) and type(metadata.get('size')) is int and metadata['size'] >= 0 and
                isinstance(metadata.get('sha256'), str) and re.fullmatch(r'[0-9a-f]{64}', metadata['sha256']),
                'Invalid snapshot file metadata')
        require(entry.stat().st_size == metadata['size'] and digest(entry) == metadata['sha256'],
                f'Snapshot checksum mismatch: {name}')
    require((path / 'deployment.json').stat().st_size <= 4 * 1024 * 1024, 'Deployment metadata is too large')
    identity = json.loads((path / 'deployment.json').read_text())['identity']
    require(fingerprint(identity) == manifest['binding'] and identity['project'] == manifest['project']
            and identity['mode'] == manifest['mode'], 'Snapshot deployment metadata does not match its manifest')
    for name in ('server-data.tar', 'web-tls.tar'):
        for _ in archive_members(path / name):
            pass
    if manifest['mode'] == 'sqlite':
        with tempfile.TemporaryDirectory(prefix='alinksec-db-verify-') as directory:
            found = False
            for archive, member, name in archive_members(path / 'server-data.tar'):
                if name in ('alinksec.db', 'alinksec.db-wal'):
                    require(member.isfile(), 'SQLite snapshot entry must be a regular file')
                    with archive.extractfile(member) as source, (Path(directory) / name).open('xb') as target:
                        shutil.copyfileobj(source, target, 1024 * 1024)
                    found |= name == 'alinksec.db'
            require(found, 'SQLite snapshot has no database')
            with (Path(directory) / 'alinksec.db').open('rb') as stream:
                require(stream.read(16) == b'SQLite format 3\x00', 'Invalid SQLite database header')
            with contextlib.closing(sqlite3.connect(Path(directory) / 'alinksec.db')) as database:
                require(database.execute('PRAGMA integrity_check').fetchall() == [('ok',)],
                        'SQLite integrity check failed')
    else:
        with (path / 'database.dump').open('rb') as stream:
            require(stream.read(5) == b'PGDMP', 'PostgreSQL dump must use custom format')
    return manifest


class Deployment:
    def __init__(self, args):
        self.args = args
        self.compose_file = Path(args.compose_file).absolute()
        self.env_file = Path(args.env_file).absolute()
        require(self.compose_file.is_file() and self.env_file.is_file(), 'Compose and environment files are required')
        require(self.env_file.stat().st_mode & 0o077 == 0, 'Environment file must have mode 600 or stricter')
        self.compose = ['docker', 'compose', '--env-file', str(self.env_file), '-f', str(self.compose_file)]
        self.config = json.loads(run(self.compose + ['config', '--format', 'json']))
        self.project = self.config['name']
        self.containers = {}
        for service in ('server', 'web', 'postgres'):
            if service not in self.config['services']:
                continue
            ids = run(self.compose + ['ps', '--all', '--quiet', service]).split()
            require(len(ids) == 1, f'Exactly one existing {service} container is required')
            item = json.loads(run(['docker', 'inspect', ids[0]]))[0]
            labels = item['Config'].get('Labels') or {}
            require(labels.get('com.docker.compose.project') == self.project and
                    labels.get('com.docker.compose.service') == service, 'Container deployment labels do not match')
            self.containers[service] = item
        require({'server', 'web'} <= set(self.containers), 'Both server and web services are required')
        self.mode = 'postgres' if 'postgres' in self.containers else 'sqlite'
        server = self.containers['server']
        mounts = {item['Destination']: item for item in server['Mounts']}
        require(set(mounts) == {'/app/data', '/app/web-tls'} and
                all(item['Type'] == 'volume' and item['RW'] for item in mounts.values()),
                'Server must use exactly the two standard writable named volumes')
        self.mounts = mounts
        web_mounts = {item['Destination']: item for item in self.containers['web']['Mounts']}
        require(set(web_mounts) == {'/etc/nginx/tls'} and
                web_mounts['/etc/nginx/tls']['Name'] == mounts['/app/web-tls']['Name'] and
                not web_mounts['/etc/nginx/tls']['RW'], 'Web must use the same TLS volume read-only')
        self.identity = {'project': self.project, 'mode': self.mode,
                         'volumes': {key: item['Name'] for key, item in mounts.items()},
                         'runtime': {name: {'image': item['Image'], 'env': sorted(item['Config']['Env'])}
                                     for name, item in self.containers.items()}}
        if self.mode == 'postgres':
            writable = [item for item in self.containers['postgres']['Mounts'] if item['RW']]
            require(len(writable) == 1 and writable[0]['Type'] == 'volume' and
                    writable[0]['Destination'] == '/var/lib/postgresql/data',
                    'PostgreSQL must use its standard named data volume')
            self.identity['volumes']['postgres:/var/lib/postgresql/data'] = writable[0]['Name']
        engine_info = run(['docker', 'info', '--format', '{{.OSType}} {{.ID}}']).strip().split()
        require(len(engine_info) == 2 and engine_info[0] == 'linux', 'A Linux Docker engine is required')
        engine = engine_info[1]
        self.identity['engine'] = engine
        volumes = json.loads(run(['docker', 'volume', 'inspect', *self.identity['volumes'].values()]))
        require(all(item['Driver'] == 'local' and not item.get('Options') for item in volumes),
                'Only standard local Docker named volumes are supported')
        self.binding = fingerprint(self.identity)
        self.state_dir = Path(args.state_dir).absolute()
        private_directory(self.state_dir)
        self.journal_path = self.state_dir / 'pending.json'
        self.journal = None
        # Independent state directories cannot bypass the per-engine/volume host lock.
        lock_dir = Path('/tmp') / ('alinksec-maintenance-' + str(os.geteuid()))
        private_directory(lock_dir)
        self.lock_path = lock_dir / (fingerprint({'engine': engine,
            'volumes': sorted(self.identity['volumes'].values())}) + '.lock')

    def docker(self, *args, **kwargs):
        return run(['docker', *args], timeout=self.args.timeout, **kwargs)

    @contextlib.contextmanager
    def lock(self):
        with self.lock_path.open('a') as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise MaintenanceError('Another maintenance operation holds the deployment lock') from error
            owner_path = self.state_dir / 'deployment.json'
            owner = {'project': self.project, 'volumes': self.identity['volumes']}
            if owner_path.exists():
                require(json.loads(owner_path.read_text()) == owner, 'State directory belongs to another deployment')
            else:
                atomic_json(owner_path, owner)
            yield

    def status(self):
        return {'project': self.project, 'mode': self.mode, 'binding': self.binding,
                'services': {name: {'id': item['Id'], 'image': item['Image'], 'status': item['State']['Status']}
                             for name, item in self.containers.items()},
                'recoveryRequired': self.journal_path.exists()}

    def preflight(self):
        require(not self.journal_path.exists(), 'An interrupted operation requires recover --yes first')
        for name, item in self.containers.items():
            require(item['State']['Running'] and not item['State'].get('Paused') and
                    not item['State'].get('Restarting'), f'{name} must already be running and unpaused')
        # Reject uncoordinated writers, including a concurrent legacy maintenance container.
        own = {item['Id'] for item in self.containers.values()}
        for volume in self.identity['volumes'].values():
            others = self.docker('ps', '--quiet', '--no-trunc', '--filter', f'volume={volume}').split()
            require(set(others) <= own, 'Another running container uses a protected volume')
        if self.mode == 'postgres':
            owner, database = self.pg_settings()
            count = self.pg('psql', '-X', '-U', owner, '--dbname', database, '-Atc',
                            "SELECT count(*) FROM pg_tablespace WHERE spcname NOT IN ('pg_default','pg_global')").strip()
            require(count == '0', 'Custom PostgreSQL tablespaces require a separate recovery procedure')
        self.health()
        return self.status()

    def health(self):
        # The probe stays inside nginx; it tests its HTTPS -> application route.
        deadline = time.monotonic() + self.args.timeout
        while True:
            try:
                response = json.loads(self.docker('exec', self.containers['web']['Id'], 'wget',
                    '--no-check-certificate', '-T', '2', '-qO-', 'https://127.0.0.1/api/health'))
                require(isinstance(response, dict) and response.get('code') == 0,
                        'Application health endpoint rejected the request')
                return
            except (MaintenanceError, ValueError):
                require(time.monotonic() < deadline, 'Application did not become healthy before timeout')
                time.sleep(1)

    def record(self, **changes):
        self.journal.update(changes)
        atomic_json(self.journal_path, self.journal)

    def begin(self, kind):
        self.journal = {'format': 1, 'kind': kind, 'binding': self.binding, 'phase': 'stopping',
                        'mutated': False, 'safety': None, 'helper': None}
        self.record()

    def stop(self):
        self.docker('stop', '--time', '30', self.containers['web']['Id'])
        self.docker('stop', '--time', '30', self.containers['server']['Id'])
        for name in ('server', 'web'):
            state = json.loads(self.docker('inspect', self.containers[name]['Id']))[0]['State']
            require(not state['Running'], f'{name} did not stop')

    def start(self):
        # Existing containers only: no implicit dependencies, migrations, builds or pulls.
        for name in ('server', 'web'):
            self.docker('start', self.containers[name]['Id'])
        self.health()

    def pg(self, *args, **kwargs):
        # Read the password inside the existing container; never place it on host argv.
        return self.docker('exec', '-i', self.containers['postgres']['Id'], '/bin/sh', '-c',
                           'export PGPASSWORD="$POSTGRES_PASSWORD"; exec "$@"', 'maintenance', args[0],
                           '--host=/var/run/postgresql', '--port=5432', '--no-password', *args[1:], **kwargs)

    def pg_settings(self):
        env = dict(entry.split('=', 1) for entry in self.containers['postgres']['Config']['Env'])
        owner, database = env.get('POSTGRES_USER', 'postgres'), env.get('POSTGRES_DB', 'postgres')
        require(all(re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]{0,62}', entry) for entry in (owner, database))
                and database not in ('postgres', 'template0', 'template1'), 'Unsupported PostgreSQL database/owner identity')
        return owner, database

    def snapshot(self, path):
        require(not path.exists() and not path.is_symlink(), 'Snapshot destination already exists')
        private_directory(path.parent)
        stage = path.parent / ('.partial-' + uuid.uuid4().hex)
        stage.mkdir(mode=0o700)
        # Incomplete stages remain private for diagnosis and are never published as the destination.
        for target, name in (('/app/data', 'server-data.tar'), ('/app/web-tls', 'web-tls.tar')):
            with (stage / name).open('xb') as stream:
                self.docker('cp', '-a', self.containers['server']['Id'] + ':' + target + '/.', '-', destination=stream)
                stream.flush()
                os.fsync(stream.fileno())
        if self.mode == 'postgres':
            owner, database = self.pg_settings()
            with (stage / 'database.dump').open('xb') as stream:
                self.pg('pg_dump', '-U', owner, '--format=custom', '--dbname', database, destination=stream)
                stream.flush()
                os.fsync(stream.fileno())
        (stage / 'deployment.json').write_text(json.dumps({'identity': self.identity, 'compose': self.config}, indent=2))
        shutil.copyfile(self.compose_file, stage / 'compose.yaml')
        shutil.copyfile(self.env_file, stage / 'environment.env')
        files = {entry.name: {'size': entry.stat().st_size, 'sha256': digest(entry)} for entry in stage.iterdir()}
        manifest = {'format': 1, 'mode': self.mode, 'project': self.project, 'binding': self.binding,
                    'createdAt': datetime.datetime.now(datetime.timezone.utc).isoformat(), 'files': files}
        atomic_json(stage / 'manifest.json', manifest)
        self.compatible(stage)
        for entry in stage.iterdir():
            with entry.open('rb') as stream:
                os.fsync(stream.fileno())
        # The deployment lock prevents same-tool destination races.
        require(not path.exists(), 'Snapshot destination was created concurrently')
        stage.rename(path)
        sync_directory(path.parent)
        return manifest

    def compatible(self, path):
        manifest = verify_snapshot(path)
        require(manifest['binding'] == self.binding, 'Snapshot requires its original project, volumes, image IDs and runtime environment')
        if self.mode == 'postgres':
            with (path / 'database.dump').open('rb') as stream:
                listing = self.pg('pg_restore', '--list', source=stream)
            _, database = self.pg_settings()
            require(re.findall(r'^;\s+dbname: (.+)$', listing, re.MULTILINE) == [database],
                    'PostgreSQL archive database identity does not match this deployment')
        return manifest

    def apply(self, path):
        # Every destructive action follows a durable journal and a sealed safety snapshot.
        self.record(mutated=True)
        helper = 'alinksec-maintenance-' + uuid.uuid4().hex
        self.record(helper=helper)
        args = ['create', '--name', helper, '--network=none', '--read-only', '--memory=64m',
                '--memory-swap=96m', '--cpus=1', '--pids-limit=32', '--cap-drop=ALL',
                '--cap-add=DAC_OVERRIDE', '--security-opt=no-new-privileges:true', '--user', '0:0',
                '--label', 'io.alinksec.maintenance.binding=' + self.binding]
        for target, mount in self.mounts.items():
            args += ['--mount', f"type=volume,source={mount['Name']},target={target}"]
        args += ['--entrypoint', '/bin/sh', self.containers['server']['Image'], '-c',
                 'find /app/data /app/web-tls -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +']
        self.docker(*args)
        self.docker('start', '--attach', helper)
        state = json.loads(self.docker('inspect', helper))[0]['State']
        require(state['ExitCode'] == 0, 'Volume cleanup failed')
        for target, name in (('/app/data', 'server-data.tar'), ('/app/web-tls', 'web-tls.tar')):
            with (path / name).open('rb') as stream:
                # For a tar on stdin, preserve its numeric owners. Docker's copyUIDGID
                # (-a on upload) instead forces the configured container user's IDs.
                self.docker('cp', '-', helper + ':' + target, source=stream)
        self.remove_helper()
        if self.mode == 'postgres':
            owner, database = self.pg_settings()
            # Recreate the whole database, preserving its ACL, locale and settings from the dump.
            self.pg('dropdb', '-U', owner, '--if-exists', '--force', '--', database)
            with (path / 'database.dump').open('rb') as stream:
                self.pg('pg_restore', '-U', owner, '--exit-on-error', '--create', '--dbname', 'postgres', source=stream)

    def remove_helper(self):
        helper = self.journal.get('helper')
        if helper:
            require(re.fullmatch(r'alinksec-maintenance-[0-9a-f]{32}', helper), 'Invalid recovery helper identity')
            ids = self.docker('ps', '--all', '--quiet', '--filter', 'name=^/' + helper + '$').split()
            if ids:
                item = json.loads(self.docker('inspect', helper))[0]
                require((item['Config'].get('Labels') or {}).get('io.alinksec.maintenance.binding') == self.binding,
                        'Recovery helper belongs to another operation')
                self.docker('rm', '--force', helper)
            self.record(helper=None)

    def finish(self):
        self.journal_path.unlink()
        sync_directory(self.state_dir)

    def recover(self, snapshot=None):
        require(self.journal_path.is_file(), 'No interrupted operation to recover')
        self.journal = json.loads(self.journal_path.read_text())
        require(self.journal.get('format') == 1 and self.journal.get('binding') == self.binding,
                'Recovery requires the original deployment configuration and images')
        if snapshot is not None:
            self.compatible(snapshot)
        try:
            self.stop()
            self.remove_helper()
            if snapshot is not None:
                # An explicit fallback also supports a damaged safety snapshot or a
                # pre-existing invalid application that cannot simply be restarted.
                self.record(previousSafety=self.journal.get('safety'), safety=str(snapshot), mutated=True)
            if self.journal['mutated']:
                require(self.journal.get('safety'), 'Missing safety snapshot: keep services stopped for manual recovery')
                safety = Path(self.journal['safety'])
                self.compatible(safety)
                self.record(phase='rollback')
                self.apply(safety)
            self.start()
            self.finish()
        except BaseException:
            try:
                self.stop()
            except BaseException:
                pass
            raise

    def maintain(self, kind, path):
        self.preflight()
        if kind == 'restore':
            self.compatible(path)  # Before any downtime or modification.
        else:
            require(not path.exists() and not path.is_symlink(), 'Snapshot destination already exists')
        self.begin(kind)
        try:
            self.stop()
            self.record(phase='snapshot')
            if kind == 'backup':
                self.snapshot(path)
            else:
                safety = path.parent / ('pre-restore-' + uuid.uuid4().hex)
                self.snapshot(safety)
                self.record(safety=str(safety), phase='applying')
                self.compatible(path)
                self.apply(path)
            self.record(phase='checking')
            self.start()
            self.finish()
        except BaseException as original:
            try:
                self.recover()
            except BaseException:
                # Do not leave a partially restored application serving requests.
                try:
                    self.stop()
                except BaseException:
                    pass
                raise MaintenanceError('Automatic recovery incomplete; keep services stopped and run recover --yes with the original state directory') from original
            raise MaintenanceError('Operation failed; original deployment recovered and healthy') from original


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose-file', default='deploy/docker/docker-compose.lite.yml')
    parser.add_argument('--env-file', default='deploy/docker/.env.lite')
    parser.add_argument('--state-dir', default='.operations')
    parser.add_argument('--timeout', type=int, default=180)
    commands = parser.add_subparsers(dest='command', required=True)
    commands.add_parser('status')
    commands.add_parser('check')
    for name in ('backup', 'verify', 'restore'):
        command = commands.add_parser(name)
        command.add_argument('snapshot', type=Path)
        if name == 'restore':
            command.add_argument('--yes', action='store_true', required=True)
    recovery = commands.add_parser('recover')
    recovery.add_argument('--yes', action='store_true', required=True)
    recovery.add_argument('--snapshot', type=Path, help='Explicit fallback if the original safety snapshot is unavailable')
    args = parser.parse_args(argv)
    require(sys.platform == 'linux' and fcntl is not None, 'Run maintenance on a Linux Docker host with Python 3.10+')
    require(1 <= args.timeout <= 3600, 'Timeout must be between 1 and 3600 seconds')
    os.umask(0o077)
    if args.command == 'verify':
        result = verify_snapshot(args.snapshot.absolute())
        print(json.dumps({'verified': True, 'mode': result['mode'], 'createdAt': result['createdAt']}))
        return
    deployment = Deployment(args)
    with deployment.lock():
        if args.command == 'status':
            result = deployment.status()
        elif args.command == 'check':
            result = deployment.preflight()
        elif args.command == 'recover':
            deployment.recover(args.snapshot.absolute() if args.snapshot else None)
            result = {'recovered': True}
        else:
            deployment.maintain(args.command, args.snapshot.absolute())
            result = {'completed': args.command, 'snapshot': str(args.snapshot.absolute()),
                      'safetySnapshot': deployment.journal.get('safety')}
        print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise MaintenanceError(f'Interrupted by signal {signum}')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        main()
    except (MaintenanceError, OSError, ValueError, KeyError, TypeError, sqlite3.Error, tarfile.TarError) as error:
        # Only our controlled errors are printed; arbitrary decoder/OS messages may contain secrets.
        print(str(error) if isinstance(error, MaintenanceError) else 'Invalid or inaccessible maintenance input', file=sys.stderr)
        sys.exit(1)
