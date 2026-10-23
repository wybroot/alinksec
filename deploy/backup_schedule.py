#!/usr/bin/env python3
"""Private automatic full-deployment checkpoints and recovery-point selection.

Run on the Linux Compose host. A checkpoint includes the database, application
files, CA and TLS material. Recovery selects a complete verified checkpoint at or
before the requested UTC time; it does not claim continuous WAL-level recovery.
"""
import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shutil
import signal
import sys
import uuid

import operations as ops


def utc(value):
    ops.require(isinstance(value, str) and len(value) <= 64, 'An explicit timezone is required')
    parsed = dt.datetime.fromisoformat(value.replace('Z', '+00:00'))
    ops.require(parsed.tzinfo is not None, 'An explicit timezone is required')
    return parsed.astimezone(dt.timezone.utc)


def now():
    return dt.datetime.now(dt.timezone.utc)


def read_private(path):
    ops.require(path.is_file() and not path.is_symlink(), 'Private schedule metadata is missing or symbolic')
    info = path.stat()
    ops.require(info.st_uid == os.geteuid() and info.st_mode & 0o077 == 0 and info.st_size <= 1024 * 1024,
                'Schedule metadata must be private, owned and bounded')
    return json.loads(path.read_text())


class Schedule:
    """All operations run under Deployment.lock(), including retention/selection."""
    def __init__(self, deployment):
        self.deployment = deployment
        self.path = deployment.state_dir / 'schedule.json'

    def load(self):
        value = read_private(self.path)
        ops.require(value.get('format') == 1 and value.get('binding') == self.deployment.binding,
                    'Schedule belongs to a different deployment configuration')
        ops.require(type(value.get('enabled')) is bool and type(value.get('intervalMinutes')) is int
                    and 15 <= value['intervalMinutes'] <= 10080 and type(value.get('keep')) is int
                    and 2 <= value['keep'] <= 365, 'Invalid schedule limits')
        root = Path(value['backupDirectory'])
        ops.require(root.is_absolute() and str(root) == str(root.resolve()), 'Invalid backup directory')
        ops.private_directory(root)
        points = value.get('points')
        ops.require(isinstance(points, list) and len(points) <= 1000, 'Invalid recovery-point catalog')
        ids = set()
        for point in points:
            ops.require(isinstance(point, dict) and re.fullmatch(r'scheduled-[0-9TZ]+-[0-9a-f]{32}', point.get('id', ''))
                        and point['id'] not in ids and re.fullmatch(r'[0-9a-f]{64}', point.get('manifestSha256', '')),
                        'Invalid recovery-point identity')
            utc(point['completedAt'])
            ids.add(point['id'])
        return value

    def save(self, value):
        ops.atomic_json(self.path, value)

    def configure(self, directory, interval, keep):
        ops.require(15 <= interval <= 10080 and 2 <= keep <= 365, 'Interval must be 15..10080 minutes; keep must be 2..365')
        # Do not follow a symlink supplied as the repository root.
        directory = directory.absolute()
        ops.private_directory(directory)
        ops.require(directory == directory.resolve(), 'Backup directory parents must not be symbolic')
        previous = self.load() if self.path.exists() else None
        if previous:
            ops.require(previous['backupDirectory'] == str(directory), 'Use the original backup directory; moving a catalog is not supported')
            ops.require(not previous.get('attempt'), 'Resolve the previous attempt before changing the schedule')
        value = previous or {'format': 1, 'binding': self.deployment.binding,
                             'backupDirectory': str(directory), 'points': [], 'failures': 0}
        value.update(enabled=True, intervalMinutes=interval, keep=keep)
        self.save(value)
        return self.summary(value)

    def disable(self):
        value = self.load()
        value['enabled'] = False
        self.save(value)
        return self.summary(value)

    def summary(self, value=None):
        value = value or self.load()
        return {key: value.get(key) for key in ('enabled', 'intervalMinutes', 'keep', 'backupDirectory',
                'lastSuccessAt', 'lastFailureAt', 'nextAttemptAt', 'failures', 'attempt', 'points')}

    def verified(self, value, point):
        path = Path(value['backupDirectory']) / point['id']
        manifest = self.deployment.compatible(path)
        ops.require(ops.digest(path / 'manifest.json') == point['manifestSha256']
                    and manifest['createdAt'] == point['completedAt'], 'Recovery-point catalog does not match the sealed snapshot')
        return path, manifest

    def publish(self, value, path):
        manifest = self.deployment.compatible(path)
        completed = manifest['createdAt']
        utc(completed)
        if not any(point['id'] == path.name for point in value['points']):
            value['points'].append({'id': path.name, 'completedAt': completed,
                                    'manifestSha256': ops.digest(path / 'manifest.json')})
        value.update(lastSuccessAt=completed, failures=0, attempt=None, nextAttemptAt=None)
        self.save(value)  # Publish before pruning; interrupted pruning is retryable.

    def prune(self, value):
        points = sorted(value['points'], key=lambda point: (utc(point['completedAt']), point['id']))
        obsolete = points[:-value['keep']]
        if not obsolete:
            return
        # Validate every victim before deleting anything. Never touch untracked
        # manual/safety/partial snapshots or follow a replaced snapshot symlink.
        for point in obsolete:
            self.verified(value, point)
        for point in obsolete:
            path = Path(value['backupDirectory']) / point['id']
            # Remove from the catalog first: a crash leaves a private orphan,
            # never an advertised point whose bytes have already disappeared.
            value['points'] = [entry for entry in value['points'] if entry['id'] != point['id']]
            self.save(value)
            shutil.rmtree(path)
            ops.sync_directory(path.parent)

    def run(self, force=False, clock=None):
        clock = clock or now()
        value = self.load()
        ops.require(not self.deployment.journal_path.exists(), 'Interrupted maintenance requires operations.py recover --yes first')
        attempt = value.get('attempt')
        if attempt:
            ops.require(isinstance(attempt, dict) and re.fullmatch(r'scheduled-[0-9TZ]+-[0-9a-f]{32}', attempt.get('id', '')),
                        'Invalid interrupted schedule attempt')
            path = Path(value['backupDirectory']) / attempt['id']
            self.deployment.preflight()
            if path.exists() or path.is_symlink():
                self.publish(value, path)
            else:
                # A process killed before sealing has no published point. The
                # private .partial-* directory remains for diagnosis.
                value.update(attempt=None, failures=value.get('failures', 0) + 1,
                             lastFailureAt=clock.isoformat(), nextAttemptAt=None)
                self.save(value)
        self.prune(value)
        if not value['enabled']:
            return {'result': 'disabled'}
        if not force:
            if value.get('nextAttemptAt') and clock < utc(value['nextAttemptAt']):
                return {'result': 'retry-not-due', 'nextAttemptAt': value['nextAttemptAt']}
            if value.get('lastSuccessAt') and clock < utc(value['lastSuccessAt']) + dt.timedelta(minutes=value['intervalMinutes']):
                return {'result': 'not-due'}
        point_id = 'scheduled-' + clock.strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex
        path = Path(value['backupDirectory']) / point_id
        value['attempt'] = {'id': point_id, 'startedAt': clock.isoformat()}
        self.save(value)
        try:
            self.deployment.maintain('backup', path)
            self.publish(value, path)
        except BaseException:
            # Never log exception text, environment variables or subprocess argv.
            failures = min(value.get('failures', 0) + 1, 1000)
            value.update(failures=failures, lastFailureAt=clock.isoformat(),
                         nextAttemptAt=(clock + dt.timedelta(minutes=min(60, 5 * failures))).isoformat())
            # Keep the attempt if a sealed point or pending rollback needs reconciliation.
            if not path.exists() and not self.deployment.journal_path.exists():
                value['attempt'] = None
            self.save(value)
            raise
        self.prune(value)
        return {'result': 'completed', 'point': value['points'][-1]}

    def select(self, requested):
        value = self.load()
        target = utc(requested)
        candidates = sorted((point for point in value['points'] if utc(point['completedAt']) <= target),
                            key=lambda point: (utc(point['completedAt']), point['id']), reverse=True)
        ops.require(candidates, 'No complete recovery point exists at or before the requested time')
        # Fail visibly on corruption instead of silently choosing an older point.
        path, manifest = self.verified(value, candidates[0])
        return path, {'requestedAt': target.isoformat(), 'selectedAt': manifest['createdAt'],
                      'point': path.name, 'granularity': 'complete-deployment-checkpoint',
                      'manifestSha256': candidates[0]['manifestSha256']}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compose-file', default='deploy/docker/docker-compose.lite.yml')
    parser.add_argument('--env-file', default='deploy/docker/.env.lite')
    parser.add_argument('--state-dir', default='.operations')
    parser.add_argument('--timeout', type=int, default=180)
    commands = parser.add_subparsers(dest='command', required=True)
    configure = commands.add_parser('configure', help='Explicitly enable scheduled maintenance downtime')
    configure.add_argument('--backup-dir', type=Path, required=True)
    configure.add_argument('--interval-minutes', type=int, default=1440)
    configure.add_argument('--keep', type=int, default=7)
    commands.add_parser('disable')
    commands.add_parser('list')
    run = commands.add_parser('run-due')
    run.add_argument('--force', action='store_true', help='Create a point now, respecting the enabled flag')
    for name in ('select', 'restore-at'):
        select = commands.add_parser(name)
        select.add_argument('time', help='ISO-8601 timestamp with explicit timezone')
        if name == 'restore-at':
            select.add_argument('--yes', action='store_true', required=True)
            select.add_argument('--expected-manifest-sha256', required=True,
                                help='Digest returned by select; binds approval to the reviewed point')
    args = parser.parse_args(argv)
    ops.require(sys.platform == 'linux' and ops.fcntl is not None, 'Linux Docker host with Python 3.10+ required')
    ops.require(1 <= args.timeout <= 3600, 'Timeout must be between 1 and 3600 seconds')
    os.umask(0o077)
    deployment = ops.Deployment(args)
    with deployment.lock():
        schedule = Schedule(deployment)
        if args.command == 'configure':
            result = schedule.configure(args.backup_dir, args.interval_minutes, args.keep)
        elif args.command == 'disable':
            result = schedule.disable()
        elif args.command == 'list':
            result = schedule.summary()
        elif args.command == 'run-due':
            result = schedule.run(args.force)
        else:
            path, result = schedule.select(args.time)
            if args.command == 'restore-at':
                ops.require(args.expected_manifest_sha256 == result['manifestSha256'],
                            'Selected recovery point changed; review select output again')
                deployment.maintain('restore', path)
                result['restored'] = True
                result['safetySnapshot'] = deployment.journal.get('safety')
        print(json.dumps(result, ensure_ascii=False))


if __name__ == '__main__':
    def interrupted(signum, _frame):
        raise ops.MaintenanceError(f'Interrupted by signal {signum}')
    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, interrupted)
    try:
        main()
    except (ops.MaintenanceError, OSError, ValueError, KeyError, TypeError, ops.sqlite3.Error, ops.tarfile.TarError) as error:
        print(str(error) if isinstance(error, ops.MaintenanceError) else 'Invalid or inaccessible schedule input', file=sys.stderr)
        sys.exit(1)
