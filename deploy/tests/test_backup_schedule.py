"""Real sealed SQLite checkpoints exercise scheduling, retention and recovery."""
import datetime as dt
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parents[1]))
import backup_schedule as scheduled
from test_operations import Fixture, ops
scheduled.ops = ops


class BackupScheduleTest(unittest.TestCase):
    def setUp(self):
        self.mask = os.umask(0o077)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.deployment = Fixture(self.root)
        self.schedule = scheduled.Schedule(self.deployment)
        self.repository = self.root / 'backups'
        self.schedule.configure(self.repository, 60, 2)

    def tearDown(self):
        self.temp.cleanup()
        os.umask(self.mask)

    def point(self):
        return self.schedule.run(force=True)['point']

    def test_due_interval_disabled_and_missed_runs_coalesce(self):
        first = self.point()
        completed = scheduled.utc(first['completedAt'])
        self.assertEqual(self.schedule.run(clock=completed + dt.timedelta(minutes=59))['result'], 'not-due')
        self.assertEqual(self.schedule.run(clock=completed + dt.timedelta(days=10))['result'], 'completed')
        self.assertEqual(len(self.schedule.load()['points']), 2)
        self.schedule.disable()
        before = len(self.deployment.events)
        self.assertEqual(self.schedule.run(force=True)['result'], 'disabled')
        self.assertEqual(len(self.deployment.events), before)

    def test_select_before_between_and_after_points_and_restore_whole_state(self):
        first = self.point()
        self.deployment.set_value('after-first')
        (self.deployment.tls / 'server.key').write_text('changed-key')
        second = self.point()
        cutoff = scheduled.utc(first['completedAt'])
        with self.assertRaisesRegex(scheduled.ops.MaintenanceError, 'No complete recovery point'):
            self.schedule.select((cutoff - dt.timedelta(microseconds=1)).isoformat())
        path, review = self.schedule.select(cutoff.isoformat())
        self.assertEqual(path.name, first['id'])
        self.assertEqual(review['manifestSha256'], first['manifestSha256'])
        self.assertEqual(review['granularity'], 'complete-deployment-checkpoint')
        self.assertEqual(self.schedule.select(second['completedAt'])[0].name, second['id'])
        self.deployment.maintain('restore', path)
        self.assertEqual(self.deployment.value(), 'before')
        self.assertEqual((self.deployment.tls / 'server.key').read_text(), 'original-tls-key')
        self.assertEqual(len(list(self.repository.glob('pre-restore-*'))), 1)
        self.assertFalse(self.deployment.journal_path.exists())

    def test_retention_preserves_manual_safety_and_partial_directories(self):
        first = self.point()
        for name in ('manual', 'pre-restore-fixture', '.partial-fixture'):
            (self.repository / name).mkdir()
            (self.repository / name / 'sentinel').write_text('keep')
        self.point()
        self.point()
        self.assertFalse((self.repository / first['id']).exists())
        self.assertEqual(len(self.schedule.load()['points']), 2)
        for name in ('manual', 'pre-restore-fixture', '.partial-fixture'):
            self.assertEqual((self.repository / name / 'sentinel').read_text(), 'keep')

    def test_failed_backup_recovers_and_backs_off_without_deleting_previous_point(self):
        first = self.point()
        self.deployment.failures['snapshot-copy'] = 1
        clock = scheduled.now() + dt.timedelta(hours=2)
        with self.assertRaisesRegex(scheduled.ops.MaintenanceError, 'original deployment recovered'):
            self.schedule.run(force=True, clock=clock)
        value = self.schedule.load()
        self.assertEqual(value['failures'], 1)
        self.assertIsNone(value['attempt'])
        self.assertEqual(value['points'], [first])
        self.assertEqual(self.deployment.value(), 'before')
        self.assertEqual(self.schedule.run(clock=clock + dt.timedelta(minutes=4))['result'], 'retry-not-due')
        self.assertEqual(self.schedule.run(clock=clock + dt.timedelta(minutes=6))['result'], 'completed')
        self.assertEqual(self.schedule.load()['failures'], 0)

    def test_crash_after_sealing_reconciles_instead_of_duplicate_backup(self):
        first = self.point()
        value = self.schedule.load()
        value.update(points=[], lastSuccessAt=None, attempt={'id': first['id'], 'startedAt': first['completedAt']})
        self.schedule.save(value)
        before = sum(event[0] == 'stop' for event in self.deployment.events if isinstance(event, tuple))
        self.assertEqual(self.schedule.run()['result'], 'not-due')
        self.assertEqual(self.schedule.load()['points'], [first])
        self.assertIsNone(self.schedule.load()['attempt'])
        self.assertEqual(sum(event[0] == 'stop' for event in self.deployment.events if isinstance(event, tuple)), before)

    def test_pending_recovery_prevents_automatic_modification(self):
        self.deployment.begin('restore')
        before = list(self.deployment.events)
        with self.assertRaisesRegex(scheduled.ops.MaintenanceError, 'recover --yes'):
            self.schedule.run(force=True)
        self.assertEqual(self.deployment.events, before)
        self.assertEqual(self.schedule.load()['points'], [])

    def test_corrupt_latest_point_is_not_silently_skipped_and_never_restored(self):
        self.point()
        second = self.point()
        path = self.repository / second['id']
        (path / 'environment.env').write_text('TAMPERED=1')
        before = list(self.deployment.events)
        with self.assertRaisesRegex(scheduled.ops.MaintenanceError, 'checksum mismatch'):
            self.schedule.select(second['completedAt'])
        self.assertEqual(self.deployment.events, before)
        self.assertEqual(self.deployment.value(), 'before')

    def test_foreign_binding_bad_ids_symlinks_and_naive_time_are_rejected(self):
        with self.assertRaises(scheduled.ops.MaintenanceError):
            scheduled.utc('2026-10-24T12:00:00')
        self.assertEqual(scheduled.utc('2026-10-24T20:00:00+08:00'), scheduled.utc('2026-10-24T12:00:00Z'))
        value = self.schedule.load()
        original = json.loads(json.dumps(value))
        value['binding'] = '0' * 64
        self.schedule.save(value)
        with self.assertRaisesRegex(scheduled.ops.MaintenanceError, 'different deployment'):
            self.schedule.run(force=True)
        self.schedule.save(original)
        self.schedule.path.chmod(0o644)
        with self.assertRaisesRegex(scheduled.ops.MaintenanceError, 'private'):
            self.schedule.load()
        self.schedule.path.chmod(0o600)
        self.schedule.path.unlink()
        real = self.root / 'real-plan.json'
        scheduled.ops.atomic_json(real, original)
        self.schedule.path.symlink_to(real)
        with self.assertRaisesRegex(scheduled.ops.MaintenanceError, 'symbolic'):
            self.schedule.load()


if __name__ == '__main__':
    unittest.main()
