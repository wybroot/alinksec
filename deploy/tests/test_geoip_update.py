import gzip
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True

repo = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('geoip_updater', repo / 'deploy/update-geoip.py')
updater = importlib.util.module_from_spec(spec)
spec.loader.exec_module(updater)
fixture = (repo / 'server/alinksec-service/src/test/resources/geoip/GeoIP2-City-Test.mmdb').read_bytes()


class DatabaseUpdateTest(unittest.TestCase):
    def test_complete_checked_release_replaces_file_and_records_version(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(updater, 'guard'):
            target = Path(directory) / 'geoip.mmdb'
            target.write_bytes(b'previous')
            receipt = updater.install(io.BytesIO(gzip.compress(fixture)), target, hashlib.sha1(fixture).hexdigest(), 'manufacturer-test-fixture', 'test')
            self.assertEqual(target.read_bytes(), fixture)
            self.assertEqual(receipt['bytes'], len(fixture))
            self.assertEqual(receipt['sha256'], hashlib.sha256(fixture).hexdigest())
            self.assertEqual(receipt['checksumFormat'], 'mmdb')
            self.assertTrue(target.with_suffix('.mmdb.json').is_file())

    def test_checksum_and_corrupt_download_failures_preserve_active_database(self):
        for payload, checksum in [(gzip.compress(fixture), '0' * 40), (b'not-gzip', '0' * 40)]:
            with tempfile.TemporaryDirectory() as directory, patch.object(updater, 'guard'):
                target = Path(directory) / 'geoip.mmdb'
                target.write_bytes(b'previous')
                with self.assertRaises(Exception):
                    updater.install(io.BytesIO(payload), target, checksum, 'fixture', 'test')
                self.assertEqual(target.read_bytes(), b'previous')
                self.assertEqual(list(target.parent.glob('*.part')), [])

    def test_resource_stop_preserves_database(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / 'geoip.mmdb'
            target.write_bytes(b'previous')
            with patch.object(updater, 'guard', side_effect=[None, RuntimeError('resource guard')]):
                with self.assertRaisesRegex(RuntimeError, 'resource guard'):
                    updater.install(io.BytesIO(gzip.compress(fixture)), target, hashlib.sha1(fixture).hexdigest(), 'fixture', 'test')
            self.assertEqual(target.read_bytes(), b'previous')
            self.assertEqual(list(target.parent.glob('*.part')), [])


if __name__ == '__main__':
    unittest.main()
