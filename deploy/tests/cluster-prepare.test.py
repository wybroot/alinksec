#!/usr/bin/env python3
"""Check the storage transition before any cluster process is started."""
import importlib.util
import os
from pathlib import Path
import stat
import tempfile
import unittest
import uuid
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('cluster_prepare', Path(__file__).resolve().parents[1] / 'cluster/prepare-shared.py')
prepare_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(prepare_module)

class SharedPreparationTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'shared'
        self.root.mkdir()
        for directory in ['certs', 'web-tls']:
            (self.root / directory).mkdir()
        for name in ['ca.crt', 'ca.key', 'server.crt', 'server.key']:
            (self.root / 'certs' / name).write_text('fixture-' + name)
        for name in ['server.crt', 'server.key']:
            (self.root / 'web-tls' / name).write_text('fixture-' + name)
        (self.root / 'jwt.secret').write_text('x' * 48)
        self.deployment = str(uuid.uuid4())
        environment = patch.dict(os.environ, {'ALINKSEC_JWT_SECRET': ''})
        environment.start(); self.addCleanup(environment.stop)

    def test_explicit_transition_binds_existing_material_and_never_overwrites_identity(self):
        result = prepare_module.prepare(self.root, self.deployment)
        self.assertTrue(result['prepared'])
        self.assertEqual((self.root / '.cluster-deployment-id').read_text(), self.deployment + '\n')
        for name in ['certs/ca.key', 'certs/server.key', 'web-tls/server.key', 'jwt.secret', '.cluster-deployment-id']:
            self.assertEqual(stat.S_IMODE((self.root / name).stat().st_mode), 0o600)
        with self.assertRaisesRegex(ValueError, 'already exists'):
            prepare_module.prepare(self.root, str(uuid.uuid4()))
        self.assertEqual((self.root / '.cluster-deployment-id').read_text(), self.deployment + '\n')

    def test_missing_pki_and_mismatched_web_tls_do_not_publish_marker(self):
        (self.root / 'web-tls/server.key').write_text('different')
        with self.assertRaisesRegex(ValueError, 'differs'):
            prepare_module.prepare(self.root, self.deployment)
        (self.root / 'certs/ca.crt').unlink()
        with self.assertRaisesRegex(ValueError, 'PKI'):
            prepare_module.prepare(self.root, self.deployment)
        self.assertFalse((self.root / '.cluster-deployment-id').exists())

    def test_external_storage_and_jwt_symlinks_are_rejected_before_publication(self):
        outside = Path(self.temporary.name) / 'outside'
        outside.mkdir()
        (self.root / 'libraries').symlink_to(outside, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'Storage path'):
            prepare_module.prepare(self.root, self.deployment)
        self.assertEqual(list(outside.iterdir()), [])
        (self.root / 'libraries').unlink()
        (self.root / 'jwt.secret').unlink()
        secret = outside / 'jwt.secret'; secret.write_text('y' * 48); secret.chmod(0o644)
        (self.root / 'jwt.secret').symlink_to(secret)
        with patch.dict(os.environ, {'ALINKSEC_JWT_SECRET': 'z' * 48}):
            with self.assertRaisesRegex(ValueError, 'JWT'):
                prepare_module.prepare(self.root, self.deployment)
        self.assertEqual(stat.S_IMODE(secret.stat().st_mode), 0o644)
        self.assertFalse((self.root / '.cluster-deployment-id').exists())

if __name__ == '__main__':
    unittest.main()
