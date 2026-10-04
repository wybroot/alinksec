"""Portable tests for the documented MISP export -> ALinkSec package workflow."""

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch
import zipfile


ROOT = Path(__file__).resolve().parents[2]
FEEDS = ROOT / "deploy" / "libraries"
SPEC = importlib.util.spec_from_file_location("feed_package", FEEDS / "build-signature-package.py")
PACKAGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(PACKAGE)
HASH_A = "a" * 64
HASH_B = "b" * 64


class FeedPackageTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.source = self.root / "sha256.txt"
        self.output = self.root / "signatures.zip"

    def build(self, text, **options):
        self.source.write_text(text, encoding="utf-8")
        return PACKAGE.build_package(self.source, self.output, **options)

    def test_complete_zip_normalizes_deduplicates_and_declares_counts(self):
        result = self.build(f"# audited export\n{HASH_B.upper()}\r\n{HASH_A}\n{HASH_B}\n\n",
                            name="MISP.KnownHash", severity=5)
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(set(archive.namelist()), {"manifest.json", "hashes.txt"})
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(manifest, {"db_version": result["db_version"],
                                        "hash_count": 2, "rule_count": 0})
            self.assertRegex(manifest["db_version"], r"^[A-Za-z0-9._-]{1,32}$")
            self.assertEqual(archive.read("hashes.txt").decode(),
                             f"{HASH_A} MISP.KnownHash 5\n{HASH_B} MISP.KnownHash 5\n")
        self.assertEqual(result["sha256"], PACKAGE.file_digest(self.output))
        self.assertTrue(result["changed"])

    def test_identical_content_keeps_published_file_and_mtime(self):
        initial = self.build(f"{HASH_A}\n{HASH_B}\n")
        before = self.output.stat()
        repeated = self.build(f"{HASH_B.upper()}\n{HASH_A}\n{HASH_A}\n")
        self.assertEqual(repeated["db_version"], initial["db_version"])
        self.assertFalse(repeated["changed"])
        self.assertEqual(self.output.stat().st_mtime_ns, before.st_mtime_ns)
        self.assertEqual(self.output.stat().st_ino, before.st_ino)

    def test_nonempty_snapshot_removes_withdrawn_hash(self):
        initial = self.build(f"{HASH_A}\n{HASH_B}\n")
        updated = self.build(f"{HASH_B}\n")
        self.assertNotEqual(initial["db_version"], updated["db_version"])
        with zipfile.ZipFile(self.output) as archive:
            self.assertEqual(archive.read("hashes.txt").decode(), f"{HASH_B} Malware.KnownHash 4\n")

    def test_empty_invalid_and_partial_error_responses_preserve_previous_zip(self):
        self.build(f"{HASH_A}\n")
        before = self.output.read_bytes()
        for invalid in ("", "\n# no results\n", "<html>login required</html>\n",
                        f"{HASH_B}\n{{\"error\":\"incomplete response\"}}\n",
                        "a" * 63, f"{HASH_A} ExtraField\n", "a" * 4097):
            with self.subTest(invalid=invalid[:30]):
                with self.assertRaises(ValueError):
                    self.build(invalid)
                self.assertEqual(self.output.read_bytes(), before)
                self.assertEqual(list(self.root.glob(".signatures-*.tmp")), [])

    def test_limits_and_bad_options_preserve_previous_zip(self):
        self.build(f"{HASH_A}\n")
        before = self.output.read_bytes()
        for options in ({"max_hashes": 1}, {"max_hashes": 250001},
                        {"severity": 0}, {"severity": 6}, {"name": "bad name"}):
            with self.subTest(options=options):
                with self.assertRaises(ValueError):
                    self.build(f"{HASH_A}\n{HASH_B}\n", **options)
                self.assertEqual(self.output.read_bytes(), before)
        with patch.object(PACKAGE, "MAX_BYTES", 65):
            with self.assertRaises(ValueError):
                self.build(f"{HASH_A}\n{HASH_B}\n")
        with patch.object(PACKAGE, "MAX_BYTES", 70):
            with self.assertRaises(ValueError):
                self.build(f"{HASH_A}\n")
        self.assertEqual(self.output.read_bytes(), before)

    def test_atomic_replacement_failure_cleans_temporary_and_preserves_previous(self):
        self.build(f"{HASH_A}\n")
        before = self.output.read_bytes()
        with patch.object(PACKAGE.os, "replace", side_effect=OSError("publisher disk error")):
            with self.assertRaises(OSError):
                self.build(f"{HASH_B}\n")
        self.assertEqual(self.output.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".signatures-*.tmp")), [])

    def test_same_input_output_is_rejected_without_truncation(self):
        self.source.write_text(HASH_A + "\n")
        with self.assertRaises(ValueError):
            PACKAGE.build_package(self.source, self.source)
        self.assertEqual(self.source.read_text(), HASH_A + "\n")

    @unittest.skipUnless(os.name == "posix", "Unix publisher permissions")
    def test_replacement_preserves_publisher_permissions(self):
        self.build(HASH_A + "\n")
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o640)
        self.output.chmod(0o600)
        self.build(HASH_B + "\n")
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    @unittest.skipUnless(shutil.which("bash") and shutil.which("flock"), "Linux refresh tools")
    def test_refresh_runs_with_query_and_preserves_zip_on_transport_or_bad_response(self):
        binaries = self.root / "bin"
        binaries.mkdir()
        fake_curl = binaries / "curl"
        fake_curl.write_text('''#!/usr/bin/env python3
import json, os, pathlib, sys
args = sys.argv[1:]
pathlib.Path(os.environ["FEED_TEST_ARGS"]).write_text(json.dumps(args))
if os.environ.get("FEED_TEST_FAIL") == "1":
    sys.exit(22)
pathlib.Path(args[args.index("--output") + 1]).write_bytes(
    pathlib.Path(os.environ["FEED_TEST_BODY"]).read_bytes())
''')
        fake_curl.chmod(0o755)
        config = self.root / "protected.curl.conf"
        config.write_text('url = "https://misp.example.invalid/attributes/restSearch"\n')
        self.source.write_text(HASH_A + "\n")
        arg_file = self.root / "curl-args.json"
        env = dict(os.environ, PATH=str(binaries) + os.pathsep + os.environ.get("PATH", ""),
                   FEED_TEST_ARGS=str(arg_file), FEED_TEST_BODY=str(self.source))
        command = ["bash", str(FEEDS / "refresh-misp.sh"), str(config),
                   str(FEEDS / "misp-query.example.json"), str(self.output)]
        result = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["hash_count"], 1)
        args = json.loads(arg_file.read_text())
        self.assertIn("--fail", args)
        self.assertIn("--max-filesize", args)
        self.assertEqual(args[args.index("--proto") + 1], "=https")
        self.assertEqual(args[args.index("--data-binary") + 1],
                         "@" + str(FEEDS / "misp-query.example.json"))
        query = json.loads((FEEDS / "misp-query.example.json").read_text())
        self.assertEqual(query["type"], "sha256")
        self.assertEqual(query["returnFormat"], "text")
        self.assertNotIn("last", query)
        self.assertNotIn("limit", query)
        before = self.output.read_bytes()
        failed = subprocess.run(command, env=dict(env, FEED_TEST_FAIL="1"),
                                capture_output=True, text=True, timeout=10)
        self.assertNotEqual(failed.returncode, 0)
        self.assertEqual(self.output.read_bytes(), before)
        self.source.write_text("<html>upstream error</html>")
        invalid = subprocess.run(command, env=env, capture_output=True, text=True, timeout=10)
        self.assertNotEqual(invalid.returncode, 0)
        self.assertEqual(self.output.read_bytes(), before)
        self.assertEqual(list(self.root.glob(".misp-export.*")), [])


if __name__ == "__main__":
    unittest.main()
