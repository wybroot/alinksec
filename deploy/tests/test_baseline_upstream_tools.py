import base64
import importlib.util
import json
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("publisher", ROOT / "deploy/baseline/publish-upstream.py")
publisher = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(publisher)


class PublisherTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = pathlib.Path(self.temporary.name)
        self.key, self.out = self.root / "key.pem", self.root / "site"
        subprocess.run(["openssl", "genpkey", "-algorithm", "Ed25519", "-out", str(self.key)], check=True, capture_output=True)
        self.package = self.root / "linux.json"
        self.package.write_bytes((ROOT / "deploy/baseline/packages/linux-baseline.json").read_bytes())

    def publish(self, seq, *extra):
        return subprocess.run(["python3", str(ROOT / "deploy/baseline/publish-upstream.py"), "--source-id", "fixture", "--sequence", str(seq), "--base-url", "https://updates.example.invalid/", "--private-key", str(self.key), "--output", str(self.out), *map(str, extra)], capture_output=True, text=True)

    def test_real_signature_immutable_versions_and_terminal_withdrawal(self):
        result = self.publish(1, "--release", self.package)
        self.assertEqual(0, result.returncode, result.stderr)
        summary = json.loads(result.stdout)
        envelope = json.loads((self.out / "index.json").read_bytes())
        payload = base64.b64decode(envelope["payload"])
        (self.root / "public.der").write_bytes(base64.b64decode(summary["publicKey"]))
        (self.root / "payload").write_bytes(payload)
        (self.root / "signature").write_bytes(base64.b64decode(envelope["signature"]))
        verified = subprocess.run(["openssl", "pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", str(self.root / "public.der"), "-in", str(self.root / "payload"), "-sigfile", str(self.root / "signature")], capture_output=True)
        self.assertEqual(0, verified.returncode)
        item = json.loads(payload)["releases"][0]
        previous = self.root / "previous.json"
        previous.write_bytes((self.out / "index.json").read_bytes())
        identity = f"{item['kind']}/{item['code']}/{item['version']}"
        result = self.publish(2, "--previous", previous, "--withdraw", identity)
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertEqual("withdrawn", json.loads(base64.b64decode(json.loads((self.out / "index.json").read_bytes())["payload"]))["releases"][0]["status"])
        withdrawn = self.root / "withdrawn.json"
        withdrawn.write_bytes((self.out / "index.json").read_bytes())
        self.assertNotEqual(0, self.publish(3, "--previous", withdrawn, "--release", self.package).returncode)
        self.assertNotEqual(0, self.publish(1, "--previous", previous).returncode)
        content = json.loads(self.package.read_bytes()); content["name"] += " changed"
        self.package.write_text(json.dumps(content))
        self.assertNotEqual(0, self.publish(3, "--previous", previous, "--release", self.package).returncode)
        self.assertEqual(withdrawn.read_bytes(), (self.out / "index.json").read_bytes())
        self.assertFalse(any(p.suffix == ".pem" for p in self.out.rglob("*")))

    def test_refuses_remote_http_and_key_inside_published_directory(self):
        with self.assertRaises(ValueError): publisher.address("http://example.invalid/")
        with self.assertRaises(ValueError): publisher.address("https://user:secret@example.invalid/")
        with self.assertRaises(ValueError): publisher.address("https://example.invalid/?token=private")
        self.out.mkdir(); unsafe_key = self.out / "key.pem"; unsafe_key.write_bytes(self.key.read_bytes())
        result = subprocess.run(["python3", str(ROOT / "deploy/baseline/publish-upstream.py"), "--source-id", "fixture", "--sequence", "1", "--base-url", "https://example.invalid/", "--private-key", str(unsafe_key), "--output", str(self.out)], capture_output=True)
        self.assertNotEqual(0, result.returncode)
        self.assertFalse((self.out / "index.json").exists())


if __name__ == "__main__": unittest.main()
