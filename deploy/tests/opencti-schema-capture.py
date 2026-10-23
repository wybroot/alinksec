#!/usr/bin/env python3
"""Capture immutable official upstream SDL; verify both Git blob identity and SHA-256."""
import hashlib
import json
from pathlib import Path
import sys
import urllib.request

target = Path(sys.argv[1] if len(sys.argv) > 1 else ".tmp/opencti-contract")
manifest = json.loads(Path(__file__).with_name("opencti-contract").joinpath("upstream.json").read_text())
target.mkdir(parents=True, exist_ok=True)
for entry in manifest["files"]:
    request = urllib.request.Request(entry["url"], headers={"User-Agent": "ALinkSec-OpenCTI-contract/1"})
    with urllib.request.urlopen(request, timeout=30) as response:
        assert response.status == 200
        raw = response.read(2 * 1024 * 1024 + 1)
    assert len(raw) == entry["bytes"], entry["path"]
    assert hashlib.sha256(raw).hexdigest() == entry["sha256"], entry["path"]
    assert hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest() == entry["blob"], entry["path"]
    target.joinpath(Path(entry["path"]).name).write_bytes(raw)
target.joinpath("upstream.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(json.dumps({"commit": manifest["commit"], "verifiedOfficialFiles": len(manifest["files"])}))
