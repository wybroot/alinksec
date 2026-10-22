#!/usr/bin/env python3
"""Capture bounded, public publisher documents for native format interoperability."""
import datetime
import hashlib
import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.request

SAMPLES = {
    "ubuntu-usn": "https://ubuntu.com/security/notices/USN-6727-1.json",
    "debian-tracker": "https://security-tracker.debian.org/tracker/data/json",
    "redhat-csaf": "https://security.access.redhat.com/data/csaf/v2/advisories/2024/rhsa-2024_0001.json",
    "ubuntu-index": "https://ubuntu.com/security/notices.json?limit=1&offset=0",
    "redhat-index": "https://security.access.redhat.com/data/csaf/v2/advisories/changes.csv",
    "msrc-index": "https://api.msrc.microsoft.com/cvrf/v3.0/updates",
    "msrc-cvrf": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2024-Apr",
}

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Publisher sample redirect rejected")

def main():
    root = Path(sys.argv[1])
    root.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(NoRedirect)
    manifest, total = [], 0
    for kind, url in SAMPLES.items():
        target = root / (kind + ".json")
        start, size, digest = time.monotonic(), 0, hashlib.sha256()
        request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "ALinkSec-Native-Format-Validation/1", "Accept-Encoding": "gzip" if kind == "debian-tracker" else "identity"})
        with opener.open(request, timeout=20) as response, target.open("wb") as output:
            assert response.status == 200 and response.geturl() == url
            while block := response.read(65536):
                size += len(block)
                total += len(block)
                if size > ((4 if kind.endswith("-index") else 32) << 20) or total > 64 << 20 or time.monotonic() - start > 45:
                    raise ValueError("Publisher sample response limit")
                digest.update(block)
                output.write(block)
        manifest.append({"format": kind, "url": url, "bytes": size, "sha256": digest.hexdigest(), "contentEncoding": "gzip" if target.read_bytes()[:2] == b"\x1f\x8b" else "identity"})
    (root / "manifest.json").write_text(json.dumps({
        "capturedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scope": "Actual public native publisher bytes; no claim of publisher signature verification or live host patch applicability.",
        "documents": manifest,
    }, indent=2) + "\n")
    print(json.dumps({"documents": len(manifest), "bytes": total, "captured": True}))

if __name__ == "__main__":
    main()
