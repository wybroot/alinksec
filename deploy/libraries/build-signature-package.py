#!/usr/bin/env python3
"""Package a curated, complete SHA256 export; no network access or dependencies."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
import zipfile


MAX_BYTES = 64 << 20
MAX_HASHES = 250_000


def build_package(input_path, output_path, name="Malware.KnownHash", severity=4,
                  max_hashes=MAX_HASHES):
    input_path, output_path = Path(input_path), Path(output_path)
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,255}", name):
        raise ValueError("name must contain 1..255 ASCII letters, digits, '.', '_' or '-'")
    if not 1 <= severity <= 5 or not 1 <= max_hashes <= MAX_HASHES:
        raise ValueError("severity must be 1..5; max-hashes must be 1..250000")
    if input_path.resolve() == output_path.resolve():
        raise ValueError("input and output must be different files")

    hashes, total = set(), 0
    with input_path.open("rb") as source:
        line_number = 0
        while True:
            line = source.readline(4098)
            if not line:
                break
            line_number += 1
            total += len(line)
            if total > MAX_BYTES or len(line) > 4097:
                raise ValueError("input exceeds the 64 MiB or 4096-character line limit")
            value = line.strip()
            if not value or value.startswith(b"#"):
                continue
            if not re.fullmatch(rb"[A-Fa-f0-9]{64}", value):
                raise ValueError(f"line {line_number}: expected exactly one SHA256")
            hashes.add(value.decode("ascii").lower())
            if len(hashes) > max_hashes:
                raise ValueError("hash count exceeds max-hashes; previous package is preserved")
    if not hashes:
        raise ValueError("refusing an empty export; previous package is preserved")

    if len(hashes) * (68 + len(name)) > MAX_BYTES:
        raise ValueError("decompressed package exceeds 64 MiB")
    payload = "".join(f"{value} {name} {severity}\n" for value in sorted(hashes)).encode("ascii")
    version = "feed-" + hashlib.sha256(payload).hexdigest()[:20]
    manifest = json.dumps({"db_version": version, "hash_count": len(hashes),
                           "rule_count": 0}, separators=(",", ":")).encode("ascii")
    if len(payload) + len(manifest) > MAX_BYTES:
        raise ValueError("decompressed package exceeds 64 MiB")

    temporary_path = None
    try:
        # Same directory keeps replacement atomic on the publisher's filesystem.
        with tempfile.NamedTemporaryFile(dir=output_path.parent, prefix=".signatures-",
                                         suffix=".tmp", delete=False) as temporary:
            temporary_path = Path(temporary.name)
            with zipfile.ZipFile(temporary, "w") as archive:
                for filename, content in (("manifest.json", manifest), ("hashes.txt", payload)):
                    entry = zipfile.ZipInfo(filename, date_time=(1980, 1, 1, 0, 0, 0))
                    entry.compress_type = zipfile.ZIP_DEFLATED
                    entry.external_attr = 0o100644 << 16
                    archive.writestr(entry, content)
            temporary.flush()
            os.fsync(temporary.fileno())
        if temporary_path.stat().st_size > MAX_BYTES:
            raise ValueError("compressed package exceeds 64 MiB")
        digest = file_digest(temporary_path)
        changed = not output_path.exists() or file_digest(output_path) != digest
        if changed:
            mode = output_path.stat().st_mode & 0o777 if output_path.exists() else 0o640
            os.chmod(temporary_path, mode)
            os.replace(temporary_path, output_path)
        return {"db_version": version, "hash_count": len(hashes),
                "sha256": digest, "changed": changed}
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


def file_digest(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(8192), b""):
            digest.update(block)
    return digest.hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, type=Path, help="one SHA256 per line")
    parser.add_argument("--output", required=True, type=Path, help="ZIP in an existing directory")
    parser.add_argument("--name", default="Malware.KnownHash")
    parser.add_argument("--severity", type=int, default=4)
    parser.add_argument("--max-hashes", type=int, default=MAX_HASHES,
                        help="lower this to leave capacity for other ALinkSec sources")
    args = parser.parse_args()
    try:
        result = build_package(args.input, args.output, args.name, args.severity, args.max_hashes)
    except (OSError, ValueError) as error:
        parser.exit(1, f"package rejected: {error}\n")
    print(json.dumps(result, separators=(",", ":")))


if __name__ == "__main__":
    main()
