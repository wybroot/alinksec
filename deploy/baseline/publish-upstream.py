#!/usr/bin/env python3
"""Build a static Ed25519 signed baseline index; never uploads or deploys it.

The signing key stays outside the output directory. OpenSSL 3+ is required.
Consumer-side package validation/review remains mandatory.
"""
import argparse
import base64
import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess
import tempfile
import urllib.parse
import zipfile

MAX_PACKAGE = 2 * 1024 * 1024
MAX_INDEX = 384 * 1024
IDENTITY = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,255}\Z")


def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def read_json(raw):
    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                      parse_constant=lambda _: (_ for _ in ()).throw(ValueError("invalid number")))


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def openssl(*args):
    return subprocess.run(["openssl", *map(str, args)], check=True, capture_output=True, timeout=15).stdout


def address(value):
    uri = urllib.parse.urlsplit(value)
    loopback = uri.scheme == "http" and uri.hostname in ("localhost", "127.0.0.1", "::1")
    if (uri.scheme != "https" and not loopback) or not uri.hostname or uri.username is not None or uri.password is not None or uri.query or uri.fragment:
        raise ValueError("base URL must be HTTPS without credentials, query or fragment")
    return value.rstrip("/") + "/"


def package(path, base_url, output):
    if path.stat().st_size > MAX_PACKAGE:
        raise ValueError("package exceeds 2 MiB")
    raw = path.read_bytes()
    kind = "scap" if path.suffix.lower() == ".zip" else "baseline"
    if kind == "scap":
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 128 or sum(e.file_size for e in entries) > 32 * 1024 * 1024:
                raise ValueError("SCAP archive exceeds bounds")
            manifests = [e for e in entries if e.filename == "alinksec-scap.json"]
            if len(manifests) != 1 or manifests[0].file_size > 16384:
                raise ValueError("missing bounded unique SCAP manifest")
            document = read_json(archive.read(manifests[0]))
    else:
        document = read_json(raw)
    code, version, os_type = document["code"], document["version"], document["osType"]
    if not isinstance(code, str) or not isinstance(version, str) or not IDENTITY.fullmatch(code) or not IDENTITY.fullmatch(version) or type(os_type) is not int or os_type not in (1, 2):
        raise ValueError("invalid package identity")
    digest = hashlib.sha256(raw).hexdigest()
    relative = f"artifacts/{digest}.{'zip' if kind == 'scap' else 'json'}"
    target = output / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and target.read_bytes() != raw:
        raise ValueError("existing content-addressed artifact differs")
    if not target.exists():
        target.write_bytes(raw)
    return dict(kind=kind, code=code, version=version, osType=os_type,
                url=base_url + relative, sha256=digest, size=len(raw), status="active")


def previous(path, public_key, temporary):
    if path.stat().st_size > MAX_INDEX:
        raise ValueError("previous index exceeds bounds")
    envelope = read_json(path.read_bytes())
    if set(envelope) != {"formatVersion", "payload", "signature"} or type(envelope["formatVersion"]) is not int or envelope["formatVersion"] != 1:
        raise ValueError("invalid previous envelope")
    payload = base64.b64decode(envelope["payload"], validate=True)
    signature = base64.b64decode(envelope["signature"], validate=True)
    (temporary / "previous.json").write_bytes(payload)
    (temporary / "previous.sig").write_bytes(signature)
    openssl("pkeyutl", "-verify", "-rawin", "-pubin", "-keyform", "DER", "-inkey", public_key,
            "-in", temporary / "previous.json", "-sigfile", temporary / "previous.sig")
    document = read_json(payload)
    if set(document) != {"sourceId", "sequence", "generatedAt", "expiresAt", "releases"} or not isinstance(document["releases"], list):
        raise ValueError("invalid previous payload")
    return document


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-id", required=True)
    parser.add_argument("--sequence", required=True, type=int)
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--private-key", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--release", action="append", default=[], type=pathlib.Path)
    parser.add_argument("--previous", type=pathlib.Path)
    parser.add_argument("--withdraw", action="append", default=[], help="kind/code/version")
    parser.add_argument("--expires-days", type=int, default=7)
    args = parser.parse_args(argv)
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}", args.source_id) or not 0 < args.sequence <= 9223372036854775807 or not 1 <= args.expires_days <= 30:
        parser.error("invalid source ID, sequence or expiry")
    base_url = address(args.base_url)
    output = args.output.resolve()
    if args.private_key.resolve().is_relative_to(output):
        parser.error("signing key must stay outside the published directory")
    output.mkdir(parents=True, exist_ok=True)
    # Temporary files contain payloads and public material only; OpenSSL reads the external key.
    with tempfile.TemporaryDirectory(prefix="alinksec-publisher-") as name:
        temporary = pathlib.Path(name)
        public = openssl("pkey", "-in", args.private_key, "-pubout", "-outform", "DER")
        if len(public) != 44 or public[:12].hex() != "302a300506032b6570032100":
            raise ValueError("signing key must be Ed25519")
        public_path = temporary / "public.der"
        public_path.write_bytes(public)
        releases = {}
        if args.previous:
            old = previous(args.previous, public_path, temporary)
            if old["sourceId"] != args.source_id or type(old["sequence"]) is not int or old["sequence"] >= args.sequence:
                raise ValueError("source identity or monotonic sequence mismatch")
            for item in old["releases"]:
                key = (item["kind"], item["code"], item["version"])
                if key in releases or not item["url"].startswith(base_url):
                    raise ValueError("previous index has duplicate identity or a different base URL")
                releases[key] = item
        for path in args.release:
            item = package(path, base_url, output)
            key = (item["kind"], item["code"], item["version"])
            if key in releases and releases[key] != item:
                raise ValueError("release identity is immutable; use a new version")
            releases[key] = item
        for identity in args.withdraw:
            key = tuple(identity.split("/"))
            if key not in releases:
                raise ValueError("withdrawal must refer to an existing release")
            releases[key] = {**releases[key], "status": "withdrawn"}
        if len(releases) > 64:
            raise ValueError("index supports at most 64 releases")
        now = dt.datetime.now(dt.timezone.utc).replace(microsecond=0)
        payload = encoded(dict(sourceId=args.source_id, sequence=args.sequence,
                               generatedAt=now.isoformat().replace("+00:00", "Z"),
                               expiresAt=(now + dt.timedelta(days=args.expires_days)).isoformat().replace("+00:00", "Z"),
                               releases=[releases[k] for k in sorted(releases)]))
        if len(payload) > 256 * 1024:
            raise ValueError("payload exceeds bounds")
        message = temporary / "payload.json"
        message.write_bytes(payload)
        signature = openssl("pkeyutl", "-sign", "-rawin", "-inkey", args.private_key, "-in", message)
        envelope = encoded(dict(formatVersion=1, payload=base64.b64encode(payload).decode("ascii"),
                                signature=base64.b64encode(signature).decode("ascii"))) + b"\n"
        staged = output / ".index.pending"
        staged.write_bytes(envelope)
        staged.replace(output / "index.json")
        print(json.dumps(dict(sourceId=args.source_id, sequence=args.sequence, releases=len(releases),
                              publicKey=base64.b64encode(public).decode("ascii"),
                              keySha256=hashlib.sha256(public).hexdigest(),
                              payloadSha256=hashlib.sha256(payload).hexdigest())))


if __name__ == "__main__":
    main()
