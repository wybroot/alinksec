#!/usr/bin/env python3
"""Install a complete DB-IP City Lite release without buffering it in memory.

Use the checksum published at https://db-ip.com/db/download/ip-to-city-lite.
The publisher may checksum the MMDB or gzip; the receipt identifies which matched.
After installation, POST /api/system/geoip/reload as an administrator.
"""
import argparse
import datetime
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import tempfile
import time
import urllib.request


def guard(destination):
    if shutil.disk_usage(destination.parent).free < 2 * 1024**3:
        raise RuntimeError('disk reserve below 2 GiB')
    if Path('/proc/meminfo').exists():
        available = int(re.search(r'MemAvailable:\s+(\d+)', Path('/proc/meminfo').read_text())[1])
        pressure = float(re.search(r'full avg10=([\d.]+)', Path('/proc/pressure/memory').read_text())[1])
        if available < 512 * 1024 or pressure > 5:
            raise RuntimeError('memory pressure guard stopped the download')


class DigestStream:
    def __init__(self, source):
        self.source, self.sha1, self.length = source, hashlib.sha1(), 0

    def read(self, size=-1):
        # GzipFile requests bounded reads; never accept an unbounded input request.
        value = self.source.read(min(65536, size) if size >= 0 else 65536)
        self.length += len(value)
        if self.length > 256 * 1024**2:
            raise RuntimeError('compressed database exceeds 256 MiB')
        self.sha1.update(value)
        return value


def install(source, destination, expected_sha1, source_url, release):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    guard(destination)
    descriptor, name = tempfile.mkstemp(prefix='.geoip-', suffix='.part', dir=destination.parent)
    candidate = Path(name)
    decoded_sha1, sha256 = hashlib.sha1(), hashlib.sha256()
    stream, length, tail, started = DigestStream(source), 0, b'', time.monotonic()
    try:
        with os.fdopen(descriptor, 'wb') as output, gzip.GzipFile(fileobj=stream) as decoded:
            while True:
                guard(destination)
                if time.monotonic() - started > 600:
                    raise RuntimeError('database download deadline exceeded')
                chunk = decoded.read(65536)
                if not chunk:
                    break
                length += len(chunk)
                if length > 1024**3:
                    raise RuntimeError('database exceeds 1 GiB')
                output.write(chunk)
                decoded_sha1.update(chunk)
                sha256.update(chunk)
                tail = (tail + chunk)[-131072:]
            output.flush()
            os.fsync(output.fileno())
        if expected_sha1 not in (decoded_sha1.hexdigest(), stream.sha1.hexdigest()):
            raise RuntimeError('publisher checksum mismatch; active database preserved')
        if b'\xab\xcd\xefMaxMind.com' not in tail:
            raise RuntimeError('MMDB metadata marker missing; active database preserved')
        guard(destination)
        os.chmod(candidate, 0o644)
        # Operators retain their prior release at a separate versioned path when rollback is needed.
        os.replace(candidate, destination)
        receipt = {'source': source_url, 'release': release, 'license': 'CC BY 4.0',
                   'attribution': 'https://db-ip.com', 'bytes': length, 'compressedBytes': stream.length,
                   'sha256': sha256.hexdigest(), 'publisherSha1': expected_sha1,
                   'checksumFormat': 'mmdb' if expected_sha1 == decoded_sha1.hexdigest() else 'gzip',
                   'installedAt': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        receipt_file = destination.with_suffix(destination.suffix + '.json')
        receipt_file.write_text(json.dumps(receipt, indent=2) + '\n')
        return receipt
    finally:
        candidate.unlink(missing_ok=True)


def main():
    def interrupted(signum, frame):
        raise InterruptedError('resource watchdog interrupted the download')
    signal.signal(signal.SIGTERM, interrupted)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--month', required=True, help='YYYY-MM from the manufacturer download page')
    parser.add_argument('--sha1', required=True, help='Publisher SHA1SUM from the manufacturer page')
    parser.add_argument('--destination', default='./data/geoip.mmdb')
    args = parser.parse_args()
    if not re.fullmatch(r'20\d{2}-(0[1-9]|1[0-2])', args.month) or not re.fullmatch(r'[0-9a-f]{40}', args.sha1):
        parser.error('invalid month or SHA1 checksum')
    url = f'https://download.db-ip.com/free/dbip-city-lite-{args.month}.mmdb.gz'
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *unused):
            raise RuntimeError('manufacturer download redirected')
    opener = urllib.request.build_opener(NoRedirect)
    request = urllib.request.Request(url, headers={'User-Agent': 'ALinkSec-GeoIP-Updater/0.0.4'})
    with opener.open(request, timeout=20) as response:
        print(json.dumps(install(response, args.destination, args.sha1, url, args.month)), flush=True)


if __name__ == '__main__':
    main()
