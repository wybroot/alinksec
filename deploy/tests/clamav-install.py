#!/usr/bin/env python3
"""Extract pinned official ClamAV test tools. Never install a system service."""
import hashlib
import json
import os
import platform
from pathlib import Path
import subprocess
import sys
import urllib.request
import zipfile

VERSION = '1.4.6'
ASSETS = {
    ('Linux', 'x86_64'): ('linux.x86_64.deb', 'd3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2'),
    ('Linux', 'aarch64'): ('linux.aarch64.deb', 'a29cc95aeb225f0dc1b99024b49f1cc109502cb17aaf168637d0901aa9674fe8'),
    ('Windows', 'AMD64'): ('win.x64.zip', '57b6fd1d60cd87bafe800f97407ecdef0576d36b3900b8b7abcfbbabe88295fd'),
}

def main():
    asset, digest = ASSETS[(platform.system(), platform.machine())]
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    name = f'clamav-{VERSION}.{asset}'
    archive = root / name
    url = f'https://github.com/Cisco-Talos/clamav/releases/download/clamav-{VERSION}/{name}'
    if not archive.exists():
        request = urllib.request.Request(url, headers={'User-Agent': 'ALinkSec-native-test'})
        temporary = archive.with_suffix(archive.suffix + '.part')
        with urllib.request.urlopen(request, timeout=60) as response, temporary.open('wb') as out:
            size = 0
            while block := response.read(1 << 20):
                size += len(block)
                if size > 200 << 20:
                    raise RuntimeError('ClamAV archive exceeds test download bound')
                out.write(block)
        temporary.replace(archive)
    sha = hashlib.sha256()
    with archive.open('rb') as src:
        while block := src.read(1 << 20):
            sha.update(block)
    if sha.hexdigest() != digest:
        raise RuntimeError('Official ClamAV artifact SHA256 mismatch')
    extracted = root / 'extracted'
    extracted.mkdir(exist_ok=True)
    if asset.endswith('.zip'):
        with zipfile.ZipFile(archive) as z:
            for item in z.infolist():
                destination = (extracted / item.filename).resolve()
                if not destination.is_relative_to(extracted):
                    raise RuntimeError('Unsafe archive path')
            z.extractall(extracted)
        binaries = list(extracted.rglob('clamd.exe'))
    else:
        subprocess.run(['dpkg-deb', '-x', str(archive), str(extracted)], check=True, timeout=60)
        binaries = list(extracted.rglob('clamd'))
    binaries = [p for p in binaries if p.is_file()]
    if len(binaries) != 1:
        raise RuntimeError('Expected exactly one native clamd binary')
    binary = binaries[0]
    runtime_env = dict(os.environ)
    library_path = None
    if asset.endswith('.deb'):
        libraries = list(extracted.rglob('libclamav.so.*'))
        if not libraries:
            raise RuntimeError('Missing extracted ClamAV runtime library')
        library_path = os.pathsep.join(sorted({str(p.parent) for p in libraries}))
        runtime_env['LD_LIBRARY_PATH'] = library_path
    version_db = root / 'version-database'
    version_db.mkdir(exist_ok=True)
    version_config = root / 'version.conf'
    version_config.write_text(f'DatabaseDirectory {version_db}\n', encoding='utf-8')
    probe = subprocess.run([str(binary), '--config-file=' + str(version_config), '--version'], capture_output=True, text=True, timeout=15, env=runtime_env)
    identity = probe.stdout.strip()
    evidence = {'version': VERSION, 'identity': identity, 'asset': name, 'sha256': digest, 'url': url, 'binary': str(binary), 'system': platform.system(), 'machine': platform.machine(), 'version_exit': probe.returncode, 'version_stderr': probe.stderr[:4096]}
    (root / 'install.json').write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    if probe.returncode != 0 or not identity.startswith('ClamAV ' + VERSION):
        raise RuntimeError(f'Native version probe failed: {probe.returncode}: {identity[:4096]} {probe.stderr[:4096]}')
    if os.getenv('GITHUB_ENV'):
        with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as env:
            env.write(f'ALINKSEC_CLAMAV_TEST_BIN={binary}\nALINKSEC_CLAMAV_TEST_SHA256={digest}\n')
            if library_path is not None:
                env.write(f'LD_LIBRARY_PATH={library_path}\n')
    print(json.dumps(evidence))

if __name__ == '__main__':
    main()
