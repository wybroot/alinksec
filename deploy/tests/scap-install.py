#!/usr/bin/env python3
"""Extract the pinned official SCC distribution without a system installation.

SCC is developed by NIWC Atlantic. Preserve Documentation and its license
notices when distributing a runtime. No bundled benchmark is enabled here.
"""
import hashlib
import io
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

VERSION = '5.12'
COMMIT = '023bf76037a003b58f52b165bcfdb7a3b4f8108d'
ASSETS = {
    ('Linux', 'x86_64'): ('ubuntu22_amd64',
        '9bd935b92633f350b315b815b2e334aadda49abacaf4d2a1c80ac72fc6a4710f',
        'scc-5.12_ubuntu22_amd64.tar.gz', 'e27ab5d1501be25cc5fa832baf38c5763660bdb762c52c7bf4853b406dd3c1c0',
        'f9af0e837d0298fd6ae7bbd57fd237bbc43bfb7b78ada497991eb280b277b84e'),
    ('Linux', 'aarch64'): ('ubuntu22_arm64',
        'c82d4054e6409e3e4e03889895143fdee71afbddfd4005cac2ee5438b135df8b',
        'scc-5.12_ubuntu22_arm64.tar.gz', '1fe20521219ab7a3278f669009f81a557178807a97c0d6824e89281cfab68be5',
        '6931fa878f7632445247c818b4bfa0b79e750ad8ff8af4e60cb1d5f7ef2917c5'),
    ('Windows', 'AMD64'): ('Windows',
        '87f62f5e45be024af3a3ffb38045e7f70c87c32a92a321e9859a6a6e2fd9b5bf',
        'scc-5.12_Windows.zip', 'a210d00818fab2a0f23aef0a99202c7e3a28a130f09333753cc94c5523e4a256',
        'b8170ad0fbb137d521d523527a9f75836f02e8d4a5cc95172a1d1bbaa4b0d7b7'),
}

def checked(data, expected):
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError('Official SCC SHA256 mismatch')
    return data

def main():
    asset, digest, inner_name, inner_digest, binary_digest = ASSETS[(platform.system(), platform.machine())]
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=True)
    name = f'scc-{VERSION}_{asset}_bundle.zip'
    archive = root/name
    url = f'https://media.githubusercontent.com/media/niwc-atlantic/scap-scc/{COMMIT}/release_archive/SCC_5.12/{name}'
    if not archive.exists():
        temporary = archive.with_suffix('.part')
        with urllib.request.urlopen(url, timeout=120) as response, temporary.open('wb') as out:
            size = 0
            while block := response.read(1 << 20):
                size += len(block)
                if size > 128 << 20:
                    raise RuntimeError('SCC download exceeds 128 MiB')
                out.write(block)
        temporary.replace(archive)
    bundle = checked(archive.read_bytes(), digest)
    with zipfile.ZipFile(io.BytesIO(bundle)) as z:
        entries = [e for e in z.infolist() if Path(e.filename).name == inner_name]
        if len(entries) != 1 or entries[0].file_size > 128 << 20:
            raise RuntimeError('Missing bounded native SCC runtime')
        inner = checked(z.read(entries[0]), inner_digest)
    extracted = root/'extracted'
    extracted.mkdir(exist_ok=True)
    if inner_name.endswith('.zip'):
        with zipfile.ZipFile(io.BytesIO(inner)) as z:
            for item in z.infolist():
                if not (extracted/item.filename).resolve().is_relative_to(extracted):
                    raise RuntimeError('Unsafe native SCC archive path')
            z.extractall(extracted)
        binaries = list(extracted.rglob('cscc.exe'))
    else:
        with tarfile.open(fileobj=io.BytesIO(inner), mode='r:gz') as t:
            t.extractall(extracted, filter='data')
        binaries = list(extracted.rglob('cscc'))
    if len(binaries) != 1:
        raise RuntimeError('Expected exactly one SCC CLI')
    binary = binaries[0]
    checked(binary.read_bytes(), binary_digest)
    # Running help/version uses the complete native runtime; it does not scan.
    probe = subprocess.run([str(binary), '--version'], capture_output=True, text=True, timeout=45, cwd=binary.parent)
    evidence = {'version': VERSION, 'asset': name, 'sha256': digest, 'innerSha256': inner_digest,
                'binarySha256': binary_digest, 'binary': str(binary), 'url': url,
                'system': platform.system(), 'machine': platform.machine(),
                'versionExit': probe.returncode, 'versionOutput': probe.stdout[:4096], 'versionError': probe.stderr[:4096]}
    (root/'install.json').write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf-8')
    if probe.returncode or VERSION not in probe.stdout + probe.stderr:
        raise RuntimeError('Native SCC version check failed: '+str(evidence))
    if os.getenv('GITHUB_ENV'):
        with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as env:
            env.write(f'ALINKSEC_SCAP_TEST_BIN={binary}\n')
    print(json.dumps(evidence))

if __name__ == '__main__':
    main()
