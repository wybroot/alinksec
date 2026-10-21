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

VERSION = '5.15'
# Official publisher checksums, reviewed 2026-10-22:
# https://dl.dod.cyber.mil/wp-content/uploads/stigs/txt/SCC_5.15_Checksums.txt
ASSETS = {
    ('Linux', 'x86_64'): ('linux_x86_64',
        'f3fac797a54efe8fb8bba8604b984a73302a98a4900befda17be85c6ef7fcee4',
        'scc-5.15_linux_x86_64.tar.gz', '5f9ef606106f743a093e71682cb1b999594644d724240869b44480032f0e6deb',
        'ba908a907b8cbef7a3c7b1d2cad65c1c255e6290ef2ac3dd8a98ba2163afce8d'),
    ('Linux', 'aarch64'): ('linux_aarch64',
        '2e1f75e909033ef7dded0a58985807bf1c09cd44dc3600bf31339f34fd4c5162',
        'scc-5.15_linux_aarch64.tar.gz', 'b3a5be3cc9b720606fb0362491e6fdf55a5aaa02898744c70ad043173ac641dd',
        'bdd792b9e16f0328565b636a2c343fa6686aa8bc521e736d2887641e80feb998'),
    ('Windows', 'AMD64'): ('Windows',
        'a537a0f9a39ccc2231818709f8bb5f8f9b9cbfc2ec0d44dbbfabbe35d4f558ba',
        'scc-5.15_Windows.zip', 'e830910d9eb43f55a4b11317b1801eaf08cda69073e8d3263e49d5e0d130b044',
        '333b209c457a5b4778292378773bc4adec0fcfb0c2ba3bfaa29432758e2d5b7b'),
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
    url = f'https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/{name}'
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
    # The manifest pins every runtime byte, including modules and schemas, not
    # just the launcher. Bundled benchmarks are excluded from task workspaces.
    runtime = binary.parent
    files = []
    total = 0
    for path in sorted(runtime.rglob('*')):
        relative = path.relative_to(runtime).as_posix()
        if relative.startswith('Resources/Content/') or relative in ['Resources/Content','alinksec-runtime.json']:
            continue
        if path.is_symlink():
            raise RuntimeError('Native runtime contains a symbolic link')
        if not path.is_file():
            continue
        size = path.stat().st_size
        total += size
        if size > 128 << 20 or total > 512 << 20 or len(files) >= 4096:
            raise RuntimeError('Native runtime exceeds packaging limits')
        files.append(dict(path=relative, size=size, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                          executable=bool(path.stat().st_mode & 0o111)))
    machine = {'x86_64':'amd64','aarch64':'arm64','AMD64':'amd64'}[platform.machine()]
    manifest = dict(schemaVersion=1, engine='SCC', version=VERSION,
                    platform=platform.system().lower()+'-'+machine,
                    executable=binary.name, files=files)
    manifest_bytes = (json.dumps(manifest, ensure_ascii=True, separators=(',',':'))+'\n').encode('utf-8')
    (runtime/'alinksec-runtime.json').write_bytes(manifest_bytes)
    runtime_digest = hashlib.sha256(manifest_bytes).hexdigest()
    # Running help/version uses the complete native runtime; it does not scan.
    command = [str(binary), '--version']
    if platform.system() == 'Linux' and os.geteuid() != 0 and os.getenv('GITHUB_ACTIONS') == 'true':
        command = ['sudo', '-n', *command]
    probe = subprocess.run(command, capture_output=True, text=True, timeout=45, cwd=binary.parent)
    evidence = {'version': VERSION, 'asset': name, 'sha256': digest, 'innerSha256': inner_digest,
                'binarySha256': binary_digest, 'binary': str(binary), 'url': url,
                'runtimeManifestSha256': runtime_digest, 'runtimeFiles': len(files), 'runtimeBytes': total,
                'system': platform.system(), 'machine': platform.machine(),
                'versionExit': probe.returncode, 'versionOutput': probe.stdout[:4096], 'versionError': probe.stderr[:4096]}
    (root/'install.json').write_text(json.dumps(evidence, indent=2)+'\n', encoding='utf-8')
    if probe.returncode or VERSION not in probe.stdout + probe.stderr:
        raise RuntimeError('Native SCC version check failed: '+str(evidence))
    if os.getenv('GITHUB_ENV'):
        with open(os.environ['GITHUB_ENV'], 'a', encoding='utf-8') as env:
            env.write(f'ALINKSEC_SCAP_TEST_BIN={binary}\nALINKSEC_SCAP_TEST_RUNTIME_SHA256={runtime_digest}\n')
    print(json.dumps(evidence))

if __name__ == '__main__':
    main()
