#!/usr/bin/env python3
"""Real enrollment, mTLS evidence, process restart and native quarantine export."""
import os
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
assert os.environ.get('ALINKSEC_SMOKE_ALLOW_FIXTURES') == 'true'
binary = Path(os.environ['ALINKSEC_EVIDENCE_AGENT_BIN']).resolve(strict=True)
output = root / '.tmp/evidence-native'
output.mkdir(parents=True, exist_ok=True, mode=0o700)
test = output / ('agent-evidence-test.exe' if os.name == 'nt' else 'agent-evidence-test')
env = dict(os.environ, GOMAXPROCS='1', GOMEMLIMIT='256MiB')
subprocess.run([os.environ.get('ALINKSEC_NATIVE_GO', 'go'), 'test', '-p=1', '-c', '-o', str(test), './cmd/agent'], cwd=root / 'agent', env=env, check=True, timeout=180)
def restore_owner(directory):
    if os.name != 'nt' and os.geteuid() != 0:
        for name in ('result.json', 'diagnostic.zip', 'observations.json', 'failed-agent-process.log'):
            path = directory / name
            if path.exists():
                subprocess.run(['sudo', '-n', 'chown', f'{os.getuid()}:{os.getgid()}', str(path)], check=True, timeout=15)


for name in ('result.json', 'diagnostic.zip', 'observations.json', 'attempts.json'):
    (output / name).unlink(missing_ok=True)
attempts = []
for number in range(1, 4):
    directory = output / f'attempt-{number}'
    directory.mkdir(exist_ok=True, mode=0o700)
    for name in ('result.json', 'diagnostic.zip', 'observations.json', 'failed-agent-process.log'):
        (directory / name).unlink(missing_ok=True)
    values = {'ALINKSEC_EVIDENCE_AGENT_BIN': str(binary), 'ALINKSEC_EVIDENCE_NATIVE_OUTPUT': str(directory)}
    command = [str(test), '-test.v', '-test.run', '^TestNativeEvidenceAgent$', '-test.timeout', '3m']
    if os.name != 'nt' and os.geteuid() != 0:
        command = ['sudo', '-n', 'env', *(f'{key}={value}' for key, value in values.items()), *command]
    # Each execution creates a fresh enrollment, process and private journal.
    # Stop at the first failure; these are repetitions, never automatic retries.
    try:
        with (directory / 'test.log').open('w', encoding='utf-8') as log:
            result = subprocess.run(command, env=dict(env, **values), stdout=log, stderr=subprocess.STDOUT, timeout=200)
    finally:
        restore_owner(directory)
        with (directory / 'test.log').open(encoding='utf-8', errors='replace') as log:
            sys.stdout.write(log.read(128 << 10))
        sys.stdout.flush()
    result.check_returncode()
    files = {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
             for name in ('result.json', 'diagnostic.zip', 'observations.json', 'test.log')}
    attempts.append({'attempt': number, 'directory': directory.name, 'sha256': files})
for name in ('result.json', 'diagnostic.zip', 'observations.json'):
    shutil.copyfile(directory / name, output / name)
(output / 'attempts.json').write_text(json.dumps({'passed': True, 'freshProcesses': 3, 'attempts': attempts}, indent=2) + '\n')
