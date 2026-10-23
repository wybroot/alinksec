#!/usr/bin/env python3
"""Real enrollment, mTLS evidence, process restart and native quarantine export."""
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
assert os.environ.get('ALINKSEC_SMOKE_ALLOW_FIXTURES') == 'true'
binary = Path(os.environ['ALINKSEC_EVIDENCE_AGENT_BIN']).resolve(strict=True)
output = root / '.tmp/evidence-native'
output.mkdir(parents=True, exist_ok=True, mode=0o700)
test = output / ('agent-evidence-test.exe' if os.name == 'nt' else 'agent-evidence-test')
env = dict(os.environ, GOMAXPROCS='1', GOMEMLIMIT='256MiB')
subprocess.run([os.environ.get('ALINKSEC_NATIVE_GO', 'go'), 'test', '-p=1', '-c', '-o', str(test), './cmd/agent'], cwd=root / 'agent', env=env, check=True, timeout=180)
values = {'ALINKSEC_EVIDENCE_AGENT_BIN': str(binary), 'ALINKSEC_EVIDENCE_NATIVE_OUTPUT': str(output)}
command = [str(test), '-test.v', '-test.run', '^TestNativeEvidenceAgent$', '-test.timeout', '3m']
if os.name != 'nt' and os.geteuid() != 0:
    command = ['sudo', '-n', 'env', *(f'{key}={value}' for key, value in values.items()), *command]
try:
    subprocess.run(command, env=dict(env, **values), check=True, timeout=200)
finally:
    if os.name != 'nt' and os.geteuid() != 0:
        for name in ('result.json', 'diagnostic.zip'):
            path = output / name
            if path.exists():
                subprocess.run(['sudo', '-n', 'chown', f'{os.getuid()}:{os.getgid()}', str(path)], check=True, timeout=15)
