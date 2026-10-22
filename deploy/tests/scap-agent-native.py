#!/usr/bin/env python3
"""Execute the production Agent worker with actual native OS privileges."""
from pathlib import Path
import os
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
roundtrip='--roundtrip' in sys.argv
test = root/('.tmp/scap-native/agent-roundtrip-test' if roundtrip else '.tmp/scap-native/agent-scap-test')
if os.name == 'nt':
    test = test.with_suffix('.exe')
env = dict(os.environ, GOMAXPROCS='1', GOMEMLIMIT='256MiB')
subprocess.run(['go','test','-c','-o',str(test),'./cmd/agent' if roundtrip else './internal/scap'],cwd=root/'agent',env=env,check=True,timeout=180)
values = dict(ALINKSEC_SCAP_NATIVE_WORKER_REQUIRED='true',
    ALINKSEC_SCAP_TEST_BIN=os.environ['ALINKSEC_SCAP_TEST_BIN'],
    ALINKSEC_SCAP_TEST_RUNTIME_SHA256=os.environ['ALINKSEC_SCAP_TEST_RUNTIME_SHA256'],
    ALINKSEC_SCAP_FIXTURE_ZIP=str(root/'.tmp/scap-native/execution/fixture/content.zip'),
    ALINKSEC_SCAP_NATIVE_EVIDENCE_FILE=str(root/'.tmp/scap-native/agent.json'))
if roundtrip:
    binary=root/('.tmp/scap-native/alinksec-agent.exe' if os.name=='nt' else '.tmp/scap-native/alinksec-agent')
    subprocess.run(['go','build','-trimpath','-o',str(binary),'./cmd/agent'],cwd=root/'agent',env=env,check=True,timeout=180)
    values.update(ALINKSEC_SCAP_AGENT_BIN=str(binary),ALINKSEC_SCAP_AGENT_EVIDENCE_FILE=str(root/'.tmp/scap-native/roundtrip.json'))
command = [str(test),'-test.v','-test.run','^TestNativeSCAPAgent$' if roundtrip else '^TestNativeScapWorker$','-test.timeout','5m']
if os.name != 'nt' and os.geteuid()!=0:
    command = ['sudo','-n','env',*(f'{k}={v}' for k,v in values.items()),*command]
try:
    subprocess.run(command,env=dict(env,**values),check=True,timeout=320)
finally:
    evidence=Path(values['ALINKSEC_SCAP_AGENT_EVIDENCE_FILE'] if roundtrip else values['ALINKSEC_SCAP_NATIVE_EVIDENCE_FILE'])
    if os.name!='nt' and os.geteuid()!=0 and evidence.exists():
        subprocess.run(['sudo','-n','chown',f'{os.getuid()}:{os.getgid()}',str(evidence)],check=True,timeout=15)
