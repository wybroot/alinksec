#!/usr/bin/env python3
"""Execute the production Agent worker with actual native OS privileges."""
from pathlib import Path
import os
import subprocess

root = Path(__file__).resolve().parents[2]
test = root/'.tmp/scap-native/agent-scap-test'
if os.name == 'nt':
    test = test.with_suffix('.exe')
env = dict(os.environ, GOMAXPROCS='1', GOMEMLIMIT='256MiB')
subprocess.run(['go','test','-c','-o',str(test),'./internal/scap'],cwd=root/'agent',env=env,check=True,timeout=180)
values = dict(ALINKSEC_SCAP_NATIVE_WORKER_REQUIRED='true',
    ALINKSEC_SCAP_TEST_BIN=os.environ['ALINKSEC_SCAP_TEST_BIN'],
    ALINKSEC_SCAP_TEST_RUNTIME_SHA256=os.environ['ALINKSEC_SCAP_TEST_RUNTIME_SHA256'],
    ALINKSEC_SCAP_FIXTURE_ZIP=str(root/'.tmp/scap-native/execution/fixture/content.zip'),
    ALINKSEC_SCAP_NATIVE_EVIDENCE_FILE=str(root/'.tmp/scap-native/agent.json'))
command = [str(test),'-test.v','-test.run','^TestNativeScapWorker$','-test.timeout','5m']
if os.name != 'nt' and os.geteuid()!=0:
    command = ['sudo','-n','env',*(f'{k}={v}' for k,v in values.items()),*command]
subprocess.run(command,env=dict(env,**values),check=True,timeout=320)
