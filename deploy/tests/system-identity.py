#!/usr/bin/env python3
"""Record the actual environment without serial numbers, usernames or secrets."""
import argparse,json,os,platform,subprocess,time
from pathlib import Path

p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('--scope',choices=['native-host','container-userland'],required=True);a=p.parse_args()
def run(args):return subprocess.check_output(args,text=True,timeout=15).strip()
d={'head':run(['git','rev-parse','HEAD']),'observedAt':int(time.time()*1000),'scope':a.scope,
   'system':platform.system(),'kernel':platform.release(),'kernelVersion':platform.version(),'machine':platform.machine(),
   'runnerImage':os.environ.get('ImageOS',''),'runnerImageVersion':os.environ.get('ImageVersion',''),
   'go':run(['go','version']),'python':platform.python_version()}
if platform.system()=='Windows':
    d['os']=json.loads(run(['powershell','-NoProfile','-NonInteractive','-Command',
        'Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | ConvertTo-Json -Compress']))
else:
    d['osRelease']=Path('/etc/os-release').read_text()
    d['effectiveUid']=os.geteuid()
assert d['head'] and d['kernel'] and d['go']
a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n');a.output.chmod(0o600)
print(json.dumps({'scope':d['scope'],'kernel':d['kernel'],'machine':d['machine']}))
