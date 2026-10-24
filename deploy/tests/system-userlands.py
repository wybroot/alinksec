#!/usr/bin/env python3
"""Exercise same-commit static binaries on real distribution userlands."""
import hashlib,json,os,platform,subprocess,uuid
from pathlib import Path

assert os.environ.get('GITHUB_ACTIONS')=='true' and os.environ.get('RUNNER_ENVIRONMENT')=='github-hosted'
assert os.environ.get('ALINKSEC_SMOKE_ALLOW_FIXTURES')=='true'
repo=Path(__file__).resolve().parents[2];out=repo/'.tmp/system-acceptance';out.mkdir(parents=True,exist_ok=True)
profiles=[('ubuntu1804','ubuntu:18.04'),('ubuntu2004','ubuntu:20.04'),('ubuntu2204','ubuntu:22.04'),('ubuntu2404','ubuntu:24.04'),
          ('debian12','debian:12-slim'),('centos7','centos:7'),('rocky8','rockylinux:8'),('rocky9','rockylinux:9')]
prefix='alinksec-userland-'+uuid.uuid4().hex[:12];results=[];passed=False
def run(args,timeout=180):return subprocess.check_output(args,cwd=repo,text=True,stderr=subprocess.STDOUT,timeout=timeout).strip()
head=run(['git','rev-parse','HEAD']);binary=repo/'.tmp/system-acceptance.test';agent=repo/'.tmp/alinksec-agent'
manifest={'head':head,'arch':os.environ['GOARCH'],'scope':'container-userland','sharedHostKernel':platform.release(),
          'agentSha256':hashlib.sha256(agent.read_bytes()).hexdigest(),'testSha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'profiles':results}
try:
    for name,image in profiles:
        entry={'name':name,'image':image,'passed':False};results.append(entry)
        run(['docker','pull',image],240)
        info=json.loads(run(['docker','image','inspect',image]))[0]
        assert info['Architecture']==os.environ['GOARCH']
        entry.update(imageId=info['Id'],repoDigests=info['RepoDigests'],architecture=info['Architecture'])
        target=out/name;target.mkdir(mode=0o700)
        args=['docker','run','--name',prefix+'-'+name,'--label','alinksec.system-validation='+prefix,
              '--network=none','--read-only','--memory=192m','--memory-swap=192m','--cpus=1','--pids-limit=64',
              '--cap-drop=ALL','--security-opt=no-new-privileges:true','--user',f'{os.getuid()}:{os.getgid()}',
              '--tmpfs','/tmp:rw,nosuid,nodev,size=32m,mode=1777',
              '--mount',f'type=bind,src={repo},dst=/workspace,readonly','--mount',f'type=bind,src={target},dst=/evidence',
              '-e','ALINKSEC_SMOKE_ALLOW_FIXTURES=true','-e','GOMEMLIMIT=96MiB','-e','GOMAXPROCS=1',
              '-e','GITHUB_SHA='+head,'-e','ALINKSEC_SYSTEM_SCOPE=container-userland','-e','ALINKSEC_SYSTEM_IMAGE='+image,
              '-e','ALINKSEC_SYSTEM_EVIDENCE_FILE=/evidence/result.json',info['Id'],'/bin/sh','-c',
              '/workspace/.tmp/alinksec-agent version && /workspace/.tmp/system-acceptance.test -test.v -test.run=^TestActualSystemInterfaces$ -test.timeout=60s']
        try:
            output=run(args,90);(target/'native.log').write_text(output+'\n')
            assert 'alinksec-agent '+(repo/'VERSION').read_text().strip() in output
            evidence=json.loads((target/'result.json').read_text());assert evidence['passed'] and evidence['head']==head and evidence['scope']=='container-userland'
            entry['passed']=True
        except subprocess.CalledProcessError as error:
            (target/'native.log').write_text(error.output[-256*1024:]);raise
        finally:
            subprocess.run(['docker','rm','-f',prefix+'-'+name],capture_output=True,timeout=30)
    passed=True
finally:
    owned=run(['docker','ps','-aq','--filter','label=alinksec.system-validation='+prefix]).splitlines()
    for ident in owned:subprocess.run(['docker','rm','-f',ident],check=True,capture_output=True,timeout=30)
    manifest['remainingOwnedContainers']=len(run(['docker','ps','-aq','--filter','label=alinksec.system-validation='+prefix]).splitlines())
    manifest['passed']=passed and manifest['remainingOwnedContainers']==0
    (out/'userlands.json').write_text(json.dumps(manifest,indent=2)+'\n')
assert manifest['passed'] and len(results)==len(profiles)
print(json.dumps({'passed':True,'userlands':len(results),'scope':'userland only; shared runner kernel'}))
