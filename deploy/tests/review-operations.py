#!/usr/bin/env python3
"""Disposable single-instance dependency, native offline and screen acceptance."""
import argparse
import concurrent.futures
import contextlib
import hashlib
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import sqlite3
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
import zipfile

parser=argparse.ArgumentParser()
parser.add_argument('--database',choices=['sqlite','postgres'],required=True)
args=parser.parse_args()
repo=Path(__file__).resolve().parents[2]
output=repo/'.tmp/review-operations'/args.database
output.mkdir(parents=True,exist_ok=False)
private=repo/('.tmp/review-operations-private-'+uuid.uuid4().hex)
private.mkdir(mode=0o700)
control=private/'control';control.mkdir()
data=private/'data';data.mkdir()
work=private/'agent';work.mkdir(mode=0o700)
prefix='alinksec-operations-'+uuid.uuid4().hex[:10]
containers=[];samples=[];observations=[];notifications=[];captures=[];lock=threading.Lock();java=None
password,enroll,owner_password,app_password=[secrets.token_urlsafe(24) for _ in range(4)]
masked=[password,enroll,owner_password,app_password]
class ValidationProcessExited(Exception): pass
admin=None
result={'passed':False,'database':args.database,'releaseOrDeployment':False}
if os.environ.get('GITHUB_ACTIONS')=='true':
    for value in masked:print('::add-mask::'+value,flush=True)

def redact(text):
    for secret in masked:text=text.replace(secret,'[removed]')
    return text
def write(name,value):
    (output/name).write_text(redact(json.dumps(value,indent=2,default=str))+'\n')
def resource():
    available=int(next(x.split()[1] for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('MemAvailable:')))//1024
    pressure=float(next(x.split('avg10=')[1].split()[0] for x in Path('/proc/pressure/memory').read_text().splitlines() if x.startswith('full ')))
    sample={'availableMiB':available,'fullPSI':pressure};samples.append(sample)
    assert available>=384 and pressure<=10,('resource watchdog',sample)
    return available
def command(argv,timeout=90):
    run=subprocess.run([str(v) for v in argv],capture_output=True,text=True,timeout=timeout)
    if run.returncode:raise RuntimeError(redact(str(argv[0])+': '+(run.stdout+run.stderr)[-1500:]))
    return run.stdout.strip()
def until(predicate,label,timeout=90,interval=.25):
    deadline=time.monotonic()+timeout;last=None;next_progress=0
    while time.monotonic()<deadline:
        resource()
        try:
            value=predicate()
            if value:return value
        except (OSError,ValueError,AssertionError,RuntimeError) as error:last=error
        if time.monotonic()>=next_progress:
            print('waiting - '+label,flush=True);next_progress=time.monotonic()+15
        time.sleep(interval)
    raise AssertionError(label+': '+redact(str(last)))
def port():
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));return sock.getsockname()[1]
def container(suffix,image,parameters,environment,memory,java=False):
    argv=['docker','run','-d','--name',prefix+suffix,'--network=host','--memory='+str(memory)+'m','--memory-swap='+str(memory)+'m','--cpus=1','--pids-limit=256',
          '--label','alinksec.review-operations='+prefix,'-v',f'{repo}:{repo}','-w',str(private)]
    if suffix!='-pg':argv+=['--user',f'{os.getuid()}:{os.getgid()}']
    if java:argv+=['--entrypoint','java']
    for key,value in environment.items():argv+=['-e',key+'='+str(value)]
    ident=command([*argv,image,*parameters],180);containers.append(ident);return ident
def state(ident):return json.loads(command(['docker','inspect','--format','{{json .State}}',ident]))
def stop(ident):
    if state(ident)['Running']:command(['docker','stop','-t','8',ident],30)
    value=state(ident);assert not value['OOMKilled'] and value['ExitCode']==0,value
    return {'exitCode':value['ExitCode'],'oomKilled':value['OOMKilled']}
def request(path,body=None,expected=200,anonymous=False,label=None):
    resource();started=time.monotonic();at=int(time.time()*1000)
    req=urllib.request.Request('http://127.0.0.1:'+str(http_port)+path,data=None if body is None else json.dumps(body).encode(),
            headers={'Content-Type':'application/json',**({} if anonymous or not admin else {'Authorization':'Bearer '+admin})})
    try:response=urllib.request.urlopen(req,timeout=8)
    except urllib.error.HTTPError as error:response=error
    with response:
        raw=response.read(8*1024*1024);value=json.loads(raw);status=response.status
    if path=='/api/auth/login' and value.get('data',{}).get('token'):
        token=value['data']['token'];masked.append(token)
        if os.environ.get('GITHUB_ACTIONS')=='true':print('::add-mask::'+token,flush=True)
    with lock:
        index=len(observations);observations.append(json.loads(redact(json.dumps({'index':index,'label':label or path,'atMillis':at,'durationMillis':round((time.monotonic()-started)*1000),
                'method':req.get_method(),'path':path,'request':body,'status':status,'response':value},default=str))))
    if expected is not None:assert status==expected,(path,status,expected)
    return value.get('data',value) if status==200 and value.get('code',0)==0 else value
def action(path,body,label=None):return request('/api/review-operations/'+path,body,label=label)
def facts(agent):return request('/api/review-operations/facts?'+urllib.parse.urlencode({'agent':agent}))
def capture(label):
    paths=['/api/dashboard/summary','/api/dashboard/screen-trend?days=7','/api/dashboard/event-distribution','/api/dashboard/baseline-categories',
           '/api/dashboard/top-hosts?limit=5','/api/alerts?page=1&size=20','/api/protect/engines','/api/protect/status']
    indices=[]
    for path in paths:
        request(path,label=label+':'+path);indices.append(len(observations)-1)
    captures.append({'name':label,'responses':indices})
    return observations[indices[6]]['response']['data']

class Sink(http.server.BaseHTTPRequestHandler):
    def log_message(self,*_):pass
    def do_POST(self):
        size=int(self.headers.get('Content-Length','0'));assert 0<=size<=256*1024
        body=self.rfile.read(size)
        if self.path=='/notify':
            with lock:notifications.append({'atMillis':int(time.time()*1000),'idempotencyKey':self.headers.get('Idempotency-Key'),
                                           'body':json.loads(body)})
        self.send_response(200);self.end_headers()

sink=http.server.ThreadingHTTPServer(('127.0.0.1',0),Sink)
thread=threading.Thread(target=sink.serve_forever,daemon=True);thread.start()
db_lock=None
try:
    assert resource()>=1536,'Smallest required scenario needs Java640 + PostgreSQL256 + one Agent192 MiB'
    write('resource-start.json',{'limitsMiB':{'java':640,'postgres':256,'nativeAgent':192},'workersPerProcess':1,
                                'maximumLocalContainers':3 if args.database=='postgres' else 2,'browserOverlapsBackend':False})
    jar=repo/'server/alinksec-bootstrap/target/alinksec-bootstrap.jar';native=repo/'.tmp/alinksec-agent'
    classes=repo/'server/alinksec-bootstrap/target/test-classes/review/operations'
    assert jar.is_file() and native.is_file()
    with zipfile.ZipFile(jar) as z:assert not any(x.startswith('BOOT-INF/classes/review/operations/') for x in z.namelist())
    shutil.copytree(classes,private/'fixture-classes/review/operations')
    source=command(['git','rev-parse','HEAD']);clean=not command(['git','status','--porcelain','--untracked-files=normal'])
    if os.environ.get('GITHUB_ACTIONS')=='true':assert source==os.environ['GITHUB_SHA'] and clean
    write('provenance.json',{'source':source,'clean':clean,'scope':'committed-ci' if clean else 'working-tree',
          'productionJarContainsFixture':False,'binaries':{str(p.relative_to(repo)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [jar,native]},
          'fixtureClasses':{str(p.relative_to(classes)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(classes.rglob('*.class'))}})
    http_port,grpc_port=port(),port()
    environment={'SPRING_PROFILES_ACTIVE':args.database,'ALINKSEC_CLUSTER_ENABLED':'false','ALINKSEC_METRICS_ENABLED':'false',
        'ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD':password,'ALINKSEC_BOOTSTRAP_ENROLL_TOKEN':enroll,'ALINKSEC_JWT_SECRET':'',
        'ALINKSEC_SQLITE_PATH':str(data/'alinksec.db'),'ALINKSEC_CERT_DIR':str(data/'certs'),'ALINKSEC_WEB_TLS_DIR':str(data/'web-tls'),
        'ALINKSEC_LIBRARY_WORK_DIR':str(data/'libraries'),'ALINKSEC_OPERATIONS_CONTROL_DIR':str(control),
        'ALINKSEC_OPERATIONS_WEBHOOK':f'http://127.0.0.1:{sink.server_port}/notify',
        'SPRING_DATASOURCE_HIKARI_MAXIMUMPOOLSIZE':'4','SPRING_DATASOURCE_HIKARI_CONNECTIONTIMEOUT':'2000'}
    if args.database=='postgres':
        pg_port=port()
        pg=container('-pg','postgres:17',['-p',str(pg_port),'-c','listen_addresses=127.0.0.1','-c','shared_buffers=32MB','-c','max_connections=20'],
                     {'POSTGRES_USER':'alinksec','POSTGRES_PASSWORD':owner_password,'POSTGRES_DB':'alinksec'},256)
        until(lambda:command(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-p',str(pg_port),'-U','alinksec']),'PostgreSQL startup')
        for schema in sorted((repo/'deploy/sql').glob('*.sql')):
            (output/('schema-'+schema.name+'.log')).write_text(command(['docker','exec',pg,'psql','-p',str(pg_port),'-U','alinksec','-d','alinksec','-v','ON_ERROR_STOP=1','-f',schema]))
        migration={'PGHOST':'127.0.0.1','PGPORT':str(pg_port),'PGDATABASE':'alinksec','PGUSER':'alinksec','PGPASSWORD':owner_password,
                   'ALINKSEC_APP_DB_USER':'alinksec_app','ALINKSEC_APP_DB_PASSWORD':app_password,'ALINKSEC_BIND_ADDRESS':'127.0.0.1','ALINKSEC_MIGRATIONS_DIR':str(repo/'deploy/migrations')}
        options=[v for key,value in migration.items() for v in ['-e',key+'='+value]]
        (output/'migrations.log').write_text(redact(command(['docker','exec',*options,pg,'bash',repo/'deploy/migrations/run-migrations.sh'])))
        environment.update(PG_HOST='127.0.0.1',PG_PORT=str(pg_port),PG_USER='alinksec_app',PG_PASSWORD=app_password)
    java=container('-java','maven:3.9.9-eclipse-temurin-21',
        ['-Xmx256m','-Xss512k','-XX:MaxMetaspaceSize=160m','-XX:MaxDirectMemorySize=96m','-XX:ReservedCodeCacheSize=48m','-XX:ActiveProcessorCount=1',
         '-Dloader.main=review.operations.OperationsFixtureServer','-Dloader.path='+str(private/'fixture-classes'),'-cp',jar,
         'org.springframework.boot.loader.launch.PropertiesLauncher','--server.address=127.0.0.1','--server.port='+str(http_port),'--alinksec.server.port='+str(grpc_port),
         '--logging.level.org.springframework.boot.diagnostics.LoggingFailureAnalysisReporter=DEBUG',
         '--server.tomcat.threads.max=16','--server.tomcat.threads.min-spare=1','--server.tomcat.accept-count=8'],environment,640,java=True)
    def started():
        if not state(java)['Running']:raise ValidationProcessExited('Application startup failed; retained container log has the cause')
        return (control/'ready.json').exists() and request('/api/health',anonymous=True) is None
    until(started,'real application startup',120)
    admin=request('/api/auth/login',{'username':'admin','password':password},anonymous=True)['token']
    request('/api/ready',anonymous=True);request('/api/users?page=1&size=20')
    identity_before={str(p.relative_to(data)):hashlib.sha256(p.read_bytes()).hexdigest() for p in data.rglob('*') if p.is_file() and (p.name=='ca.crt' or p.name=='jwt.secret')}
    ready_before=len(observations)-2
    if args.database=='postgres':stop(pg)
    else:
        db_lock=sqlite3.connect(data/'alinksec.db',timeout=1);db_lock.execute('BEGIN IMMEDIATE')
    request('/api/health',anonymous=True,label='dependency-down-liveness')
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as workers:
        list(workers.map(lambda _:request('/api/ready',expected=503,anonymous=True,label='dependency-down-readiness'),range(16)))
    # The authenticated REST filter also needs the database during an outage.
    # A private test-classpath sampler observes worker bounds without bypassing that filter.
    bounds=json.loads((control/'resources-live.json').read_text());assert bounds['maximumPool']==1 and bounds['probeWorkers']<=1 and bounds['probeQueue']<=1 and bounds['probeQueueRemaining']+bounds['probeQueue']==1
    if args.database=='postgres':
        request('/api/users?page=1&size=20',expected=None,label='dependency-down-core-query')
        assert observations[-1]['status']!=200 or observations[-1]['response'].get('code',0)!=0
        command(['docker','start',pg]);until(lambda:command(['docker','exec',pg,'pg_isready','-h','127.0.0.1','-p',str(pg_port),'-U','alinksec']),'same PostgreSQL dependency restart')
    else:db_lock.rollback();db_lock.close();db_lock=None
    until(lambda:request('/api/ready',anonymous=True).get('ready') is True,'business readiness recovery',30)
    request('/api/users?page=1&size=20',label='dependency-recovered-core-query')
    identity_after={str(p.relative_to(data)):hashlib.sha256(p.read_bytes()).hexdigest() for p in data.rglob('*') if p.is_file() and (p.name=='ca.crt' or p.name=='jwt.secret')}
    assert identity_before==identity_after and any(x.endswith('ca.crt') for x in identity_before)
    write('readiness.json',{'beforeObservation':ready_before,'probeResourcesDuringOutage':bounds,'identityBefore':identity_before,'identityAfter':identity_after,
                          'restoredOriginalAdministratorSession':True,'kind':'real-postgres-stop-restart' if args.database=='postgres' else 'real-sqlite-write-lock'})
    print('ok - dependency liveness, bounded failed readiness and recovery',flush=True)

    config=private/'agent.yml';config.write_text(f'server_addr: 127.0.0.1:{grpc_port}\nheartbeat_interval: 10s\ncollect_interval: 24h\ndecoy:\n  enabled: false\n')
    entry=private/'agent-entry.sh';entry.write_text('set -eu\n'+f'if [ ! -f {work}/certs/client.crt ]; then {native} install --server 127.0.0.1:{grpc_port} --token "$ALINKSEC_TEST_TOKEN" --ca-file {data}/certs/ca.crt --workdir {work}; fi\n'+f'{native} config apply --from {config} --workdir {work}\nexec {native} run --workdir {work}\n')
    agent_container=container('-agent','ubuntu:24.04',['sh',entry],{'GOMEMLIMIT':'96MiB','GOMAXPROCS':'1','ALINKSEC_TEST_TOKEN':enroll},192)
    agent=until(lambda:next((x.split(': ',1)[1] for x in (work/'state.yml').read_text().splitlines() if x.startswith('agent_id: ')),None),'native Agent enrollment')
    assert str(uuid.UUID(agent))==agent
    online=until(lambda:(v if (v:=facts(agent))['hosts'][0]['status']==1 and v['hosts'][0]['lastHeartbeatMillis']>0 else None),'actual native heartbeat')
    stopped_at=int(time.time()*1000);agent_stop=stop(agent_container)
    offline=until(lambda:(v if (v:=facts(agent))['alerts'] and v['deliveries'] and v['deliveries'][0]['delivered_at'] else None),'scheduled native stop offline alert and local webhook',110,1)
    assert len(offline['alerts'])==len(offline['deliveries'])==1 and offline['alerts'][0]['count']==1 and offline['hosts'][0]['status']==2
    elapsed=offline['observedMillis']-online['hosts'][0]['lastHeartbeatMillis'];assert 59_000<=elapsed<=105_000,elapsed
    first_alert=offline['alerts'][0]['alert_no'];request('/api/alerts?page=1&size=100',label='native-offline-visible-alert')
    until(lambda:facts(agent)['observedMillis']>=offline['observedMillis']+31_000,'next production offline scan without duplicate',40,1)
    repeated=facts(agent);assert len(repeated['alerts'])==len(repeated['deliveries'])==1 and repeated['alerts'][0]['count']==1
    own_notifications=[x for x in notifications if x['body'].get('alinksec',{}).get('agentId')==agent]
    assert len(own_notifications)==1 and own_notifications[0]['body']['alinksec']['eventType']=='host_offline' and own_notifications[0]['idempotencyKey']
    command(['docker','start',agent_container]);recovered=until(lambda:(v if (v:=facts(agent))['hosts'][0]['status']==1 and v['alerts'][0]['status']==2 else None),'native reconnect automatically closes incident',35,1)
    request('/api/hosts/'+agent+'/maintenance',{'seconds':3600},label='actual-maintenance-window');planned_at=int(time.time()*1000);stop(agent_container)
    until(lambda:facts(agent)['observedMillis']>=planned_at+95_000,'real planned shutdown remains suppressed across scheduled scans',105,1)
    maintenance=facts(agent);assert len(maintenance['alerts'])==len(maintenance['deliveries'])==1 and maintenance['alerts'][0]['status']==2 and maintenance['hosts'][0]['status']==2
    assert len(maintenance['excludedFixtures'])==3 and all(x['alerts']==0 for x in maintenance['excludedFixtures'])
    assert len([x for x in notifications if x['body'].get('alinksec',{}).get('agentId')==agent])==1
    write('offline.json',{'agentId':agent,'heartbeatIntervalSeconds':10,'offlineThresholdSeconds':60,'scanSeconds':30,'stoppedAtMillis':stopped_at,'agentStop':agent_stop,
          'online':online,'offline':offline,'afterNextScan':repeated,'recovered':recovered,'plannedStoppedAtMillis':planned_at,'maintenance':maintenance,'notifications':own_notifications,
          'scope':'actual-native-agent-stop-production-scheduler-and-loopback-test-webhook'})
    action('exclude',{'agent':agent})
    print('ok - actual native stop, scheduled single notification, reconnect and planned shutdown',flush=True)

    response_facts=action('responses',{});write('response-facts.json',response_facts)
    engines=capture('confirmed-responses')
    summary=observations[captures[-1]['responses'][0]]['response']['data'];window=summary['alerts']
    sql=request('/api/review-operations/response-sql?'+urllib.parse.urlencode({'from':window['automated30dFrom'],'through':window['automated30dThrough']}))
    assert window['automated30d']==sql['count']>20
    write('response-sql.json',{'window':window,'sql':sql})
    stages=[]
    for stage in ['empty','healthy','linux-only']:
        seeded=action('engine-stage',{'stage':stage});items=capture('engines-'+stage);stages.append({'stage':stage,'key':'file_watch','seedObservation':len(observations)-9,'captured':captures[-1]['name']})
        assert len(items)==9
        if stage=='healthy':assert sum(x['status']=='ready' for x in items)==5 and all(x['coverage']==0 for x in items if x['evidence']=='unreported')
        if stage=='linux-only':assert next(x for x in items if x['key']=='windows_login')['total']==0 and sum(x['status']=='ready' for x in items)==4
    for key in ['file_watch','windows_login','clamav','yara','scap']:
        for stage in ['missing','failed','disabled','unsupported','stale-received','stale-probe','future-received','offline','global-off','partial','beyond-page']:
            action('engine-stage',{'stage':stage,'key':key});items=capture('engines-'+key+'-'+stage)
            selected=next(x for x in items if x['key']==key)
            assert selected['status']!='ready',(key,stage,selected)
            if stage=='beyond-page':assert selected['total']==121 and selected['ready']==120 and selected['coverage']==99
            if stage=='partial':assert selected['total']==2 and selected['ready']==1 and selected['coverage']==50
            stages.append({'stage':stage,'key':key,'seedObservation':len(observations)-9,'captured':captures[-1]['name']})
    write('engine-stages.json',stages);write('captures.json',captures)
    result.update(passed=True,source=source,clean=clean,actualHttpTransactions=len(observations),engineStages=len(stages),probeResourcesVerified=True,
                  actualNativeOfflineVerified=True,localWebhookOnly=True,successfulResponseCount=window['automated30d'])
    print('ok - real HTTP response aggregation and per-engine state matrix',flush=True)
finally:
    if db_lock is not None:db_lock.rollback();db_lock.close()
    cleanup=[];cleanup_errors=[]
    for ident in reversed(containers):
        with contextlib.suppress(Exception):
            before=state(ident)
            if before['Paused']:command(['docker','unpause',ident])
            if before['Running']:command(['docker','stop','-t','8',ident],30)
            after=state(ident);cleanup.append({'exitCode':after['ExitCode'],'expectedExitCode':143 if ident==java else 0,'termination':'SIGTERM' if ident==java else 'graceful',
                                             'oomKilled':after['OOMKilled'],'running':after['Running']})
            raw=subprocess.run(['docker','logs',ident],capture_output=True,text=True,timeout=30)
            (output/('container-'+str(len(cleanup))+'.log')).write_text(redact(raw.stdout+raw.stderr))
        removed=subprocess.run(['docker','rm','-f','-v',ident],capture_output=True,text=True,timeout=30)
        if removed.returncode:cleanup_errors.append(redact((removed.stdout+removed.stderr)[-1500:]))
    sink.shutdown();sink.server_close();thread.join(timeout=3)
    write('http.json',observations);write('notifications.json',notifications);write('resources.json',samples);write('cleanup.json',cleanup);write('cleanup-errors.json',cleanup_errors)
    shutil.rmtree(private)
    remaining=command(['docker','ps','-aq','--filter','label=alinksec.review-operations='+prefix])
    result.update(remainingOwnedContainers=0 if not remaining else len(remaining.splitlines()),privateDirectoryRemoved=not private.exists(),cleanupErrors=len(cleanup_errors),
                  cleanupVerified=not cleanup_errors and all(not x['running'] and not x['oomKilled'] and x['exitCode']==x['expectedExitCode'] for x in cleanup))
    scenario_passed=result['passed'];result['passed']=scenario_passed and result['cleanupVerified']
    for path in output.rglob('*'):
        if path.is_file():
            raw=path.read_bytes()
            assert not any(value.encode() in raw for value in masked),path
    result['credentialsCompared']=len(masked);write('result.json',result)
    assert not remaining and result['privateDirectoryRemoved'],result
    if scenario_passed:assert result['passed'],result
