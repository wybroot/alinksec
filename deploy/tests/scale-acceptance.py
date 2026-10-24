"""Bounded, real mTLS/REST/SQL observation inside the disposable cluster fixture."""
import hashlib,json,math,os,queue,re,signal,subprocess,threading,time,uuid
from pathlib import Path

UUID=re.compile(r'^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$')

def percentile(values,p):
    if not values or any(not math.isfinite(x) or x<0 for x in values):raise AssertionError('missing or invalid latency samples')
    return sorted(values)[max(0,math.ceil(len(values)*p)-1)]

def summary(values):
    return {'count':len(values),'p50Millis':percentile(values,.5),'p95Millis':percentile(values,.95),'p99Millis':percentile(values,.99),'maxMillis':max(values)}

def quoted(values):
    assert len(values)<=4096 and all(UUID.fullmatch(v) for v in values)
    return ','.join("'"+v+"'" for v in values) or "''"

def process_usage(pid):
    root=Path('/proc')/str(pid)
    status=root.joinpath('status').read_text();fields=root.joinpath('stat').read_text().rsplit(')',1)[1].split()
    rss=next(int(line.split()[1])*1024 for line in status.splitlines() if line.startswith('VmRSS:'))
    return {'pid':pid,'rssBytes':rss,'cpuSeconds':(int(fields[11])+int(fields[12]))/os.sysconf('SC_CLK_TCK')}

def container_usage(pid):
    # Actual cgroup totals include the whole dependency, including child DB
    # processes. Process RSS alone would undercount PostgreSQL.
    lines=Path(f'/proc/{pid}/cgroup').read_text().splitlines()
    path=next(line.split(':',2)[2] for line in lines if line.startswith('0::'))
    root=Path('/sys/fs/cgroup')/path.lstrip('/')
    cpu=dict(line.split() for line in (root/'cpu.stat').read_text().splitlines())
    return {'pid':pid,'memoryBytes':int((root/'memory.current').read_text()),'cpuSeconds':int(cpu['usage_usec'])/1e6,'pids':int((root/'pids.current').read_text())}

def run_scale(*,repo,private,sql,api,port,admin,address,addresses,ca,native_agent,java_processes,container_ids,redact):
    profile_path=repo/'deploy/tests/profiles/scale-ci.json';profile=json.loads(profile_path.read_text())
    assert profile['version']==1 and profile['syntheticClients']==200 and profile['durationSeconds']==180
    out=repo/'.tmp/scale-native';out.mkdir(mode=0o700,exist_ok=False)
    profile_bytes=profile_path.read_bytes();run_id=uuid.uuid4().hex
    result={'passed':False,'head':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),
            'profile':profile,'profileSha256':hashlib.sha256(profile_bytes).hexdigest(),'runId':run_id,
            'scope':profile['scope'],'syntheticClients':200,'realAgents':1,'realHosts':1,'errors':[]}
    latencies={name:[] for name in ['logVisibility','heartbeatVisibility','syntheticCommand','nativeCollect','api']}
    pending_logs,pending_hearts,pending_commands={},{},{}
    totals={'heartbeat':0,'log':0,'ack':0,'syntheticCommand':0,'nativeCollect':0};ready=None;produced=None;finished=None;worker=None;reader=None;stop_requested=False
    events=queue.Queue(maxsize=4096);reader_errors=[];samples=0;commands_sent=0;native_sent=0;ids=[];all_ids=[]
    first_dashboard=None;max_resources={'javaRssBytes':0,'driverRssBytes':0,'inboxPending':0,'inboxBytes':0}
    def observe(value,kind,at,now):
        if start<=at<end:
            latencies[kind].append((now-at)/1e6)
            raw_latency.write(json.dumps({'kind':kind,'identity':value,'sentMonotonicNs':at,'observedMonotonicNs':now,'latencyMillis':(now-at)/1e6})+'\n')
            assert len(latencies[kind])<=100000
    def collect_events():
        nonlocal ready,produced,finished
        while True:
            try:event=events.get_nowait()
            except queue.Empty:break
            kind=event['kind']
            if kind=='ready':
                assert ready is None and event['clients']==200 and len(set(event['agentIds']))==200
                assert all(UUID.fullmatch(v) for v in event['agentIds']);ready=event
            elif kind=='finished':
                assert finished is None;finished=event
            elif kind=='produced':
                assert produced is None and event['clients']==200;produced=event
            elif kind=='error':raise AssertionError('protocol driver error: '+event['code'])
            else:
                assert kind in totals and UUID.fullmatch(event['agentId']) and UUID.fullmatch(event['reportId'])
                totals[kind]+=1
                if kind=='log':pending_logs[event['reportId']]=event['sentMonotonicNs']
                if kind=='heartbeat':pending_hearts[(event['agentId'],event['sequence'])]=(event['sentUnixMillis'],event['sentMonotonicNs'])
        assert not reader_errors,reader_errors
        assert len(pending_logs)<=4096 and len(pending_hearts)<=4096
    def dispatch(agent,kind):
        nonlocal commands_sent,native_sent
        before=set(sql(f"SELECT cmd_id FROM t_command WHERE agent_id='{agent}' AND type='collect_now'").splitlines())
        at=time.monotonic_ns();api(port,'/api/hosts/'+agent+'/collect',token=admin,body={})
        created=set(sql(f"SELECT cmd_id FROM t_command WHERE agent_id='{agent}' AND type='collect_now'").splitlines())-before
        assert len(created)==1 and UUID.fullmatch(next(iter(created)))
        ident=created.pop();pending_commands[ident]=(at,kind);totals[kind]+=1
        raw_commands.write(json.dumps({'phase':'dispatched','commandId':ident,'kind':kind,'sentMonotonicNs':at})+'\n')
        if kind=='syntheticCommand':commands_sent+=1
        else:native_sent+=1
    def poll_commands():
        if not pending_commands:return
        now=time.monotonic_ns()
        rows=sql(f"SELECT cmd_id,status FROM t_command WHERE cmd_id IN ({quoted(pending_commands)})").splitlines()
        now=time.monotonic_ns()
        for line in rows:
            ident,status=line.split('|');assert status not in ['5','6'],('command failed',ident,status)
            if status=='4':
                at,kind=pending_commands.pop(ident);observe(ident,kind,at,now)
                raw_commands.write(json.dumps({'phase':'done','commandId':ident,'kind':kind,'sentMonotonicNs':at,'observedMonotonicNs':now,'latencyMillis':(now-at)/1e6})+'\n')
    def db_sample():
        nonlocal first_dashboard
        snapshot=json.loads(sql(f"""SELECT json_build_object(
          'heartbeats',(SELECT COALESCE(json_object_agg(agent_id,(EXTRACT(EPOCH FROM last_heartbeat)*1000)::bigint),'{{}}'::json) FROM t_agent WHERE agent_id IN ({quoted(ids)})),
          'logs',(SELECT COALESCE(json_agg(report_id),'[]'::json) FROM t_cluster_ingress WHERE report_id IN ({quoted(pending_logs)}) AND state='applied'),
          'failures',(SELECT COUNT(*) FROM t_cluster_ingress WHERE agent_id IN ({quoted(all_ids)}) AND state='failed'),
          'pending',(SELECT COUNT(*) FROM t_cluster_ingress WHERE content_b64<>''),
          'bytes',(SELECT COALESCE(SUM(size_bytes),0) FROM t_cluster_ingress WHERE content_b64<>''),
          'rows',(SELECT COUNT(*) FROM t_agent_log WHERE source='scale:{run_id}'),
          'retainedRows',(SELECT retained_rows FROM t_agent_log_state WHERE id=1),
          'retainedBytes',(SELECT retained_bytes FROM t_agent_log_state WHERE id=1),
          'databaseBytes',pg_database_size(current_database()),
          'logTableBytes',pg_total_relation_size('t_agent_log'),
          'owners',(SELECT COUNT(DISTINCT node_id) FROM t_cluster_session WHERE agent_id IN ({quoted(ids)})),
          'sessions',(SELECT COUNT(*) FROM t_cluster_session WHERE agent_id IN ({quoted(ids)})))"""))
        now=time.monotonic_ns();assert snapshot['failures']==0
        snapshot['observedMonotonicNs']=now
        for ident in snapshot['logs']:
            at=pending_logs.pop(ident);observe(ident,'logVisibility',at,now)
        for key,(wall,at) in list(pending_hearts.items()):
            if (snapshot['heartbeats'].get(key[0]) or 0)>=wall:
                del pending_hearts[key];observe(key,'heartbeatVisibility',at,now)
        max_resources['inboxPending']=max(max_resources['inboxPending'],snapshot['pending'])
        max_resources['inboxBytes']=max(max_resources['inboxBytes'],snapshot['bytes'])
        assert snapshot['pending']<=profile['maxPendingInbox'] and snapshot['bytes']<=profile['maxInboxBytes']
        assert snapshot['retainedRows']<=200000 and snapshot['retainedBytes']<=1073741824
        return snapshot
    try:
        token=api(port,'/api/hosts/enroll-token?maxUses=200',token=admin,body={})['data']['token']
        config=private/'scale-config.json';config.write_text(json.dumps({'address':address,'addresses':addresses,'ca':str(ca),'token':token,'runId':run_id,'clients':200,
            'durationSeconds':profile['durationSeconds']+profile['warmupSeconds'],'heartbeatSeconds':profile['heartbeatSeconds'],'logSeconds':profile['logSeconds']}));config.chmod(0o600)
        worker=subprocess.Popen([str(repo/'.tmp/scale-fixture'),'--config',str(config)],cwd=repo,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        def read_events():
            try:
                with (out/'driver-events.jsonl').open('w') as raw:
                    count=0
                    for line in worker.stdout:
                        count+=1;assert count<=100000 and len(line)<=65536
                        value=json.loads(line);raw.write(line);raw.flush();events.put(value,timeout=1)
            except BaseException as failure:reader_errors.append(type(failure).__name__)
        reader=threading.Thread(target=read_events,daemon=True);reader.start()
        deadline=time.monotonic()+130
        while ready is None:
            collect_events();assert worker.poll() is None,'driver exited before all streams opened'
            assert time.monotonic()<deadline,'all-client startup deadline';time.sleep(.05)
        ids=ready['agentIds'];all_ids=ids+[native_agent];assert UUID.fullmatch(native_agent)
        start=ready['startedMonotonicNs']+profile['warmupSeconds']*1_000_000_000;end=start+profile['durationSeconds']*1_000_000_000
        result['startedMonotonicNs']=start;result['finishedMonotonicNs']=end
        container_pids={ident:int(subprocess.check_output(['docker','inspect','--format','{{.State.Pid}}',ident],text=True)) for ident in container_ids}
        next_sample=time.monotonic_ns();next_command=start;next_native=start;maximum_deadline=end+profile['drainSeconds']*1_000_000_000
        with (out/'seconds.jsonl').open('w') as raw_samples,(out/'command-observations.jsonl').open('w') as raw_commands,(out/'latency-observations.jsonl').open('w') as raw_latency:
            while True:
                collect_events();now=time.monotonic_ns()
                assert now<maximum_deadline,('reports or commands failed to drain',{'logs':len(pending_logs),'heartbeats':len(pending_hearts),'commands':len(pending_commands),'samples':samples})
                if worker.poll() is not None and finished is None and not reader.is_alive() and events.empty():raise AssertionError('driver exited without a complete sustained window: '+str(worker.returncode))
                if start<=now<end:
                    if now>=next_command:
                        dispatch(ids[commands_sent%len(ids)],'syntheticCommand');next_command+=int(1e9/profile['commandsPerSecond'])
                    if now>=next_native:
                        dispatch(native_agent,'nativeCollect');next_native+=profile['nativeCommandEverySeconds']*1_000_000_000
                poll_commands()
                raw_commands.flush();raw_latency.flush()
                now=time.monotonic_ns()
                if now>=next_sample:
                    snapshot=db_sample();now=time.monotonic_ns();inside=start<=now<end
                    if inside:assert snapshot['sessions']==200 and snapshot['owners']==2,'scale streams must remain on both actual replicas'
                    process_samples=[process_usage(p.pid) for p in java_processes]
                    max_resources['javaRssBytes']=max(max_resources['javaRssBytes'],max(v['rssBytes'] for v in process_samples))
                    driver_usage=process_usage(worker.pid) if worker.poll() is None else None
                    if driver_usage:max_resources['driverRssBytes']=max(max_resources['driverRssBytes'],driver_usage['rssBytes'])
                    assert max_resources['javaRssBytes']<=profile['maxJavaRssMiBPerReplica']*1048576
                    assert max_resources['driverRssBytes']<=profile['maxDriverRssMiB']*1048576
                    api_started=time.monotonic_ns();dashboard=api(port,'/api/dashboard/summary',token=admin)['data'];api_done=time.monotonic_ns()
                    observe(None,'api',api_started,api_done)
                    if first_dashboard is None and dashboard['hosts']['online']>=201:first_dashboard=api_done
                    sample={'monotonicNs':now,'steadyWindow':inside,'elapsedSeconds':(now-start)/1e9,'database':snapshot,'java':process_samples,'driver':driver_usage,
                            'containers':{ident:container_usage(pid) for ident,pid in container_pids.items()},'dashboardOnline':dashboard['hosts']['online'],
                            'sent':dict(totals),'pendingLogObservations':len(pending_logs),'pendingHeartbeatObservations':len(pending_hearts),'pendingCommands':len(pending_commands)}
                    raw_samples.write(json.dumps(sample)+'\n');raw_samples.flush()
                    if inside:samples+=1
                    next_sample+=1_000_000_000
                    # A slow observer is a missing sample, never backfilled.
                    if next_sample<time.monotonic_ns():next_sample=time.monotonic_ns()+1_000_000_000
                if produced is not None and not pending_logs and not pending_commands and not pending_hearts and not stop_requested:
                    worker.stdin.write('stop\n');worker.stdin.flush();worker.stdin.close();stop_requested=True
                if finished is not None and not pending_logs and not pending_commands and not pending_hearts:break
                time.sleep(profile['sqlPollMillis']/1000)
        assert worker.wait(timeout=5)==0;reader.join(timeout=5);assert not reader.is_alive() and not reader_errors
        assert finished['finishedMonotonicNs']>=end and finished['clients']==200
        assert produced is not None and produced['producedMonotonicNs']>=end and stop_requested
        assert finished['sentReports']==sum(totals[k] for k in ['heartbeat','log','ack'])
        assert samples>=profile['minimumSecondSamples'],('missing steady-window seconds',samples,profile['minimumSecondSamples'])
        assert commands_sent>=profile['minimumSyntheticCommands'],('missing synthetic commands',commands_sent,profile['minimumSyntheticCommands'])
        assert native_sent>=profile['minimumNativeCommands'],('missing actual Agent commands',native_sent,profile['minimumNativeCommands'])
        assert len(latencies['syntheticCommand'])==commands_sent and len(latencies['nativeCollect'])==native_sent
        # Independent SQL reads validate exact UTF-8 bytes, all producer sequences
        # and deduplication instead of trusting the load driver's Send count.
        rows=sql(f"SELECT agent_id,event_key,content_sha256,raw_content FROM t_agent_log WHERE source='scale:{run_id}' ORDER BY id").splitlines()
        sequences={agent:0 for agent in ids}
        for row in rows:
            agent,event_key,digest,content=row.split('|',3);seq=int(content.rsplit(' ',1)[1]);assert seq==sequences[agent]+1
            assert content=='synthetic harmless log 中文 '+str(seq)
            assert event_key==hashlib.sha256(f'{run_id}/{agent}/{seq}'.encode()).hexdigest() and digest==hashlib.sha256(content.encode()).hexdigest()
            sequences[agent]=seq
        assert len(rows)==totals['log'] and len(rows)>=profile['minimumLogRows'] and all(n>0 for n in sequences.values())
        assert first_dashboard is not None and first_dashboard-ready['startedMonotonicNs']<=5_000_000_000
        deadline=time.monotonic()+10
        while int(sql(f"SELECT COUNT(*) FROM t_cluster_session WHERE agent_id IN ({quoted(ids)})")) and time.monotonic()<deadline:time.sleep(.1)
        remaining=int(sql(f"SELECT COUNT(*) FROM t_cluster_session WHERE agent_id IN ({quoted(ids)})"));assert remaining==0
        metrics={key:summary(value) for key,value in latencies.items()}
        for key,limit in [('logVisibility','logVisibilityP95Millis'),('heartbeatVisibility','heartbeatVisibilityP95Millis'),('syntheticCommand','syntheticCommandP95Millis'),('nativeCollect','nativeCollectP95Millis'),('api','apiP95Millis')]:
            assert metrics[key]['p95Millis']<=profile[limit],(key,metrics[key],profile[limit])
        result.update(passed=True,actualSustainedSeconds=(produced['producedMonotonicNs']-start)/1e9,actualDrainSeconds=(finished['finishedMonotonicNs']-produced['producedMonotonicNs'])/1e9,secondSamples=samples,metrics=metrics,totals=totals,
                      logRows=len(rows),remainingSyntheticSessions=remaining,dashboardInitialVisibilityMillis=(first_dashboard-ready['startedMonotonicNs'])/1e6,
                      maxResources=max_resources,hostOrderAndExactBytes=True,longSoakAccepted=False,real200HostAcceptance=False,
                      loadRouting='Synthetic streams alternate between two direct loopback replicas; actual Agent retains HAProxy failover route')
    except BaseException as failure:
        result['errors'].append(redact(str(failure))[:2000]);result['errorDistribution']={type(failure).__name__:1};raise
    finally:
        if worker is not None:
            if worker.poll() is None:
                worker.terminate()
                try:worker.wait(timeout=5)
                except subprocess.TimeoutExpired:worker.kill();worker.wait(timeout=5)
            if reader is not None:reader.join(timeout=5)
            if worker.stdin is not None and not worker.stdin.closed:worker.stdin.close()
            error=worker.stderr.read(65536);worker.stderr.close();worker.stdout.close()
            if error:(out/'driver-stderr.log').write_text(redact(error))
            result['driverExitCode']=worker.returncode
        result['latencyCounts']={k:len(v) for k,v in latencies.items()};result['observedSecondSamples']=samples
        (out/'result.json').write_text(json.dumps(result,indent=2)+'\n')
    return result
