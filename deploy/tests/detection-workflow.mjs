import assert from 'node:assert/strict'
import {createHash} from 'node:crypto'
import {mkdirSync,writeFileSync} from 'node:fs'
import {join,resolve} from 'node:path'
import {setTimeout as delay} from 'node:timers/promises'

// Only harmless fixture bytes and one existing disposable Linux Agent are used.
export async function detectionWorkflow({api,command,until,agent,sql,importPackage,pass=console.log}) {
 const dex=(...args)=>command('docker',['exec',agent.container,...args])
 const sample='#!/bin/sh\n# harmless detection workflow; never executed\n'
 const digest=createHash('sha256').update(sample).digest('hex')
 const stateRoot=agent.workDir, prefix='/tmp/alinksec-native/scan',file=prefix+'/harmless.sh'
 writeFileSync(join(agent.fixtures,'detect-sample'),sample);writeFileSync(join(agent.fixtures,'detect-replacement'),'unrelated replacement\n')
 const pkg=join(agent.fixtures,'detection.zip')
 await command('python3',['-c',String.raw`import json,sys,zipfile
with zipfile.ZipFile(sys.argv[1],'w',zipfile.ZIP_DEFLATED) as z:
 z.writestr('manifest.json',json.dumps({'db_version':'native-detection-v2','hash_count':1,'rule_count':0}))
 z.writestr('hashes.txt',sys.argv[2]+' Native.Harmless 4\n')`,pkg,digest])
 async function realtime(enabled,action) {
  await api('/api/virus/realtime',{enabled,action})
  await until(async()=>{const policy=JSON.parse(await dex('cat',`${stateRoot}/policy.json`));return policy.virus_realtime?.enabled===enabled && policy.virus_realtime.action===action},'Detection policy did not reach Agent')
 }
 const findings=task=>sql('SELECT * FROM t_virus_finding WHERE task_id=?',task)
 async function scan(paths) {
  const {taskId}=await api('/api/virus/tasks',{name:'Actual Agent harmless detection',agentIds:[agent.id],mode:3,paths})
  await until(()=>sql('SELECT status FROM t_virus_scan_task WHERE id=?',taskId)[0]?.status!==1,'Scan did not finish',45_000)
  return taskId
 }
 async function act(id,action,expected) {
  const result=await api('/api/virus/findings/actions',{findingIds:[id],action})
  await until(()=>sql('SELECT state FROM t_virus_action_evidence WHERE command_id=?',result.commands[0])[0]?.state===expected,action+' did not return target receipt')
 }
 await realtime(false,'alert_only')
 await dex('chown','root:root',stateRoot,stateRoot+'/virus');await dex('chmod','0755',stateRoot,stateRoot+'/virus')
 await dex('mkdir','-p',prefix);await dex('cp','/fixtures/detect-sample',file);await dex('chmod','0640',file)
 await importPackage(pkg)
 const version=(await api('/api/virus/db'))[0].db_version
 await until(()=>sql('SELECT virus_execution_contract,virus_db_version FROM t_agent WHERE agent_id=?',agent.id).some(r=>r.virus_execution_contract===2 && r.virus_db_version===version),'Native signature install/heartbeat did not converge',45_000)
 const partial=await scan([file,prefix+'/missing']);const first=findings(partial)[0]
 assert.equal(first.sha256,digest);assert.equal(first.status,1);assert.match(first.quarantine_id,/^[0-9a-f]{32}$/)
 const evidence=(await api(`/api/virus/tasks/${partial}/evidence`))[0]
 assert.equal(evidence.state,'partial');assert.equal(evidence.evidence.files_failed,1);assert.equal(evidence.evidence.db_version,version);assert.match(evidence.evidence_sha256,/^[0-9a-f]{64}$/)
 await dex('cp','/fixtures/detect-replacement',file);await act(first.id,'delete','succeeded')
 assert.equal(await dex('cat',file),'unrelated replacement')
 pass('actual Agent pinned partial scan, immutable per-host evidence and quarantine-ID delete preserves original-path replacement')
 await dex('cp','/fixtures/detect-sample',file);await dex('chmod','0640',file)
 const secondTask=await scan([file]);const second=findings(secondTask)[0]
 await dex('cp','/fixtures/detect-replacement',file);await act(second.id,'restore','failed')
 assert.equal(sql('SELECT status FROM t_virus_finding WHERE id=?',second.id)[0].status,1)
 assert.equal(await dex('cat',file),'unrelated replacement')
 await dex('rm',file);await act(second.id,'restore','succeeded')
 assert.equal((await dex('sha256sum',file)).split(' ')[0],digest)
 assert.equal(await dex('stat','-c','%a',file),'640')
 const history=await api(`/api/virus/findings/${second.id}/history`);assert.ok(history.some(h=>h.state==='failed'));assert.ok(history.some(h=>h.state==='observed' && h.evidence.quarantine_id===second.quarantine_id))
 pass('actual Agent occupied-path restore fails safely; later restore preserves bytes and permissions with initial capture evidence')
 await api('/api/virus/findings/actions',{findingIds:[second.id],action:'whitelist'})
 await until(async()=>JSON.parse(await dex('cat',`${stateRoot}/policy.json`)).virus_whitelist?.some(w=>w.type==='hash' && w.value===digest),'Whitelist not applied')
 const clean=await scan([file]);assert.equal(findings(clean).length,0);assert.equal(sql('SELECT status FROM t_virus_finding WHERE id=?',second.id)[0].status,3)
 const whitelist=(await api('/api/virus/whitelist')).find(w=>w.value===digest);await api('/api/virus/whitelist/'+whitelist.id,undefined,'DELETE')
 await until(async()=>!JSON.parse(await dex('cat',`${stateRoot}/policy.json`)).virus_whitelist?.some(w=>w.value===digest),'Whitelist removal not applied')
 const cross='/tmp/alinksec-detection-cross-volume.sh';await dex('cp','/fixtures/detect-sample',cross)
 const crossTask=await scan([cross]),crossFinding=findings(crossTask)[0];assert.equal(crossFinding.status,0);assert.ok(crossFinding.action_error);assert.equal(crossFinding.quarantine_id,'')
 await act(crossFinding.id,'delete','failed');await dex('test','-f',cross);await dex('rm',cross)
 pass('actual Agent cross-volume quarantine/delete fail without removing original bytes')
 await realtime(true,'alert_only');await delay(12000)
 const periodic=prefix+'/periodic.sh';await dex('cp','/fixtures/detect-sample',periodic)
 // Native events and bounded recovery can both report the same unchanged file.
 // This workflow requires detection and byte-bound evidence, not exact-once delivery.
 await until(()=>sql("SELECT id FROM t_virus_finding WHERE agent_id=? AND task_id IS NULL AND path=?",agent.id,periodic).length>0,'Independent periodic detection did not produce finding',45_000)
 const events=sql('SELECT status,sha256,initial_evidence FROM t_virus_finding WHERE agent_id=? AND task_id IS NULL AND path=? ORDER BY id',agent.id,periodic)
 for(const event of events) {
  assert.equal(event.status,0);assert.equal(event.sha256,digest)
  const proof=JSON.parse(event.initial_evidence);assert.equal(proof.source,'realtime_guard');assert.equal(proof.sha256,digest)
 }
 const event=events[0];assert.equal(await dex('test','-f',periodic),'')
 await realtime(false,'alert_only')
 const output=resolve(agent.dir,'../../detection-capabilities-native');mkdirSync(output,{recursive:true});writeFileSync(join(output,'result.json'),JSON.stringify({passed:true,agent:agent.id,distro:(await api(`/api/hosts/${agent.id}`)).distro_version,pinnedVersion:version,partialEvidence:evidence,firstFinding:first,replacementSurvived:true,restoredDigest:digest,restoredMode:'640',history,whitelistedEvidence:await api(`/api/virus/tasks/${clean}/evidence`),periodicEvidence:event,periodicEvidenceCount:events.length},null,2)+'\n')
 pass('actual Agent whitelist retains historical physical state; independent periodic alert works while decoy is disabled')
}
