import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { isDeepStrictEqual } from 'node:util'

// The caller supplies one disposable Agent and its existing platform connection.
export async function protectionWorkflow({ api, command, until, agent, alerts, restart, sourceIP = '198.51.100.23', probe, pass = console.log }) {
  const work = join(agent.dir, 'work'), fixture = agent.fixtures
  const originals = (await api('/api/protect/rules')).filter(r => ['PR-0002','PR-0003'].includes(r.rule_id))
  assert.equal(originals.length,2)
  const containerPath = '/work/protected-test/config', file = join(work,'protected-test/config')
  mkdirSync(join(work,'protected-test'),{recursive:true})
  writeFileSync(file,'ORIGINAL\n',{mode:0o640})
  const baselineKey = createHash('sha256').update('PR-0002\0'+containerPath).digest('hex')
  const baseline = '/work/file-protection/'+baselineKey+'.json'
  const dex = (...args) => command('docker',['exec',agent.container,...args])
  const exists = path => dex('test','-e',path).then(()=>true,()=>false)
  const state = async path => JSON.parse(await dex('cat','/work/'+path))
  async function rule(id, body, field) {
    await api(`/api/protect/rules/${id}`,body,'PUT')
    await until(async () => {
      if (!await exists('/work/policy.json')) return false
      const current = (await state('policy.json'))[field]?.find(r=>r.id===id)
      return current && Object.entries(body).every(([key,value]) => isDeepStrictEqual(current[key],value))
    },`Protection policy ${id} did not reach Agent`)
  }
  const fileBody = {enabled:true,match:{platforms:['linux'],paths:[containerPath],max_file_bytes:1024},actions:['alert']}
  let loginBody = {enabled:true,match:{platforms:['linux'],window_sec:60,failure_threshold:3,cooldown_sec:1,block_duration_sec:10,ssh_ports:[2222],trusted_ips:[],user_exclude:[],off_hours_enabled:false,allowed_start_hour:8,allowed_end_hour:20,timezone:'UTC'},actions:['alert']}
  async function count(type) { return (await alerts(type)).reduce((sum,row)=>sum+Number(row.count),0) }
  async function newEvent(type,before,action) {
    let result
    await until(async()=>{
      const rows = await alerts(type)
      result = rows.find(r=>r.action_taken===action)
      return rows.reduce((n,r)=>n+Number(r.count),0)>before && result
    },`${type} did not report ${action}`,45_000)
    assert.ok(JSON.parse(result.detail).fingerprint,'Aggregation fingerprint was lost')
    return result
  }
  async function logLines({failed=true,ip=sourceIP,user='root',n=3,method='password'}={}) {
    const stamp = new Date().toISOString()
    writeFileSync(join(fixture,'ssh.log'),Array.from({length:n},(_,i)=>`${stamp} fixture sshd[${500+i}]: ${failed?'Failed':'Accepted'} ${method} for ${user} from ${ip} port ${45000+i} ssh2\n`).join(''))
    await dex('sh','-c','cat /fixtures/ssh.log >> /var/log/auth.log')
  }
  try {
    await rule('PR-0002',fileBody,'file_rules')
    await until(()=>exists(baseline),'File baseline not captured')
    let before = await count('file_tamper')
    writeFileSync(file,'ALERT ONLY\n')
    const alerted = await newEvent('file_tamper',before,'alert_only')
    assert.equal(readFileSync(file,'utf8'),'ALERT ONLY\n')
    assert.ok(!alerted.detail.includes('ORIGINAL') && !alerted.detail.includes('ALERT ONLY'),'Event leaked file contents')
    before = await count('file_tamper'); await delay(6000); assert.equal(await count('file_tamper'),before)
    pass('file change alert, content privacy and repeated-change suppression')

    before = await count('file_tamper'); fileBody.actions=['alert','restore']; await rule('PR-0002',fileBody,'file_rules')
    await newEvent('file_tamper',before,'restored')
    assert.equal(readFileSync(file,'utf8'),'ORIGINAL\n')
    assert.equal(await dex('stat','-c','%a',containerPath),'640')
    for (const mutation of ['delete','symlink']) {
      before = await count('file_tamper')
      await dex('rm','-f',containerPath)
      if (mutation==='symlink') {
        writeFileSync(join(work,'outside'),'OUTSIDE\n')
        await dex('ln','-s','/work/outside',containerPath)
      }
      await newEvent('file_tamper',before,'restored')
      assert.equal(readFileSync(file,'utf8'),'ORIGINAL\n')
      if (mutation==='symlink') assert.equal(readFileSync(join(work,'outside'),'utf8'),'OUTSIDE\n')
    }
    before = await count('file_tamper'); await command('docker',['stop','--timeout','5',agent.container])
    writeFileSync(file,'CHANGED DURING RESTART\n'); await restart()
    await newEvent('file_tamper',before,'restored'); assert.equal(readFileSync(file,'utf8'),'ORIGINAL\n')
    pass('real file restoration preserves permissions, replaces symlink safely and survives Agent restart')

    await rule('PR-0002',{enabled:false},'file_rules'); await until(async()=>!await exists(baseline),'Disabled baseline not removed')
    before = await count('file_tamper'); writeFileSync(file,'APPROVED\n'); await delay(6000)
    assert.equal(await count('file_tamper'),before)
    await rule('PR-0002',{enabled:true},'file_rules'); await until(()=>exists(baseline),'Fresh baseline not captured')
    writeFileSync(file,'TAMPERED\n'); await newEvent('file_tamper',before,'restored'); assert.equal(readFileSync(file,'utf8'),'APPROVED\n')
    pass('disabled file rule permits approved changes and re-enabling captures a fresh baseline')

    before = await count('file_tamper')
    await dex('mv','/work/protected-test','/work/protected-test-original')
    mkdirSync(join(work,'protected-test'))
    writeFileSync(file,'UNRELATED\n')
    const replaced = await newEvent('file_tamper',before,'restore_failed')
    assert.equal(JSON.parse(replaced.detail).change,'parent_changed')
    assert.equal(readFileSync(file,'utf8'),'UNRELATED\n')
    pass('replaced parent directory refuses restoration without changing unrelated contents')

    await rule('PR-0003',loginBody,'login_rules')
    before = await count('login_crack'); await logLines({n:2}); await delay(6500)
    assert.equal(await count('login_crack'),before)
    await logLines({n:1}); await newEvent('login_crack',before,'alert_only')
    pass('actual SSH log collection triggers exactly at the configured brute-force threshold')

    loginBody.match.trusted_ips=[sourceIP]; loginBody.match.user_exclude=['backup']; await rule('PR-0003',loginBody,'login_rules')
    before = await count('login_crack'); await logLines(); await logLines({ip:'203.0.113.44',user:'backup'}); await delay(6500)
    assert.equal(await count('login_crack'),before)
    pass('SSH trusted-source and excluded-account policies suppress detection')

    loginBody.match.trusted_ips=[]; loginBody.actions=['alert','block_ip']; loginBody.match.block_duration_sec=20
    await rule('PR-0003',loginBody,'login_rules'); if(probe) await probe(true)
    before = await count('login_crack'); await logLines(); await newEvent('login_crack',before,'blocked_ip')
    assert.match(await dex('iptables','-S','ALINKSEC_LOGIN'),new RegExp(sourceIP.replaceAll('.','\\.')+'(?:/32)? .*--dport 2222 .*DROP'))
    if(probe) await probe(false)
    const originalExpiry = Object.values((await state('login-protection.json')).blocks)[0].expires
    await restart()
    assert.match(await dex('iptables','-S','ALINKSEC_LOGIN'),/--dport 2222 .*DROP/)
    assert.equal(Object.values((await state('login-protection.json')).blocks)[0].expires,originalExpiry)
    await until(async()=>!((await dex('iptables','-S','ALINKSEC_LOGIN')).includes('--dport 2222')),'SSH source block did not expire',35_000)
    if(probe) await probe(true)
    pass('real SSH-port firewall block, restart persistence and automatic expiry')

    before = await count('login_crack'); await logLines(); await newEvent('login_crack',before,'blocked_ip')
    loginBody.match.trusted_ips=[sourceIP]; await rule('PR-0003',loginBody,'login_rules')
    await until(async()=>!((await dex('iptables','-S','ALINKSEC_LOGIN')).includes('--dport 2222')),'Allowlist did not release SSH source')
    if(probe) await probe(true)
    pass('adding a trusted source immediately releases its active firewall block')

    const hour = new Date().getUTCHours()
    loginBody.actions=['alert']; loginBody.match.trusted_ips=[]; loginBody.match.off_hours_enabled=true
    loginBody.match.allowed_start_hour=(hour+2)%24; loginBody.match.allowed_end_hour=(hour+3)%24
    await rule('PR-0003',loginBody,'login_rules'); before=await count('login_anomaly')
    await logLines({failed:false,n:1,method:'gssapi-with-mic'}); await newEvent('login_anomaly',before,'alert_only')
    loginBody.match.allowed_start_hour=0;loginBody.match.allowed_end_hour=24; await rule('PR-0003',loginBody,'login_rules')
    before=await count('login_anomaly'); await logLines({failed:false,n:1}); await delay(6500)
    assert.equal(await count('login_anomaly'),before)
    pass('actual successful SSH log produces off-hours alert and no alert during allowed hours')
  } finally {
    for (const original of originals) await api(`/api/protect/rules/${original.rule_id}`,{enabled:original.enabled,match:original.match,actions:original.actions},'PUT')
  }
}
