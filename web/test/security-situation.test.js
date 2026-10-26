import test from 'node:test'
import assert from 'node:assert/strict'
import { eventEvidence, located, situationStats } from '../src/utils/securitySituation.js'
import { greatCircle, project, vector } from '../src/utils/globeGeometry.js'
const ip = { status: 'located', provider: 'ipip', latitude: 39.12, longitude: 117.29 }
const asset = { status: 'located', provider: 'asset_inventory', latitude: 31.23, longitude: 121.47 }
test('local alerts cannot be promoted to network attacks by an incidental IP or coordinates', () => {
  const event=eventEvidence({event_type:'file_tamper',detail:'{"source_ip":"8.8.8.8","latitude":39,"longitude":117}'})
  assert.equal(event.network,false);assert.equal(event.sourceIp,'');assert.equal(located(event.sourceLocation),false)
  assert.deepEqual(situationStats([event]),{attacks:0,network:0,routes:0,located:0,local:1})
})
test('SSH brute force and web attacks retain their observed sources, including missing-source attacks', () => {
  const metadata={source:{ip:'8.8.8.8',location:{...ip,provider:'dbip'}},target:{agentId:'host',location:asset}}
  for(const event_type of ['login_crack','ssh_bruteforce','web_attack','sql_injection','xss','rce','ssrf','path_traversal','command_injection','file_inclusion','webshell_attack','port_scan','credential_stuffing']) {
    const event=eventEvidence({agent_id:'host',event_type,detail:{source_ip:'8.8.8.8'}},metadata)
    assert.equal(event.network,true,event_type);assert.equal(event.sourceIp,'8.8.8.8');assert.equal(situationStats([event]).routes,1)
    const unknown=eventEvidence({event_type,detail:{request:'GET /?source_ip=8.8.8.8',headers:{'X-Forwarded-For':'8.8.8.8'}}})
    assert.equal(situationStats([unknown]).attacks,1);assert.equal(unknown.sourceIp,'');assert.equal(situationStats([unknown]).routes,0)
  }
  const ssh=eventEvidence({event_type:'login_crack',detail:{source_ip:'8.8.8.8',trigger:'ssh_bruteforce'}})
  assert.equal(ssh.attackLabel,'SSH 暴力破解')
})
test('network geolocation must match the observed source and authenticated target identity', () => {
  const alert={id:1,agent_id:'real-agent',event_type:'login_crack',detail:'{"source_ip":"8.8.8.8"}',count:3,last_time:'2026-10-26 08:00:00'}
  const meta={source:{ip:'8.8.8.8',location:ip},target:{agentId:'real-agent',location:asset}}
  const event=eventEvidence(alert,meta)
  assert.equal(situationStats([event]).routes,1); assert.equal(event.count,3)
  assert.equal(located(eventEvidence(alert,{...meta,source:{...meta.source,ip:'8.8.4.4'}}).sourceLocation),false)
  assert.equal(located(eventEvidence(alert,{...meta,target:{...meta.target,agentId:'other'}}).targetLocation),false)
  assert.equal(located(eventEvidence({...alert,host_ip:'10.2.3.4'},{...meta,target:{...meta.target,ip:'10.2.3.5'}}).targetLocation),false)
  assert.equal(located({...ip,latitude:null}),false);assert.equal(located({...ip,longitude:181}),false);assert.equal(located({...ip,provider:'random'}),false)
  assert.equal(located({...ip,latitude:0,longitude:0}),true)
})
test('missing and malformed detail remain unknown without inventing a location', () => {
  for (const detail of [null,'broken',[],{},'null']) {
    const event=eventEvidence({event_type:'login_crack',detail})
    assert.equal(event.sourceIp,'');assert.equal(situationStats([event]).routes,0)
  }
})
test('surface endpoints and arc endpoints remain attached during rotation with far-side occlusion', () => {
  const start=vector([117.29,39.12]), end=vector([121.47,31.23])
  for (const rotation of [0,.5,1,Math.PI]) {
    const a=project(start,rotation), b=project(greatCircle(start,end,0),rotation)
    const c=project(end,rotation), d=project(greatCircle(start,end,1),rotation)
    for(const k of ['x','y','depth']) { assert.ok(Math.abs(a[k]-b[k])<1e-10);assert.ok(Math.abs(c[k]-d[k])<1e-10) }
  }
  assert.notEqual(project(start,0).x,project(start,.5).x)
  assert.equal(project(vector([180,0]),0,0).visible,false);assert.equal(project(vector([0,0]),0,0).visible,true)
  for(const pair of [[[0,0],[180,0]],[[0,0],[0,0]]]) {
    for(const t of [0,.25,.5,.75,1]) assert.ok(greatCircle(vector(pair[0]),vector(pair[1]),t).every(Number.isFinite))
  }
})
