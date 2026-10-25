import test from 'node:test'
import assert from 'node:assert/strict'
import { fetchAlerts, fetchDashboard, fetchScreen, fetchProtect } from '../src/api/index.js'

test('source-aware levels remain consistent across alerts, dashboard, screen and blocks', async () => {
  const oldFetch=globalThis.fetch, oldStorage=globalThis.localStorage
  const rows=[
    {severity:4,severity_level:3,severity_source:'agent_proto_v1'},
    {severity:4,severity_level:4,severity_source:'legacy_unclassified'},
    {severity:3,severity_level:2,severity_source:'agent_proto_v1'},
    {severity:1,severity_level:0,severity_source:'agent_proto_v1'},
    {severity:99,severity_level:-1,severity_source:'agent_proto_v1'},
  ].map((r,i)=>({...r,id:i,title:'row '+i,detail:'{}'}))
  globalThis.localStorage={getItem:()=>null}
  globalThis.fetch=async path=>({ok:true,status:200,json:async()=>({code:0,data:
    path.startsWith('/api/alerts?')?{list:rows}:
    path.startsWith('/api/protect/blocks')?rows:
    path==='/api/dashboard/summary'?{alerts:{bySeverity:rows.map(r=>({severity:r.severity_level,count:1}))}}:[]
  })})
  try {
    const alerts=await fetchAlerts(), dashboard=await fetchDashboard(), screen=await fetchScreen(), protect=await fetchProtect()
    for(const list of [alerts,dashboard.events,screen.events]) {
      assert.deepEqual(list.map(r=>r.sev),['high','critical','medium','info','unknown'])
      assert.deepEqual(list.map(r=>r.legacySeverity),[false,true,false,false,false])
    }
    assert.deepEqual(protect.blocks.map(r=>r.severity),['high','critical','medium','info','unknown'])
    assert.equal(dashboard.stats.crit,1);assert.equal(screen.kpi.crit,1)
    for(const list of [dashboard.sevDist,screen.sevPie]) {
      assert.equal(list.find(r=>r.name==='信息').value,1);assert.equal(list.find(r=>r.name==='未知').value,1)
      assert.equal(list.find(r=>r.name==='高危').value,1)
    }
  } finally {globalThis.fetch=oldFetch;globalThis.localStorage=oldStorage}
})
