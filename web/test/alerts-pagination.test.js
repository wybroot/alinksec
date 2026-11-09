import test from 'node:test'
import assert from 'node:assert/strict'
import {fetchAlertPage,fetchScreen} from '../src/api/index.js'

test('alert pagination retains totals and sends filters to the server',async()=>{
 const oldFetch=globalThis.fetch,oldStorage=globalThis.localStorage
 globalThis.localStorage={getItem:()=>null}
 const urls=[]
 globalThis.fetch=async path=>{urls.push(path);return {ok:true,status:200,json:async()=>({code:0,data:{list:[{id:101,severity_level:4,detail:'{}'}],total:205}})}}
 try {
  const data=await fetchAlertPage({page:2,size:100,tab:'open'})
  assert.equal(data.total,205);assert.equal(data.list[0].id,101)
  const query=new URL(urls.at(-1),'http://local').searchParams
  assert.equal(query.get('page'),'2');assert.equal(query.get('status'),'-1')
  await fetchAlertPage({tab:'high'})
  assert.match(urls.at(-1),/severity=3/);assert.match(urls.at(-1),/maxSeverity=3/)
 }finally{globalThis.fetch=oldFetch;globalThis.localStorage=oldStorage}
})
test('screen uses complete backend aggregate and never infers engine readiness from main switches',async()=>{
 const oldFetch=globalThis.fetch,oldStorage=globalThis.localStorage
 globalThis.localStorage={getItem:()=>null}
 globalThis.fetch=async path=>({ok:true,status:200,json:async()=>({code:0,data:path==='/api/dashboard/summary'?{hosts:{total:20,online:20},alerts:{automated30d:57}}:path==='/api/protect/engines'?[{key:'decoy',name:'decoy',status:'unknown'}]:path==='/api/protect/status'?[{protect_enabled:true}]:path.startsWith('/api/alerts?')?{list:[{action_taken:'alert_only'}]}:[]})})
 try{const data=await fetchScreen();assert.equal(data.kpi.rtHit,57);assert.equal(data.engines[0].on,false);assert.equal(data.engines[0].status,'unknown')}finally{globalThis.fetch=oldFetch;globalThis.localStorage=oldStorage}
})
