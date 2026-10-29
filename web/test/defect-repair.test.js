import test from 'node:test'
import assert from 'node:assert/strict'
import { fetchAlertPage, handleAlert, fetchHosts, fetchGroups, assignHostGroup } from '../src/api/index.js'

test('alert queries filter on server and preserve total and distinct record states', async () => {
 const oldFetch=globalThis.fetch, oldStorage=globalThis.localStorage
 globalThis.localStorage={getItem:()=>null}
 const requests=[]
 globalThis.fetch=async (path,options)=>{requests.push({path,options});return {ok:true,status:200,json:async()=>({code:0,data:{total:103,list:[{id:101,status:1},{id:102,status:2},{id:103,status:3}]}})}}
 try {
  const result=await fetchAlertPage({page:2,tab:'open'})
  assert.equal(result.total,103);assert.equal(result.list[0].done,false)
  assert.deepEqual(result.list.map(row=>row.statusLabel),['跟进中','已确认记录','已忽略'])
  const query=new URL(requests[0].path,'http://localhost').searchParams
  assert.equal(query.get('page'),'2');assert.equal(query.get('status'),'-1')
  await fetchAlertPage({tab:'high'})
  assert.match(requests[1].path,/severity=3/);assert.match(requests[1].path,/exactSeverity=true/)
  await handleAlert(101,'ignored','ignore')
  assert.deepEqual(JSON.parse(requests[2].options.body),{remark:'ignored',resolution:'ignore'})
 } finally {globalThis.fetch=oldFetch;globalThis.localStorage=oldStorage}
})

test('group identity survives listing and ungrouped filter is explicit', async()=>{
 const oldFetch=globalThis.fetch, oldStorage=globalThis.localStorage
 globalThis.localStorage={getItem:()=>null};const requests=[]
 globalThis.fetch=async(path,options)=>{requests.push({path,options});return {ok:true,status:200,json:async()=>({code:0,data:path.endsWith('/groups')?[{id:7,name:'A',host_count:1}]:{total:1,list:[{agent_id:'a',group_id:7,group_name:'A'}]}})}}
 try {
  const r=await fetchHosts({groupId:0});assert.match(requests[0].path,/groupId=0/);assert.equal(r.list[0].group,'A');assert.equal(r.list[0].groupId,7)
  assert.equal((await fetchGroups())[0].id,7)
  await assignHostGroup('a',7);assert.deepEqual(JSON.parse(requests[2].options.body),{groupId:7})
 }finally{globalThis.fetch=oldFetch;globalThis.localStorage=oldStorage}
})
