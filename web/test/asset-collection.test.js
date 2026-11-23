import test from 'node:test'
import assert from 'node:assert/strict'
import { collectionEmptyLabel, collectionTime, formatAssetBytes } from '../src/utils/asset-collection.js'
import { fetchHostDetail } from '../src/api/index.js'

test('an absent, failed or partial observation cannot confirm an empty inventory', () => {
  for (const state of [undefined, {}, { status: 'failed' }, { status: 'partial' }, { status: 'legacy' }, { status: 'unsupported' }]) {
    assert.match(collectionEmptyLabel(state, 'confirmed empty'), /不能据此判断资产为空/)
  }
  assert.equal(collectionEmptyLabel({ status: 'complete' }, 'confirmed empty'), 'confirmed empty')
  for (const value of [0, -1, undefined, 'bad', Infinity, 8640000000000001]) assert.equal(collectionTime(value), '未知')
  assert.equal(collectionTime(1000), '1970-01-01 00:00:01 UTC')
  assert.equal(formatAssetBytes(1024 ** 3), '1.0 GiB')
})

test('host detail includes the disk inventory and surfaces a failed disk read', async () => {
  const oldFetch=globalThis.fetch, oldStorage=globalThis.localStorage
  let fail=false
  globalThis.localStorage={getItem:()=>null}
  globalThis.fetch=async path=>({ok:!fail || !path.endsWith('/disks'),status:503,
    json:async()=>({code:0,data:path.endsWith('/disks')?[{mount:'/data',total_bytes:1000,used_bytes:400}]:[]})})
  try {
    assert.deepEqual((await fetchHostDetail('host')).disks,[{mount:'/data',total_bytes:1000,used_bytes:400}])
    fail=true
    await assert.rejects(fetchHostDetail('host'))
  } finally {globalThis.fetch=oldFetch;globalThis.localStorage=oldStorage}
})
