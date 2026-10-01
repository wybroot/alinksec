import test from 'node:test'
import assert from 'node:assert/strict'
import { fetchProtect } from '../src/api/index.js'

test('protection cards show engine details and recent blocks without editable state', async () => {
  const oldFetch = globalThis.fetch
  const oldStorage = globalThis.localStorage
  const paths = []
  globalThis.localStorage = { getItem: () => null }
  globalThis.fetch = async (path) => {
    paths.push(path)
    const data = path.endsWith('/engines')
      ? [{ key: 'process', name: '进程防护', desc: '进程行为规则' }]
      : [{ id: 1, title: '已阻断异常进程', severity: 4, last_time: '2026-10-01T12:34:00Z' }]
    return { ok: true, status: 200, json: async () => ({ code: 0, data }) }
  }

  try {
    const result = await fetchProtect()
    assert.deepEqual(paths, ['/api/protect/engines', '/api/protect/blocks?limit=6'])
    assert.deepEqual(result.cards, [{ title: '进程防护', desc: '进程行为规则' }])
    assert.equal(result.blocks[0].title, '已阻断异常进程')
    assert.equal(result.blocks[0].severity, 'critical')
    assert.match(result.blocks[0].time, /^10-01 \d{2}:34$/)
  } finally {
    globalThis.fetch = oldFetch
    globalThis.localStorage = oldStorage
  }
})
