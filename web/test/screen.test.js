import test from 'node:test'
import assert from 'node:assert/strict'
import { fetchScreen } from '../src/api/index.js'

test('screen host switch counts come from the complete summary and engine entries remain capabilities', async (t) => {
  const data = {
    '/api/dashboard/summary': {
      hosts: { online: 8, total: 100, protectOn: 73 },
      virus: { findings30d: 91 },
    },
    '/api/alerts': { list: Array.from({ length: 20 }, (_, id) => ({ id, action_taken: 'alert_only' })) },
    '/api/protect/engines': [{ key: 'process', name: '恶意进程防护', desc: '按规则检测进程', builtin: true }],
  }
  const paths = []
  const storage = Object.getOwnPropertyDescriptor(globalThis, 'localStorage')
  Object.defineProperty(globalThis, 'localStorage', { configurable: true, value: { getItem: () => null } })
  t.after(() => { if (storage) Object.defineProperty(globalThis, 'localStorage', storage); else delete globalThis.localStorage })
  t.mock.method(globalThis, 'fetch', async path => {
    paths.push(path)
    return { ok: true, status: 200, json: async () => ({ code: 0, data: data[path.split('?')[0]] ?? [] }) }
  })
  const screen = await fetchScreen()
  assert.equal(screen.kpi.protectOn, 73)
  assert.equal(screen.kpi.virus, 91)
  assert.equal(screen.kpi.compliance, null)
  assert.equal('rtHit' in screen.kpi, false, 'a recent alert page cannot establish automatic response totals')
  assert.equal(paths.includes('/api/protect/status'), false, 'avoid a full host list solely to recount summary data')
  assert.deepEqual(screen.engines, [{ key: 'process', name: '恶意进程防护', desc: '按规则检测进程', builtin: true }])
  assert.equal('on' in screen.engines[0], false, 'the engine catalog supplies no runtime evidence')
  data['/api/dashboard/summary'].hosts.protectOn = 0
  data['/api/dashboard/summary'].baseline = { avgScore: 0, hostsChecked: 3 }
  const zero = await fetchScreen()
  assert.equal(zero.kpi.protectOn, 0)
  assert.equal(zero.kpi.compliance, 0, 'an actual zero score differs from missing results')
  assert.equal(zero.kpi.hostsChecked, 3)
})
