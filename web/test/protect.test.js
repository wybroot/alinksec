import test from 'node:test'
import assert from 'node:assert/strict'
import { fetchProtect, fetchAlerts, fetchDashboard, fetchScreen } from '../src/api/index.js'

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

test('Agent critical ransomware alerts remain critical in lists, filters and summary totals', async () => {
  const oldFetch = globalThis.fetch
  const oldStorage = globalThis.localStorage
  globalThis.localStorage = { getItem: () => null }
  const alert = { id: 1, severity: 5, event_type: 'ransom_behavior', title: '勒索加密行为', detail: '{}' }
  globalThis.fetch = async path => {
    const data = path.startsWith('/api/alerts?') ? { list: [alert] }
      : path === '/api/dashboard/summary' ? { alerts: { bySeverity: [{ severity: 4, count: 2 }, { severity: 5, count: 3 }] } }
      : []
    return { ok: true, status: 200, json: async () => ({ code: 0, data }) }
  }
  try {
    const alerts = await fetchAlerts(), dashboard = await fetchDashboard(), screen = await fetchScreen()
    assert.equal(alerts[0].sev, 'critical')
    assert.equal(alerts.filter(a => a.sev === 'critical').length, 1)
    assert.equal(dashboard.events[0].sev, 'critical')
    assert.equal(screen.events[0].sev, 'critical')
    assert.equal(dashboard.stats.crit, 5)
    assert.equal(screen.kpi.crit, 5)
    assert.equal(dashboard.sevDist.find(s => s.name === '严重').value, 5)
    assert.equal(screen.sevPie.find(s => s.name === '严重').value, 5)
  } finally {
    globalThis.fetch = oldFetch
    globalThis.localStorage = oldStorage
  }
})
