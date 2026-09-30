import test from 'node:test'
import assert from 'node:assert/strict'
import { createPackageFixTask, fetchVulns } from '../src/api/index.js'

test('single and batch package fixes keep each agent finding pair', async () => {
  const oldFetch = globalThis.fetch
  const oldStorage = globalThis.localStorage
  const requests = []
  globalThis.localStorage = { getItem: () => null }
  globalThis.fetch = async (path, options) => {
    requests.push({ path, options })
    const data = path.startsWith('/api/vuln/findings')
      ? { list: [
          { id: 11, agent_id: 'agent-a', hostname: 'host-a', cve_id: 'CVE-1', software: 'openssl', fixed_version: '3.0.2', installed_version: '3.0.1', severity: 3, status: 0 },
          { id: 12, agent_id: 'agent-b', hostname: 'host-b', cve_id: 'CVE-1', software: 'openssl', fixed_version: '3.0.2', installed_version: '3.0.1', severity: 3, status: 1 },
          { id: 13, agent_id: 'agent-c', hostname: 'host-c', cve_id: 'CVE-1', software: 'openssl', fixed_version: '3.0.2', installed_version: '3.0.1', severity: 3, status: 3 },
          { id: 14, agent_id: 'agent-d', hostname: 'host-d', cve_id: 'CVE-1', software: 'libssl', fixed_version: '3.0.2', installed_version: '3.0.1', severity: 3, status: 0 },
        ] }
      : { taskId: 42 }
    return { ok: true, status: 200, json: async () => ({ code: 0, data }) }
  }

  try {
    const rows = await fetchVulns()
    assert.equal(rows.length, 2)
    assert.equal(rows[0].target, '3.0.2')
    assert.equal(rows[0].hosts, 3)
    assert.deepEqual(rows[0].findings, [
      { agentId: 'agent-a', findingId: 11 },
      { agentId: 'agent-b', findingId: 12 },
    ])
    assert.deepEqual(rows[1].findings, [{ agentId: 'agent-d', findingId: 14 }])

    await createPackageFixTask(rows[0].findings, { approver: 'admin' })
    await createPackageFixTask(rows.flatMap(row => row.findings), { approver: 'admin' })
    assert.deepEqual(JSON.parse(requests[1].options.body).items, rows[0].findings)
    assert.deepEqual(JSON.parse(requests[2].options.body).items, [
      ...rows[0].findings, ...rows[1].findings,
    ])
  } finally {
    globalThis.fetch = oldFetch
    globalThis.localStorage = oldStorage
  }
})
