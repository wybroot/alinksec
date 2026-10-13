import test from 'node:test'
import assert from 'node:assert/strict'
import { createPackageFixTask, fetchVulns } from '../src/api/index.js'

test('missing and unsupported execution capabilities retain findings but cannot enter single or batch repairs', async () => {
  const oldFetch = globalThis.fetch, oldStorage = globalThis.localStorage
  globalThis.localStorage = { getItem: () => null }
  const base = { agent_id: 'a', cve_id: 'CVE-2026-12345', software: 'fixture', installed_version: '1.0', fixed_version: '2.0', severity: 3, status: 0,
    identity_status: 'complete', identity_current: 1, rule_source_id: 'manual', rule_digest: 'a'.repeat(64), evidence_status: 'declared', rule_current: 1 }
  const list = [{ ...base, id: 1, execution_supported: 1 }, { ...base, id: 2, execution_supported: 0 }, { ...base, id: 3 }, { ...base, id: 4, execution_supported: 2 }]
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({ code: 0, data: { list } }) })
  try {
    const rows = await fetchVulns()
    assert.equal(rows.length, 1); assert.equal(rows[0].blocked, 3); assert.equal(rows[0].executionUnsupported, 3)
    assert.deepEqual(rows.flatMap(r => r.findings), [{ agentId: 'a', findingId: 1 }])
  } finally { globalThis.fetch = oldFetch; globalThis.localStorage = oldStorage }
})

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
        ].map(f => ({ ...f, source: 'dpkg', architecture: 'amd64', distro_id: 'ubuntu', distro_version: '24.04', identity_status: 'complete', identity_current: 1, execution_supported: 1,
          rule_source_id: 'manual', rule_digest: 'a'.repeat(64), evidence_status: 'declared', rule_current: 1 })) }
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

test('aggregation separates package identities and installed versions, counts agents once and excludes stale or legacy repairs across pages', async () => {
  const oldFetch = globalThis.fetch, oldStorage = globalThis.localStorage
  globalThis.localStorage = { getItem: () => null }
  const base = { id: 1, agent_id: 'a', hostname: 'same-hostname', cve_id: 'CVE-2026-12345', software: 'fixture',
    installed_version: '1.0', fixed_version: '2.0', source: 'dpkg', architecture: 'amd64', distro_id: 'ubuntu', distro_version: '24.04',
    os_type: 1, os_version: 'Ubuntu', identity_status: 'complete', identity_current: 1, execution_supported: 1, status: 0, severity: 3,
    rule_source_id: 'manual', rule_digest: 'a'.repeat(64), evidence_status: 'declared', rule_current: 1 }
  const records = [base, { ...base, id: 2 }, { ...base, id: 3, agent_id: 'b' }, { ...base, id: 4, architecture: 'i386' },
    { ...base, id: 5, distro_id: 'debian' }, { ...base, id: 6, distro_version: '22.04' },
    { ...base, id: 7, source: 'rpm' }, { ...base, id: 8, installed_version: '1.1' },
    { ...base, id: 9, identity_status: 'legacy', identity_current: 0 }, { ...base, id: 10, identity_current: 0 }]
  const paths = []
  globalThis.fetch = async path => {
    paths.push(path)
    const list = path.includes('page=1&') ? records.slice(0, 4) : [...records.slice(4), base]
    return { ok: true, status: 200, json: async () => ({ code: 0, data: { list, total: records.length } }) }
  }
  try {
    const rows = await fetchVulns()
    assert.equal(paths.length, 2)
    assert.equal(rows.length, 7)
    assert.equal(rows[0].hosts, 2)
    assert.equal(rows[0].blocked, 1)
    assert.deepEqual(rows[0].findings.map(f => f.findingId), [1, 2, 3])
    const legacy = rows.find(row => row.identityStatus === 'legacy')
    assert.equal(legacy.findings.length, 0)
    assert.equal(legacy.blocked, 1)
    assert.equal(rows.filter(row => row.architecture === 'i386').length, 1)
    assert.equal(rows.filter(row => row.cur === '1.1').length, 1)
  } finally { globalThis.fetch = oldFetch; globalThis.localStorage = oldStorage }
})
test('different rule origins and digests stay separate, and stale, conflicting or missing evidence cannot be repaired', async () => {
  const oldFetch = globalThis.fetch, oldStorage = globalThis.localStorage
  globalThis.localStorage = { getItem: () => null }
  const base = { id: 1, agent_id: 'a', hostname: 'a', cve_id: 'CVE-2026-12345', software: 'fixture', installed_version: '1.0', fixed_version: '2.0', severity: 3, status: 0,
    identity_status: 'complete', identity_current: 1, execution_supported: 1, rule_source_id: 'manual', rule_digest: 'a'.repeat(64), evidence_status: 'declared', rule_current: 1,
    rule_evidence: JSON.stringify({ import: { source_id: 'manual', verification: 'imported_declaration' }, rules: [{ evidence: { basis: 'manual_analysis', notes: 'fixture' } }] }) }
  const records = [base, { ...base, id: 2, rule_current: 0 }, { ...base, id: 3, rule_digest: 'b'.repeat(64) },
    { ...base, id: 4, rule_source_id: 'provider' }, { ...base, id: 5, evidence_status: 'conflicting' },
    { ...base, id: 6, evidence_status: 'legacy', rule_digest: '', rule_source_id: '', rule_evidence: 'invalid JSON' }]
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => ({ code: 0, data: { list: records, total: records.length } }) })
  try {
    const rows = await fetchVulns()
    assert.equal(rows.length, 5)
    assert.equal(rows[0].blocked, 1)
    assert.deepEqual(rows[0].findings, [{ agentId: 'a', findingId: 1 }])
    assert.equal(rows[0].ruleEvidence.import.source_id, 'manual')
    assert.equal(rows.find(row => row.evidenceStatus === 'conflicting').findings.length, 0)
    const legacy = rows.find(row => row.evidenceStatus === 'legacy')
    assert.equal(legacy.findings.length, 0); assert.deepEqual(legacy.ruleEvidence, {})
  } finally { globalThis.fetch = oldFetch; globalThis.localStorage = oldStorage }
})
