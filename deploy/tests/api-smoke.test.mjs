import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import { after, before, test } from 'node:test'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

const mode = process.env.ALINKSEC_SMOKE_DB
assert.ok(['postgres', 'sqlite'].includes(mode), 'Set ALINKSEC_SMOKE_DB to postgres or sqlite')
assert.equal(process.env.ALINKSEC_SMOKE_ALLOW_FIXTURES, 'true', 'Run only against a disposable deployment')
const password = process.env.ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD
assert.ok(password, 'Set ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD')
const baseUrl = new URL(process.env.ALINKSEC_SMOKE_BASE_URL || 'https://127.0.0.1:8443')
assert.ok(baseUrl.protocol === 'https:' || (baseUrl.protocol === 'http:'
  && ['127.0.0.1', 'localhost', '[::1]'].includes(baseUrl.hostname)),
  'Use HTTPS, or loopback HTTP for local validation')
const ca = baseUrl.protocol === 'https:' ? readFileSync(process.env.ALINKSEC_SMOKE_CA_FILE) : undefined
const transport = baseUrl.protocol === 'https:' ? https : http
const sqliteFile = process.env.ALINKSEC_SMOKE_SQLITE_FILE
if (sqliteFile) {
  assert.equal(mode, 'sqlite', 'ALINKSEC_SMOKE_SQLITE_FILE requires SQLite mode')
  assert.ok(existsSync(sqliteFile), 'The disposable SQLite database must already exist')
}
const DatabaseSync = sqliteFile ? (await import('node:sqlite')).DatabaseSync : undefined
const composeFile = fileURLToPath(new URL(
  mode === 'sqlite' ? '../docker/docker-compose.lite.yml' : '../docker/docker-compose.yml', import.meta.url))
const composeArgs = ['compose']
if (process.env.ALINKSEC_SMOKE_ENV_FILE) composeArgs.push('--env-file', process.env.ALINKSEC_SMOKE_ENV_FILE)
composeArgs.push('-f', composeFile)

function sql(statement) {
  if (sqliteFile) {
    const database = new DatabaseSync(sqliteFile)
    try {
      database.exec('PRAGMA busy_timeout = 5000;')
      const query = database.prepare(statement)
      if (query.columns().length) {
        return query.all().map(row => Object.values(row).join('|')).join('\n')
      }
      database.exec(statement)
      return ''
    } finally {
      database.close()
    }
  }
  const args = mode === 'postgres'
    ? ['exec', '-T', 'postgres', 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'alinksec', '-d', 'alinksec', '-Atc', statement]
    : ['run', '--rm', '-T', '--no-deps', 'sqlite-maintenance', '/data/alinksec.db', statement]
  if (mode === 'postgres' && process.env.ALINKSEC_SMOKE_PG_CONTAINER) {
    const container = process.env.ALINKSEC_SMOKE_PG_CONTAINER
    assert.match(container, /^[a-zA-Z0-9][a-zA-Z0-9_.-]+$/)
    return execFileSync('docker', ['exec', container, 'psql', '-v', 'ON_ERROR_STOP=1', '-U', 'alinksec',
      '-d', 'alinksec', '-Atc', statement], { encoding: 'utf8', timeout: 60_000 }).trim()
  }
  return execFileSync('docker', [...composeArgs, ...args], { encoding: 'utf8', timeout: 60_000 }).trim()
}

function request(path, { token, method = 'GET', body } = {}) {
  return new Promise((resolve, reject) => {
    const payload = body === undefined ? undefined : JSON.stringify(body)
    const headers = {}
    if (token) headers.Authorization = `Bearer ${token}`
    if (payload) headers['Content-Type'] = 'application/json'
    const req = transport.request(new URL(path, baseUrl), { ca, method, headers }, res => {
      let text = ''
      res.setEncoding('utf8')
      res.on('data', chunk => { text += chunk })
      res.on('error', reject)
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(text) }) }
        catch { reject(new Error(`${method} ${path}: invalid JSON (HTTP ${res.statusCode})`)) }
      })
    })
    req.on('error', reject)
    req.setTimeout(10_000, () => req.destroy(new Error(`${method} ${path}: timeout`)))
    req.end(payload)
  })
}

async function ok(path, options) {
  const response = await request(path, options)
  assert.equal(response.status, 200, path)
  assert.equal(response.body.code, 0, `${path}: ${response.body.msg}`)
  return response.body.data
}

async function login(username) {
  return (await ok('/api/auth/login', { method: 'POST', body: { username, password } })).token
}

async function waitForSql(statement, expected) {
  for (let attempt = 0; attempt < 20; attempt++) {
    const actual = sql(statement)
    if (actual === expected) return
    if (attempt === 19) assert.equal(actual, expected, statement)
    await delay(250)
  }
}

const tokens = {}
let seeded = false
let auditStartId

before(async () => {
  // Reserve fixture names and refuse to overwrite data from an earlier run.
  assert.equal(sql("SELECT count(*) FROM t_agent WHERE agent_id LIKE 'ci-smoke-%';"), '0')
  assert.equal(sql("SELECT count(*) FROM t_user WHERE username LIKE 'ci-smoke-%';"), '0')
  assert.equal(sql("SELECT count(*) FROM t_scan_task WHERE task_no = 'ci-smoke-scan';"), '0')
  assert.equal(sql("SELECT count(*) FROM t_notify_channel WHERE name = 'ci-smoke-disabled-webhook';"), '0')
  auditStartId = sql('SELECT COALESCE(MAX(id), 0) FROM t_audit_log;')
  assert.match(auditStartId, /^\d+$/)
  const hosts = Array.from({ length: 105 }, (_, i) => {
    const suffix = String(i + 1).padStart(3, '0')
    return `('ci-smoke-${suffix}', 'ci-smoke-host-${suffix}', '10.20.0.${i + 1}', 1, ${i === 1 ? 2 : 1}, ${i === 0 ? 2 : 0}, CURRENT_TIMESTAMP)`
  }).join(',\n')
  sql(`BEGIN;
    INSERT INTO t_agent(agent_id, hostname, ip, os_type, status, isolation_status, last_heartbeat) VALUES ${hosts};
    INSERT INTO t_agent(agent_id, hostname, os_type, status) VALUES ('ci-smoke-deleted', 'ci-smoke-deleted', 1, 4);
    INSERT INTO t_user(username, password_hash, role_id, status)
      SELECT 'ci-smoke-' || r.name, u.password_hash, r.id, 1
      FROM t_role r CROSS JOIN t_user u WHERE u.username = 'admin' AND r.name IN ('operator', 'viewer');
    INSERT INTO t_asset_software(agent_id, name, version) VALUES ('ci-smoke-001', 'OpenSSH', '9.7');
    INSERT INTO t_scan_task(task_no, name, type, scope) VALUES ('ci-smoke-scan', 'CI smoke scan', 1, '{}');
    INSERT INTO t_vuln_finding(task_id, agent_id, cve_id, software, installed_version, fixed_version, severity, status)
      SELECT id, 'ci-smoke-001', 'CVE-2024-6387', 'openssh', '9.7', '9.8', 4, 0 FROM t_scan_task WHERE task_no = 'ci-smoke-scan';
    INSERT INTO t_vuln_finding(task_id, agent_id, cve_id, software, installed_version, fixed_version, severity, status)
      SELECT id, 'ci-smoke-002', 'CVE-2024-6387', 'openssh', '9.7', '9.8', 4, 1 FROM t_scan_task WHERE task_no = 'ci-smoke-scan';
    INSERT INTO t_vuln_finding(task_id, agent_id, cve_id, software, installed_version, fixed_version, severity, status)
      SELECT id, 'ci-smoke-003', 'CVE-2024-6387', 'openssh', '9.7', '9.8', 4, 3 FROM t_scan_task WHERE task_no = 'ci-smoke-scan';
    INSERT INTO t_vuln_finding(task_id, agent_id, cve_id, software, severity, status)
      SELECT id, 'ci-smoke-004', 'CVE-2024-6387', 'openssh', 4, 2 FROM t_scan_task WHERE task_no = 'ci-smoke-scan';
    COMMIT;`)
  seeded = true
  for (const role of ['admin', 'operator', 'viewer']) {
    tokens[role] = await login(role === 'admin' ? 'admin' : `ci-smoke-${role}`)
  }
})

after(() => {
  if (!seeded) return
  sql(`BEGIN;
    DELETE FROM t_command WHERE agent_id LIKE 'ci-smoke-%';
    DELETE FROM t_asset_software WHERE agent_id LIKE 'ci-smoke-%';
    DELETE FROM t_vuln_finding WHERE agent_id LIKE 'ci-smoke-%';
    DELETE FROM t_scan_task WHERE task_no = 'ci-smoke-scan';
    DELETE FROM t_agent WHERE agent_id LIKE 'ci-smoke-%';
    DELETE FROM t_notify_channel WHERE name = 'ci-smoke-disabled-webhook';
    DELETE FROM t_audit_log WHERE username IN ('ci-smoke-operator', 'ci-smoke-viewer');
    DELETE FROM t_user WHERE username IN ('ci-smoke-operator', 'ci-smoke-viewer');
    COMMIT;`)
})

test(`${mode}: health, authentication and JWT access`, async () => {
  await ok('/api/health')
  assert.equal((await request('/api/hosts')).status, 401)
  assert.equal((await request('/api/hosts', { token: 'invalid-token' })).status, 401)
  const wrongPassword = await request('/api/auth/login', {
    method: 'POST', body: { username: 'admin', password: 'incorrect-password' },
  })
  assert.equal(wrongPassword.body.code, 40101)
  await ok('/api/hosts', { token: tokens.admin })
})

test(`${mode}: host pagination, filters and durable isolation state`, async () => {
  const options = { token: tokens.admin }
  const first = await ok('/api/hosts?keyword=ci-smoke-&size=100&page=1', options)
  const second = await ok('/api/hosts?keyword=ci-smoke-&size=100&page=2', options)
  assert.equal(first.total, 105)
  assert.equal(first.list.length, 100)
  assert.equal(second.total, 105)
  assert.equal(second.list.length, 5)
  assert.equal(new Set([...first.list, ...second.list].map(row => row.agent_id)).size, 105)
  const laterHost = second.list[0].agent_id
  assert.match(laterHost, /^ci-smoke-\d{3}$/)
  assert.equal((await ok(`/api/hosts/${laterHost}`, options)).agent_id, laterHost)
  await ok(`/api/hosts/${laterHost}/collect`, { ...options, method: 'POST' })
  assert.equal(sql(`SELECT count(*) FROM t_command WHERE agent_id = '${laterHost}' AND type = 'collect_now';`), '1')
  const isolated = await ok('/api/hosts?keyword=CI-SMOKE-&status=1&isolationStatus=2', options)
  assert.equal(isolated.total, 1)
  assert.equal(isolated.list[0].agent_id, 'ci-smoke-001')
  const detail = await ok('/api/hosts/ci-smoke-001', options)
  assert.equal(detail.status, 1)
  assert.equal(detail.isolation_status, 2)
  assert.equal((await ok('/api/hosts?keyword=ci-smoke-&status=2', options)).total, 1)
})

test(`${mode}: host assets with absent, blank, trimmed and case-insensitive keywords`, async () => {
  for (const query of ['', '?keyword=', '?keyword=%20%20', '?keyword=OPENSSH', '?keyword=%20OPENSSH%20']) {
    const rows = await ok(`/api/hosts/ci-smoke-001/software${query}`, { token: tokens.admin })
    assert.equal(rows.length, 1, query)
    assert.equal(rows[0].name, 'OpenSSH')
  }
  const rows = await ok('/api/hosts/ci-smoke-001/software?keyword=missing', { token: tokens.admin })
  assert.deepEqual(rows, [])
})

test(`${mode}: pending and fixed vulnerability counts and target versions`, async () => {
  const options = { token: tokens.admin }
  const findings = await ok('/api/vuln/findings?keyword=OPENSSH', options)
  assert.equal(findings.total, 2)
  assert.ok(findings.list.every(row => row.fixed_version === '9.8'))
  const fixed = await ok('/api/vuln/findings?status=3&agentId=ci-smoke-003', options)
  assert.equal(fixed.total, 1)
  const stats = await ok('/api/vuln/stats', options)
  assert.equal(stats.pending, 2)
  assert.equal(stats.fixed, 1)
  assert.equal(stats.total, 3)
})

test(`${mode}: core dashboard and task queries`, async () => {
  for (const path of [
    '/api/dashboard/summary', '/api/dashboard/alert-trend?days=7',
    '/api/dashboard/screen-trend?days=7', '/api/dashboard/baseline-categories',
    '/api/baseline/templates', '/api/baseline/templates/1/items', '/api/baseline/tasks',
    '/api/vuln/tasks', '/api/vuln/ports', '/api/vuln/weakpwds',
    '/api/virus/tasks', '/api/virus/findings', '/api/virus/stats', '/api/fix/tasks',
  ]) await ok(path, { token: tokens.admin })
  const trend = await ok('/api/dashboard/alert-trend?days=7', { token: tokens.admin })
  assert.equal(trend.length, 7)
})

test(`${mode}: typed protection rules, persisted toggles and matching policy snapshot`, async () => {
  const options = { token: tokens.admin }
  const rules = await ok('/api/protect/rules', options)
  assert.ok(rules.length > 0)
  for (const rule of rules) {
    assert.equal(typeof rule.enabled, 'boolean')
    assert.equal(typeof rule.built_in, 'boolean')
    assert.equal(typeof rule.match, 'object')
    assert.ok(Array.isArray(rule.actions))
  }
  const rule = rules.find(row => row.type === 'process')
  assert.ok(rule, 'Expected a process protection rule')
  try {
    await ok(`/api/protect/rules/${rule.rule_id}`, { ...options, method: 'PUT', body: { enabled: !rule.enabled } })
    const updated = (await ok('/api/protect/rules', options)).find(row => row.rule_id === rule.rule_id)
    assert.equal(updated.enabled, !rule.enabled)
    const snapshot = JSON.parse(sql('SELECT CAST(content AS TEXT) FROM t_policy_state WHERE id=1;'))
    assert.equal(snapshot.process_rules.find(row => row.id === rule.rule_id).enabled, !rule.enabled)
  } finally {
    await ok(`/api/protect/rules/${rule.rule_id}`, { ...options, method: 'PUT', body: { enabled: rule.enabled } })
  }
})

test(`${mode}: role permissions and auditing of denied writes`, async () => {
  for (const role of ['viewer', 'operator']) {
    const token = tokens[role]
    await ok('/api/hosts', { token })
    for (const path of ['/api/audit/logs', '/api/notify/channels']) {
      assert.equal((await request(path, { token })).status, 403, `${role} ${path}`)
    }
    assert.equal((await request('/api/hosts/enroll-token', { token, method: 'POST' })).status, 403)
  }
  assert.equal((await request('/api/hosts/ci-smoke-001/collect', {
    token: tokens.viewer, method: 'POST',
  })).status, 403)
  await ok('/api/hosts/ci-smoke-001/collect', { token: tokens.operator, method: 'POST' })
  assert.equal(sql("SELECT count(*) FROM t_command WHERE agent_id = 'ci-smoke-001' AND type = 'collect_now';"), '1')
  // AuditFilter records the write after the response handler completes.
  await waitForSql("SELECT count(*) FROM t_audit_log WHERE username = 'ci-smoke-viewer' AND path = '/api/hosts/ci-smoke-001/collect' AND status = 403;", '1')
})

test(`${mode}: webhook credentials are absent from audit records`, async () => {
  const secret = 'ci-smoke-webhook-secret'
  const token = tokens.admin
  const channel = await ok('/api/notify/channels', {
    token, method: 'POST', body: {
      name: 'ci-smoke-disabled-webhook', webhookUrl: `https://notify.invalid/?token=${secret}`, enabled: false,
    },
  })
  try {
    await waitForSql(`SELECT count(*) FROM t_audit_log WHERE id > ${auditStartId} AND username = 'admin' AND method = 'POST' AND path = '/api/notify/channels' AND status = 200;`, '1')
    const audit = await ok('/api/audit/logs?path=%2Fapi%2Fnotify%2Fchannels', { token })
    assert.ok(audit.total >= 1)
    assert.ok(audit.list.every(row => !Object.hasOwn(row, 'body_digest')))
    assert.ok(!JSON.stringify(audit).includes(secret))
    assert.equal(sql("SELECT count(*) FROM t_audit_log WHERE body_digest IS NOT NULL AND body_digest <> '';"), '0')
  } finally {
    await ok(`/api/notify/channels/${channel.id}`, { token, method: 'DELETE' })
  }
})
