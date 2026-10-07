import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { existsSync, readFileSync, mkdirSync, writeFileSync } from 'node:fs'
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

function request(path, { token, method = 'GET', body, rawBody, extraHeaders = {} } = {}) {
  return new Promise((resolve, reject) => {
    const payload = rawBody ?? (body === undefined ? undefined : JSON.stringify(body))
    const headers = { ...extraHeaders }
    if (token) headers.Authorization = `Bearer ${token}`
    if (body !== undefined) headers['Content-Type'] = 'application/json'
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
const baselinePackages = [], baselineTaskIds = []

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
  for (const pkg of baselinePackages) sql(`BEGIN;
    DELETE FROM t_baseline_package WHERE id='${pkg.id}';
    DELETE FROM t_baseline_package_gate WHERE code='${pkg.code}';
    DELETE FROM t_baseline_item WHERE template_id=${pkg.template || -1};
    DELETE FROM t_baseline_template WHERE id=${pkg.template || -1};
    COMMIT;`)
  for (const task of baselineTaskIds) sql(`BEGIN;
    DELETE FROM t_baseline_result WHERE task_id=${task};
    DELETE FROM t_baseline_summary WHERE task_id=${task};
    DELETE FROM t_baseline_task_expected WHERE task_id=${task};
    DELETE FROM t_baseline_task_item WHERE task_id=${task};
    DELETE FROM t_baseline_task_template WHERE task_id=${task};
    DELETE FROM t_baseline_task WHERE id=${task};
    COMMIT;`)
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

test(`${mode}: baseline candidates, mixed systems, snapshots and publication lifecycle`, async () => {
  sql("UPDATE t_agent SET os_version='ubuntu 24.04' WHERE agent_id='ci-smoke-001'; INSERT INTO t_agent(agent_id,hostname,os_type,os_version) VALUES ('ci-smoke-windows','ci-windows-test-host',2,'Windows Server 2022');")
  const fixtures = { mode, capturedFrom: 'disposable REST API; complete test results seeded as protocol fixtures', platforms: {} }
  const options = { token: tokens.admin, method: 'POST' }
  const retired = (await ok('/api/baseline/templates', { token: tokens.viewer })).find(row => row.code === 'DJBH2.0-LINUX')
  assert.equal(retired.name, 'Linux 旧参考模板（已停用）')
  assert.ok(retired.enabled === false || retired.enabled === 0)
  assert.equal((await request('/api/baseline/tasks', { ...options, body: { agentIds: ['ci-smoke-001'], templateIds: [retired.id] } })).status, 400)
  const previousCommands = sql("SELECT count(*) FROM t_command WHERE type='baseline_check';")
  for (const [platform, agent] of [['linux', 'ci-smoke-001'], ['windows', 'ci-smoke-windows']]) {
    const document = JSON.parse(readFileSync(new URL(`../baseline/packages/${platform}-baseline.json`, import.meta.url)))
    document.code = `API-${mode}-${platform}`
    const boundary = 'alinksec-baseline-fixture-boundary'
    const rawBody = Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="baseline.json"\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(document)}\r\n--${boundary}--\r\n`)
    const upload = { method: 'POST', rawBody, extraHeaders: { 'Content-Type': `multipart/form-data; boundary=${boundary}` } }
    for (const role of ['operator', 'viewer']) {
      assert.equal((await request('/api/baseline/packages/import', { ...upload, token: tokens[role] })).status, 403)
      await ok('/api/baseline/packages', { token: tokens[role] })
    }
    const candidate = await ok('/api/baseline/packages/import', { ...upload, token: tokens.admin })
    assert.match(candidate.id, /^[a-f0-9-]{36}$/)
    const record = { id: candidate.id, code: document.code }; baselinePackages.push(record)
    const stages = { candidate }; fixtures.platforms[platform] = stages
    assert.equal(candidate.status, 'candidate'); assert.equal(candidate.diff.length, document.items.length + document.unsupported.length)
    const prefix = `/api/baseline/packages/${candidate.id}`
    assert.equal((await request(`${prefix}/publish`, { ...options, body: { note: 'No review' } })).status, 400)
    stages.approved = await ok(`${prefix}/review`, { ...options, body: { approved: true, note: 'Fixture review' } })
    record.template = Number(stages.approved.template_id); assert.ok(Number.isSafeInteger(record.template) && record.template > 1, 'Generated template IDs cannot reuse the built-in template ID')
    assert.equal((await request('/api/baseline/tasks', { ...options, body: { agentIds: [agent], templateIds: [record.template] } })).status, 400)
    if (platform === 'linux') assert.equal(sql("SELECT count(*) FROM t_command WHERE type='baseline_check';"), previousCommands, 'Import/review cannot run checks')
    const foreign = platform === 'linux' ? 'ci-smoke-windows' : 'ci-smoke-001'
    assert.equal((await request(`${prefix}/test`, { ...options, body: { agentIds: [foreign] } })).status, 400)
    for (const outcome of ['error', 'legacy']) {
      const attempt = await ok(`${prefix}/test`, { ...options, body: { agentIds: [agent] } })
      const failedTest = Number(attempt.test_task_id); baselineTaskIds.push(failedTest)
      sql(`BEGIN;
        INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
        SELECT e.task_id,e.agent_id,e.item_id,false,'','Unable to evaluate check','${outcome}'
        FROM t_baseline_task_expected e WHERE e.task_id=${failedTest};
        INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count,legacy_count)
        VALUES (${failedTest},'${agent}',4,0,4,0,${outcome === 'error' ? 4 : 0},${outcome === 'legacy' ? 4 : 0});
        UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${failedTest};
        COMMIT;`)
      stages[outcome] = await ok(prefix, { token: tokens.admin })
      assert.equal(stages[outcome].testReady, false)
      assert.equal((await request(`${prefix}/publish`, { ...options, body: { note: 'Invalid execution evidence' } })).status, 400)
      if (outcome === 'error') {
        stages.errorLatest = await ok('/api/baseline/latest', { token: tokens.viewer })
        stages.errorItems = await ok(`/api/baseline/tasks/${failedTest}/agents/${agent}/items`, { token: tokens.viewer })
        stages.errorCategories = await ok(`/api/baseline/tasks/${failedTest}/category-stats`, { token: tokens.viewer })
        assert.ok(stages.errorItems.every(item => item.execution_status === 'error' && !item.fixable))
        assert.ok(stages.errorCategories.every(category => Number(category.failed) === 0))
      }
    }
    stages.testing = await ok(`${prefix}/test`, { ...options, body: { agentIds: [agent] } })
    const testId = Number(stages.testing.test_task_id); assert.ok(Number.isSafeInteger(testId)); baselineTaskIds.push(testId)
    assert.equal(sql(`SELECT count(*) FROM t_baseline_task_expected WHERE task_id=${testId};`), '4')
    assert.equal((await request(`${prefix}/publish`, { ...options, body: { note: 'Incomplete test' } })).status, 400)
    const task = await ok(`/api/baseline/tasks/${testId}`, { token: tokens.viewer })
    assert.deepEqual(task.task.template_ids, [record.template])
    const taskList = await ok('/api/baseline/tasks?page=1&size=100', { token: tokens.viewer })
    assert.deepEqual(taskList.list.find(row => Number(row.id) === testId).template_ids, [record.template])
    assert.equal(task.templates[0].version, document.version); assert.equal(task.templates[0].content_sha256, candidate.content_sha256)
    // API fixtures model a complete Agent report. Native check execution is validated separately.
    const expected = mode === 'sqlite' ? `json_extract(i."check", '$.expected')` : `CAST(i."check" AS JSONB)->>'expected'`
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,true,${expected},'pass' FROM t_baseline_task_expected e
      JOIN t_baseline_task_item i ON i.task_id=e.task_id AND i.item_id=e.item_id WHERE e.task_id=${testId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score) VALUES (${testId},'${agent}',4,4,0,100);
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${testId};
      COMMIT;`)
    stages.completed = await ok(prefix, { token: tokens.admin })
    assert.equal(stages.completed.testReady, true)
    stages.published = await ok(`${prefix}/publish`, { ...options, body: { note: 'Protocol fixture results reviewed' } })
    assert.equal(stages.published.status, 'published')
    const details = await ok(`/api/baseline/tasks/${testId}/agents/${agent}/items`, { token: tokens.viewer })
    assert.equal(details.length, 4); assert.ok(details.every(item => item.template_version === document.version && !item.fixable))
    await waitForSql(`SELECT count(*) FROM t_audit_log WHERE path='${prefix}/review' AND status=200;`, '1')
  }
  const agents = ['ci-smoke-001', 'ci-smoke-windows']
  fixtures.coverage = await ok('/api/baseline/coverage', { ...options, body: { agentIds: agents, templateIds: [] } })
  assert.ok(fixtures.coverage.every(row => row.covered))
  const unknown = await ok('/api/baseline/coverage', { ...options, body: { agentIds: ['ci-smoke-002'], templateIds: [] } })
  assert.equal(unknown[0].covered, false)
  assert.equal((await request('/api/baseline/tasks', { ...options, body: { agentIds: ['ci-smoke-002'] } })).status, 400)
  const created = await ok('/api/baseline/tasks', { token: tokens.operator, method: 'POST', body: { agentIds: agents } })
  baselineTaskIds.push(Number(created.taskId))
  const windowsPayload = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-windows' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
  assert.ok(!JSON.stringify(windowsPayload).includes('sysctl -n'), 'Windows cannot receive Linux command selectors')
  fixtures.templates = await ok('/api/baseline/templates', { token: tokens.viewer })
  fixtures.list = await ok('/api/baseline/packages', { token: tokens.viewer })
  fixtures.hosts = await ok('/api/hosts?page=1&size=100', { token: tokens.viewer })
  fixtures.hostsPage2 = await ok('/api/hosts?page=2&size=100', { token: tokens.viewer })
  for (const pkg of baselinePackages) {
    const withdrawn = await ok(`/api/baseline/packages/${pkg.id}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } })
    fixtures.platforms[pkg.code.endsWith('linux') ? 'linux' : 'windows'].withdrawn = withdrawn
    assert.equal(withdrawn.status, 'withdrawn')
  }
  // A separate product candidate preserves connection context through the real
  // API. Complete reports below are protocol fixtures, not native SSH evidence.
  const sshDocument = JSON.parse(readFileSync(new URL('../baseline/packages/ssh/linux-baseline.json', import.meta.url)))
  sshDocument.code = `API-${mode}-ssh`
  const sshBoundary = 'alinksec-ssh-fixture-boundary'
  const sshUpload = document => ({ method: 'POST', token: tokens.admin,
    rawBody: Buffer.from(`--${sshBoundary}\r\nContent-Disposition: form-data; name="file"; filename="ssh.json"\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(document)}\r\n--${sshBoundary}--\r\n`),
    extraHeaders: { 'Content-Type': `multipart/form-data; boundary=${sshBoundary}` } })
  const invalidSSH = structuredClone(sshDocument)
  invalidSSH.items[0].check.connection.address = '192.0.2.10,user=other'
  assert.equal((await request('/api/baseline/packages/import', sshUpload(invalidSSH))).status, 400)
  const ssh = { candidate: await ok('/api/baseline/packages/import', sshUpload(sshDocument)) }; fixtures.ssh = ssh
  const sshRecord = { id: ssh.candidate.id, code: sshDocument.code }; baselinePackages.push(sshRecord)
  const sshPrefix = `/api/baseline/packages/${sshRecord.id}`
  ssh.approved = await ok(`${sshPrefix}/review`, { ...options, body: { approved: true, note: 'Review explicit sample connection only' } })
  sshRecord.template = Number(ssh.approved.template_id)
  assert.equal((await request(`${sshPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-windows'] } })).status, 400)
  for (const outcome of ['error', 'fail']) {
    ssh.testing = await ok(`${sshPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(ssh.testing.test_task_id); baselineTaskIds.push(taskId)
    const rawChecks = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId} ORDER BY code;`).split('\n')
    const checks = rawChecks.map(value => JSON.parse(value))
    assert.equal(checks.length, 2)
    assert.ok(checks.every(check => check.type === 'sshd_effective'))
    for (const check of checks) assert.deepEqual(check.connection, sshDocument.items[0].check.connection)
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    const payload = Buffer.from(stored.command_b64, 'base64').toString('utf8')
    assert.ok(payload.includes('sshd_effective') && payload.includes('192.0.2.10'))
    assert.ok(rawChecks.every(check => payload.includes(check)), 'Dispatched protobuf must preserve both snapshotted check definitions')
    const option = mode === 'sqlite' ? `json_extract(i."check", '$.option')` : `CAST(i."check" AS JSONB)->>'option'`
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,false,
        CASE WHEN ${option}='permitrootlogin' THEN 'connection=(user=root,host=admin.example.invalid,addr=192.0.2.10,laddr=192.0.2.20,lport=22) permitrootlogin=yes'
             ELSE 'connection=(user=root,host=admin.example.invalid,addr=192.0.2.10,laddr=192.0.2.20,lport=22) maxauthtries=6' END,
        '${outcome === 'error' ? 'SSH configuration query failed' : 'Sample connection policy mismatch'}','${outcome}'
      FROM t_baseline_task_expected e JOIN t_baseline_task_item i ON i.task_id=e.task_id AND i.item_id=e.item_id WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',2,0,2,0,${outcome === 'error' ? 2 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    if (outcome === 'error') {
      ssh.error = await ok(sshPrefix, { token: tokens.admin })
      assert.equal(ssh.error.testReady, false)
      assert.equal((await request(`${sshPrefix}/publish`, { ...options, body: { note: 'Query errors cannot publish' } })).status, 400)
    } else {
      ssh.completed = await ok(sshPrefix, { token: tokens.admin })
      assert.equal(ssh.completed.testReady, true)
      assert.ok(ssh.completed.testResults[0].items.every(item => item.actual.includes('addr=192.0.2.10') && item.message === 'Sample connection policy mismatch'))
    }
  }
  ssh.published = await ok(`${sshPrefix}/publish`, { ...options, body: { note: 'Protocol fixtures: both sample-context policies are noncompliant; no live host certification' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === sshRecord.id))
  ssh.withdrawn = await ok(`${sshPrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } })
  assert.equal(ssh.withdrawn.status, 'withdrawn')
  // Identity policies retain numeric metadata and the explicit UID range in
  // immutable snapshots. These complete reports are redacted protocol fixtures.
  const identityDocument = JSON.parse(readFileSync(new URL('../baseline/packages/identity/linux-baseline.json', import.meta.url)))
  identityDocument.code = `API-${mode}-identity`
  const identityBoundary = 'alinksec-identity-fixture-boundary'
  const identityUpload = document => ({ method: 'POST', token: tokens.admin,
    rawBody: Buffer.from(`--${identityBoundary}\r\nContent-Disposition: form-data; name="file"; filename="identity.json"\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(document)}\r\n--${identityBoundary}--\r\n`),
    extraHeaders: { 'Content-Type': `multipart/form-data; boundary=${identityBoundary}` } })
  const invalidIdentity = structuredClone(identityDocument)
  invalidIdentity.items.find(item => item.check.option === 'system_shells').check.uid_min = 0
  assert.equal((await request('/api/baseline/packages/import', identityUpload(invalidIdentity))).status, 400)
  const identity = { candidate: await ok('/api/baseline/packages/import', identityUpload(identityDocument)) }; fixtures.identity = identity
  const identityRecord = { id: identity.candidate.id, code: identityDocument.code }; baselinePackages.push(identityRecord)
  const identityPrefix = `/api/baseline/packages/${identityRecord.id}`
  identity.approved = await ok(`${identityPrefix}/review`, { ...options, body: { approved: true, note: 'Review Ubuntu24 local files and explicit UID 1..999 scope' } })
  identityRecord.template = Number(identity.approved.template_id)
  for (const agent of ['ci-smoke-windows', 'ci-smoke-002']) {
    assert.equal((await request(`${identityPrefix}/test`, { ...options, body: { agentIds: [agent] } })).status, 400)
  }
  for (const outcome of ['error', 'complete']) {
    identity.testing = await ok(`${identityPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(identity.testing.test_task_id); baselineTaskIds.push(taskId)
    const rawChecks = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId} ORDER BY code;`).split('\n')
    assert.deepEqual(rawChecks.map(value => JSON.parse(value)), [...identityDocument.items].sort((a,b) => a.code.localeCompare(b.code)).map(item => item.check))
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    const payload = Buffer.from(stored.command_b64, 'base64').toString('utf8')
    assert.ok(rawChecks.every(check => payload.includes(check)), 'Dispatched protobuf must preserve all seven identity snapshots')
    const type = mode === 'sqlite' ? `json_extract(i."check", '$.type')` : `CAST(i."check" AS JSONB)->>'type'`
    const target = mode === 'sqlite' ? `json_extract(i."check", '$.target')` : `(CAST(i."check" AS JSONB)->>'target')`
    const option = mode === 'sqlite' ? `json_extract(i."check", '$.option')` : `CAST(i."check" AS JSONB)->>'option'`
    const metadata = `${type}='local_identity_file'`
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,${outcome === 'error' ? 'false' : metadata},
        CASE WHEN ${metadata} THEN CASE WHEN ${target} IN ('/etc/shadow','/etc/gshadow')
          THEN 'scope=local-files target=' || ${target} || ' mode=0600 uid=0 gid=42 access_acl=none allowed_mode=0640 expected_uid=0 expected_gid=42'
          ELSE 'scope=local-files target=' || ${target} || ' mode=0444 uid=0 gid=0 access_acl=none allowed_mode=0644 expected_uid=0 expected_gid=0' END
          WHEN ${option}='empty_password' THEN 'scope=local-files target=/etc/shadow passwd_accounts=3 shadow_accounts=3 offender_count=1 accounts=[shadow:fixture-user]'
          WHEN ${option}='system_shells' THEN 'scope=local-files target=/etc/passwd uid_range=1..999 checked=2 offender_count=1 accounts=[fixture-service(uid=999)]'
          ELSE 'scope=local-files target=/etc/passwd accounts=3 uid0_count=2 uid0_accounts=[fixture-admin,root] expected=root' END,
        ${outcome === 'error' ? "'Local identity query failed'" : `CASE WHEN ${metadata} THEN '' ELSE 'Local identity policy mismatch' END`},
        ${outcome === 'error' ? "'error'" : `CASE WHEN ${metadata} THEN 'pass' ELSE 'fail' END`}
      FROM t_baseline_task_expected e JOIN t_baseline_task_item i ON i.task_id=e.task_id AND i.item_id=e.item_id WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',7,${outcome === 'error' ? 0 : 4},${outcome === 'error' ? 7 : 3},${outcome === 'error' ? 0 : 57},${outcome === 'error' ? 7 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    if (outcome === 'error') {
      identity.error = await ok(identityPrefix, { token: tokens.admin })
      assert.equal(identity.error.testReady, false)
      assert.equal((await request(`${identityPrefix}/publish`, { ...options, body: { note: 'Unconfirmed identity queries cannot publish' } })).status, 400)
    } else {
      identity.completed = await ok(identityPrefix, { token: tokens.admin })
      assert.equal(identity.completed.testReady, true)
      const items = identity.completed.testResults[0].items
      assert.equal(items.length, 7); assert.equal(items.filter(item => item.execution_status === 'pass').length, 4)
      assert.equal(items.filter(item => item.execution_status === 'fail').length, 3)
      assert.ok(items.every(item => !item.fixable))
      assert.ok(items.some(item => item.actual.includes('uid_range=1..999')))
      assert.ok(!JSON.stringify(identity.completed).includes('DO_NOT_REPORT_PASSWORD_HASH'))
    }
  }
  identity.published = await ok(`${identityPrefix}/publish`, { ...options, body: { note: 'Redacted protocol fixture: four metadata passes and three account policy failures; no live host certification' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === identityRecord.id))
  identity.withdrawn = await ok(`${identityPrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } })
  assert.equal(identity.withdrawn.status, 'withdrawn')
  // The PAM service and reference remain immutable; full reports here are
  // protocol fixtures. Actual password changes occur only in the dedicated image.
  const pamDocument = JSON.parse(readFileSync(new URL('../baseline/packages/pam/linux-baseline.json', import.meta.url)))
  pamDocument.code = `API-${mode}-pam`
  const pamBoundary = 'alinksec-pam-fixture-boundary'
  const pamUpload = document => ({ method: 'POST', token: tokens.admin,
    rawBody: Buffer.from(`--${pamBoundary}\r\nContent-Disposition: form-data; name="file"; filename="pam.json"\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(document)}\r\n--${pamBoundary}--\r\n`),
    extraHeaders: { 'Content-Type': `multipart/form-data; boundary=${pamBoundary}` } })
  const invalidPAM = structuredClone(pamDocument); invalidPAM.items[0].check.target = '/etc/pam.d/sshd'
  assert.equal((await request('/api/baseline/packages/import', pamUpload(invalidPAM))).status, 400)
  const pam = { candidate: await ok('/api/baseline/packages/import', pamUpload(pamDocument)) }; fixtures.pam = pam
  const pamRecord = { id: pam.candidate.id, code: pamDocument.code }; baselinePackages.push(pamRecord)
  const pamPrefix = `/api/baseline/packages/${pamRecord.id}`
  pam.approved = await ok(`${pamPrefix}/review`, { ...options, body: { approved: true, note: 'Confirm passwd local password chain and explicit quality/hash references' } })
  pamRecord.template = Number(pam.approved.template_id)
  for (const agent of ['ci-smoke-windows', 'ci-smoke-002']) assert.equal((await request(`${pamPrefix}/test`, { ...options, body: { agentIds: [agent] } })).status, 400)
  for (const outcome of ['error', 'complete']) {
    pam.testing = await ok(`${pamPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(pam.testing.test_task_id); baselineTaskIds.push(taskId)
    const rawChecks = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId} ORDER BY code;`).split('\n')
    assert.deepEqual(rawChecks.map(value => JSON.parse(value)), pamDocument.items.map(item => item.check))
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    const payload = Buffer.from(stored.command_b64, 'base64').toString('utf8')
    assert.ok(rawChecks.every(check => payload.includes(check)), 'Dispatched protobuf must retain selected PAM service and full reference')
    const option = mode === 'sqlite' ? `json_extract(i."check", '$.option')` : `CAST(i."check" AS JSONB)->>'option'`
    const hash = `${option}='unix_hash'`
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,${outcome === 'error' ? 'false' : hash},
        CASE WHEN ${hash} THEN 'scope=passwd-password-chain service=/etc/pam.d/passwd stack=local-unix-deny-permit quality_present=true unix_use_authtok=true algorithm=yescrypt inputs=4 expected=yescrypt'
        ELSE 'scope=passwd-password-chain service=/etc/pam.d/passwd stack=local-unix-deny-permit quality_present=true unix_use_authtok=true algorithm=yescrypt inputs=4 minlen=8 minclass=1 dcredit=0 ucredit=0 lcredit=0 ocredit=0 enforcing=1 enforce_for_root=0' END,
        ${outcome === 'error' ? "'PAM chain is unconfirmed'" : `CASE WHEN ${hash} THEN '' ELSE 'PAM password quality reference mismatch' END`},
        ${outcome === 'error' ? "'error'" : `CASE WHEN ${hash} THEN 'pass' ELSE 'fail' END`}
      FROM t_baseline_task_expected e JOIN t_baseline_task_item i ON i.task_id=e.task_id AND i.item_id=e.item_id WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',2,${outcome === 'error' ? 0 : 1},${outcome === 'error' ? 2 : 1},${outcome === 'error' ? 0 : 50},${outcome === 'error' ? 2 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    if (outcome === 'error') {
      pam.error = await ok(pamPrefix, { token: tokens.admin }); assert.equal(pam.error.testReady, false)
      assert.equal((await request(`${pamPrefix}/publish`, { ...options, body: { note: 'Unsupported PAM chain cannot publish' } })).status, 400)
    } else {
      pam.completed = await ok(pamPrefix, { token: tokens.admin }); assert.equal(pam.completed.testReady, true)
      const items = pam.completed.testResults[0].items
      assert.equal(items.filter(item => item.execution_status === 'pass').length, 1)
      assert.equal(items.filter(item => item.execution_status === 'fail').length, 1)
      assert.ok(items.every(item => !item.fixable && item.actual.includes('service=/etc/pam.d/passwd')))
      assert.ok(!JSON.stringify(pam.completed).includes('DO_NOT_REPORT_PAM_SECRET'))
    }
  }
  pam.published = await ok(`${pamPrefix}/publish`, { ...options, body: { note: 'Protocol fixture: declared hash selection passes, quality reference fails; no production credentials changed' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === pamRecord.id))
  pam.withdrawn = await ok(`${pamPrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } }); assert.equal(pam.withdrawn.status, 'withdrawn')
  const serviceDocument = JSON.parse(readFileSync(new URL('../baseline/packages/systemd/linux-baseline.json', import.meta.url)))
  serviceDocument.code = `API-${mode}-systemd`
  const invalidService = structuredClone(serviceDocument); invalidService.items[0].check.target = 'ssh.service'
  assert.equal((await request('/api/baseline/packages/import', pamUpload(invalidService))).status, 400)
  const systemd = { candidate: await ok('/api/baseline/packages/import', pamUpload(serviceDocument)) }; fixtures.systemd = systemd
  const serviceRecord = { id: systemd.candidate.id, code: serviceDocument.code }; baselinePackages.push(serviceRecord)
  const servicePrefix = `/api/baseline/packages/${serviceRecord.id}`
  systemd.approved = await ok(`${servicePrefix}/review`, { ...options, body: { approved: true, note: 'Confirm Ubuntu24 local system manager and exact service state scope; protocol fixture' } })
  serviceRecord.template = Number(systemd.approved.template_id)
  for (const agent of ['ci-smoke-windows', 'ci-smoke-002']) assert.equal((await request(`${servicePrefix}/test`, { ...options, body: { agentIds: [agent] } })).status, 400)
  for (const outcome of ['error', 'completed']) {
    systemd.testing = await ok(`${servicePrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(systemd.testing.test_task_id); baselineTaskIds.push(taskId)
    const snapshots = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId} ORDER BY code;`).split('\n').map(value => JSON.parse(value))
    assert.deepEqual(snapshots, serviceDocument.items.map(item => item.check))
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    const payload = Buffer.from(stored.command_b64, 'base64').toString('utf8')
    assert.ok(payload.includes('systemd_service') && payload.includes('auditd.service') && payload.includes('rsyslog.service'))
    const audit = "i.code='BL-LINUX-0022'"
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,${outcome === 'error' ? 'false' : audit},
        CASE WHEN ${audit} THEN 'manager=local-system unit=auditd.service Id=auditd.service LoadState=loaded ActiveState=active SubState=running MainPID=42'
        ELSE 'manager=local-system unit=rsyslog.service Id=rsyslog.service LoadState=loaded ActiveState=inactive SubState=dead MainPID=0' END,
        ${outcome === 'error' ? "'System bus unavailable'" : `CASE WHEN ${audit} THEN '' ELSE 'Service running reference mismatch' END`},
        ${outcome === 'error' ? "'error'" : `CASE WHEN ${audit} THEN 'pass' ELSE 'fail' END`}
      FROM t_baseline_task_expected e JOIN t_baseline_task_item i ON i.task_id=e.task_id AND i.item_id=e.item_id WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',2,${outcome === 'error' ? 0 : 1},${outcome === 'error' ? 2 : 1},${outcome === 'error' ? 0 : 50},${outcome === 'error' ? 2 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    systemd[outcome] = await ok(servicePrefix, { token: tokens.admin })
    assert.equal(systemd[outcome].testReady, outcome !== 'error')
    if (outcome === 'error') assert.equal((await request(`${servicePrefix}/publish`, { ...options, body: { note: 'Unconfirmed service query blocks publication' } })).status, 400)
    else {
      const items = systemd.completed.testResults[0].items
      assert.equal(items.filter(item => item.execution_status === 'pass').length, 1)
      assert.equal(items.filter(item => item.execution_status === 'fail').length, 1)
      assert.ok(items.every(item => !item.fixable && item.actual.includes('manager=local-system')))
    }
  }
  systemd.published = await ok(`${servicePrefix}/publish`, { ...options, body: { note: 'Complete service state protocol fixture; no audit event or log delivery certification' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === serviceRecord.id))
  systemd.withdrawn = await ok(`${servicePrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } }); assert.equal(systemd.withdrawn.status, 'withdrawn')
  const authDocument = JSON.parse(readFileSync(new URL('../baseline/packages/pam-auth/linux-baseline.json', import.meta.url)))
  authDocument.code = `API-${mode}-pam-auth`
  const invalidAuth = structuredClone(authDocument); invalidAuth.items[0].check.target = '/etc/pam.d/sshd'
  assert.equal((await request('/api/baseline/packages/import', pamUpload(invalidAuth))).status, 400)
  const pamAuth = { candidate: await ok('/api/baseline/packages/import', pamUpload(authDocument)) }; fixtures.pamAuth = pamAuth
  const authRecord = { id: pamAuth.candidate.id, code: authDocument.code }; baselinePackages.push(authRecord)
  const authPrefix = `/api/baseline/packages/${authRecord.id}`
  pamAuth.approved = await ok(`${authPrefix}/review`, { ...options, body: { approved: true, note: 'Confirm login auth chain and three consistent faillock stages; protocol fixture' } })
  authRecord.template = Number(pamAuth.approved.template_id)
  for (const agent of ['ci-smoke-windows', 'ci-smoke-002']) assert.equal((await request(`${authPrefix}/test`, { ...options, body: { agentIds: [agent] } })).status, 400)
  for (const outcome of ['error', 'fail', 'pass']) {
    pamAuth.testing = await ok(`${authPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(pamAuth.testing.test_task_id); baselineTaskIds.push(taskId)
    const check = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId};`)
    assert.deepEqual(JSON.parse(check), authDocument.items[0].check)
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    assert.ok(Buffer.from(stored.command_b64, 'base64').toString('utf8').includes(check))
    const passed = outcome === 'pass'
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,${passed},
        'scope=login-auth-chain service=/etc/pam.d/login stack=preauth-unix-authfail-authsucc-deny deny=${passed ? 3 : 6} fail_interval=900 unlock_time=900 explicit_even_deny_root=true root_unlock_time=900 tally_dir=/var/run/faillock inputs=4',
        '${outcome === 'error' ? 'Unconfirmed login auth chain' : passed ? '' : 'PAM login lockout reference mismatch'}','${outcome}'
      FROM t_baseline_task_expected e WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',1,${passed ? 1 : 0},${passed ? 0 : 1},${passed ? 100 : 0},${outcome === 'error' ? 1 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    pamAuth[outcome === 'fail' ? 'completed' : outcome] = await ok(authPrefix, { token: tokens.admin })
    if (outcome === 'error') {
      assert.equal(pamAuth.error.testReady, false)
      assert.equal((await request(`${authPrefix}/publish`, { ...options, body: { note: 'Unconfirmed chain blocks publication' } })).status, 400)
    } else {
      const detail = pamAuth[outcome === 'fail' ? 'completed' : 'pass']
      assert.equal(detail.testReady, true)
      assert.equal(detail.testResults[0].items[0].execution_status, outcome)
      assert.ok(!detail.testResults[0].items[0].fixable)
      assert.ok(detail.testResults[0].items[0].actual.includes('service=/etc/pam.d/login'))
    }
  }
  pamAuth.published = await ok(`${authPrefix}/publish`, { ...options, body: { note: 'Complete login auth protocol fixture; no live authentication or tally changes' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === authRecord.id))
  pamAuth.withdrawn = await ok(`${authPrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } }); assert.equal(pamAuth.withdrawn.status, 'withdrawn')
  const directory = fileURLToPath(new URL('../../.tmp/', import.meta.url)); mkdirSync(directory, { recursive: true })
  writeFileSync(`${directory}/baseline-browser-fixtures-${mode}.json`, JSON.stringify(fixtures, null, 2))
})
