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
  const logDocument = JSON.parse(readFileSync(new URL('../baseline/packages/log-metadata/linux-baseline.json', import.meta.url)))
  logDocument.code = `API-${mode}-log-metadata`
  const invalidLog = structuredClone(logDocument); invalidLog.items[0].check.target = '/tmp/audit'
  assert.equal((await request('/api/baseline/packages/import', pamUpload(invalidLog))).status, 400)
  const logMetadata = { candidate: await ok('/api/baseline/packages/import', pamUpload(logDocument)) }; fixtures.logMetadata = logMetadata
  const logRecord = { id: logMetadata.candidate.id, code: logDocument.code }; baselinePackages.push(logRecord)
  const logPrefix = `/api/baseline/packages/${logRecord.id}`
  logMetadata.approved = await ok(`${logPrefix}/review`, { ...options, body: { approved: true, note: 'Confirm traditional fixed paths and local utmp group; metadata protocol fixture' } })
  logRecord.template = Number(logMetadata.approved.template_id)
  for (const agent of ['ci-smoke-windows', 'ci-smoke-002']) assert.equal((await request(`${logPrefix}/test`, { ...options, body: { agentIds: [agent] } })).status, 400)
  for (const outcome of ['error', 'completed']) {
    logMetadata.testing = await ok(`${logPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(logMetadata.testing.test_task_id); baselineTaskIds.push(taskId)
    const snapshots = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId} ORDER BY code;`).split('\n').map(value => JSON.parse(value))
    assert.deepEqual(snapshots, logDocument.items.map(item => item.check))
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    const payload = Buffer.from(stored.command_b64, 'base64').toString('utf8')
    assert.ok(payload.includes('linux_log_metadata') && logDocument.items.every(item => payload.includes(item.check.target)))
    const badMode = "i.code='BL-LINUX-0027'"
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,${outcome === 'error' ? 'false' : `NOT (${badMode})`},
        CASE WHEN i.code='BL-LINUX-0023' THEN 'scope=fixed-log-path target=/var/log/audit kind=directory mode=0700 uid=0 gid=0 access_acl=none default_acl=none allowed_mode=0700 expected_uid=0 expected_gid=0'
        WHEN ${badMode} THEN 'scope=fixed-log-path target=/var/log/btmp kind=regular mode=0666 uid=0 gid=43 access_acl=none default_acl=n/a allowed_mode=0660 expected_uid=0 expected_gid=43'
        ELSE 'scope=fixed-log-path target=/var/log/wtmp kind=regular mode=0600 uid=0 gid=43 access_acl=none default_acl=n/a allowed_mode=0664 expected_uid=0 expected_gid=43' END,
        ${outcome === 'error' ? "'ACL or path applicability unconfirmed'" : `CASE WHEN ${badMode} THEN 'Log metadata reference mismatch' ELSE '' END`},
        ${outcome === 'error' ? "'error'" : `CASE WHEN ${badMode} THEN 'fail' ELSE 'pass' END`}
      FROM t_baseline_task_expected e JOIN t_baseline_task_item i ON i.task_id=e.task_id AND i.item_id=e.item_id WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',3,${outcome === 'error' ? 0 : 2},${outcome === 'error' ? 3 : 1},${outcome === 'error' ? 0 : 66.67},${outcome === 'error' ? 3 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    logMetadata[outcome] = await ok(logPrefix, { token: tokens.admin })
    assert.equal(logMetadata[outcome].testReady, outcome !== 'error')
    if (outcome === 'error') assert.equal((await request(`${logPrefix}/publish`, { ...options, body: { note: 'Unconfirmed metadata blocks publication' } })).status, 400)
    else {
      const items = logMetadata.completed.testResults[0].items
      assert.equal(items.filter(item => item.execution_status === 'pass').length, 2)
      assert.equal(items.filter(item => item.execution_status === 'fail').length, 1)
      assert.ok(items.every(item => !item.fixable && item.actual.includes('scope=fixed-log-path')))
    }
  }
  logMetadata.published = await ok(`${logPrefix}/publish`, { ...options, body: { note: 'Complete fixed metadata protocol fixture; no log delivery certification' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === logRecord.id))
  logMetadata.withdrawn = await ok(`${logPrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } }); assert.equal(logMetadata.withdrawn.status, 'withdrawn')
  const auditDocument = JSON.parse(readFileSync(new URL('../baseline/packages/audit/linux-baseline.json', import.meta.url)))
  auditDocument.code = `API-${mode}-audit`
  const invalidAudit = structuredClone(auditDocument); invalidAudit.items[0].check.target = '/etc/passwd'
  assert.equal((await request('/api/baseline/packages/import', pamUpload(invalidAudit))).status, 400)
  const audit = { candidate: await ok('/api/baseline/packages/import', pamUpload(auditDocument)) }; fixtures.audit = audit
  const auditRecord = { id: audit.candidate.id, code: auditDocument.code }; baselinePackages.push(auditRecord)
  const auditPrefix = `/api/baseline/packages/${auditRecord.id}`
  audit.approved = await ok(`${auditPrefix}/review`, { ...options, body: { approved: true, note: 'Confirm initial namespace kernel audit and limited loaded watch reference; protocol fixture' } })
  auditRecord.template = Number(audit.approved.template_id)
  for (const agent of ['ci-smoke-windows', 'ci-smoke-002']) assert.equal((await request(`${auditPrefix}/test`, { ...options, body: { agentIds: [agent] } })).status, 400)
  for (const outcome of ['error', 'completed']) {
    audit.testing = await ok(`${auditPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(audit.testing.test_task_id); baselineTaskIds.push(taskId)
    const snapshots = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId} ORDER BY code;`).split('\n').map(value => JSON.parse(value))
    assert.deepEqual(snapshots, auditDocument.items.map(item => item.check))
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    const payload = Buffer.from(stored.command_b64, 'base64').toString('utf8')
    assert.ok(payload.includes('linux_audit') && auditDocument.items.every(item => payload.includes(item.check.option)))
    const badMode = "i.code='BL-LINUX-0025'"
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,${outcome === 'error' ? 'false' : `NOT (${badMode})`},
        CASE WHEN i.code='BL-LINUX-0021' THEN 'scope=kernel-audit enabled=1 daemon_pid=0 lost=0 backlog=0'
        ELSE 'scope=kernel-audit enabled=1 daemon_pid=0 lost=0 backlog=0 rules=3 reference=always_exit_all identity_watches=wa /etc/passwd=wa /etc/shadow=wa /etc/group=wa /etc/gshadow=none' END,
        ${outcome === 'error' ? "'Kernel audit query unavailable or rule form unsupported'" : `CASE WHEN ${badMode} THEN 'Loaded identity watch reference mismatch' ELSE '' END`},
        ${outcome === 'error' ? "'error'" : `CASE WHEN ${badMode} THEN 'fail' ELSE 'pass' END`}
      FROM t_baseline_task_expected e JOIN t_baseline_task_item i ON i.task_id=e.task_id AND i.item_id=e.item_id WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',2,${outcome === 'error' ? 0 : 1},${outcome === 'error' ? 2 : 1},${outcome === 'error' ? 0 : 50},${outcome === 'error' ? 2 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    audit[outcome] = await ok(auditPrefix, { token: tokens.admin })
    assert.equal(audit[outcome].testReady, outcome !== 'error')
    if (outcome === 'error') assert.equal((await request(`${auditPrefix}/publish`, { ...options, body: { note: 'Unconfirmed kernel query blocks publication' } })).status, 400)
    else {
      const items = audit.completed.testResults[0].items
      assert.equal(items.filter(item => item.execution_status === 'pass').length, 1)
      assert.equal(items.filter(item => item.execution_status === 'fail').length, 1)
      assert.ok(items.every(item => !item.fixable && item.actual.includes('scope=kernel-audit')))
    }
  }
  audit.published = await ok(`${auditPrefix}/publish`, { ...options, body: { note: 'Complete kernel protocol fixture; no event delivery certification' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === auditRecord.id))
  audit.withdrawn = await ok(`${auditPrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } }); assert.equal(audit.withdrawn.status, 'withdrawn')
  const cronDocument = JSON.parse(readFileSync(new URL('../baseline/packages/cron/linux-baseline.json', import.meta.url)))
  cronDocument.code = `API-${mode}-cron`
  const invalidCron = structuredClone(cronDocument); invalidCron.items[0].check.target = '/etc/crontab'
  assert.equal((await request('/api/baseline/packages/import', pamUpload(invalidCron))).status, 400)
  const cron = { candidate: await ok('/api/baseline/packages/import', pamUpload(cronDocument)) }; fixtures.cron = cron
  const cronRecord = { id: cron.candidate.id, code: cronDocument.code }; baselinePackages.push(cronRecord)
  const cronPrefix = `/api/baseline/packages/${cronRecord.id}`
  cron.approved = await ok(`${cronPrefix}/review`, { ...options, body: { approved: true, note: 'Confirm installed Debian cron and all direct system table metadata; protocol fixture' } })
  cronRecord.template = Number(cron.approved.template_id)
  for (const agent of ['ci-smoke-windows', 'ci-smoke-002']) assert.equal((await request(`${cronPrefix}/test`, { ...options, body: { agentIds: [agent] } })).status, 400)
  for (const outcome of ['error', 'completed', 'pass']) {
    cron.testing = await ok(`${cronPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(cron.testing.test_task_id); baselineTaskIds.push(taskId)
    const snapshots = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId} ORDER BY code;`).split('\n').map(value => JSON.parse(value))
    assert.deepEqual(snapshots, cronDocument.items.map(item => item.check))
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    const payload = Buffer.from(stored.command_b64, 'base64').toString('utf8')
    assert.ok(payload.includes('debian_cron_metadata') && payload.includes(cronDocument.items[0].check.expected))
    const pass = outcome === 'pass', error = outcome === 'error'
    const quoted = value => "'" + value.replaceAll("'", "''") + "'"
    const actual = 'scope=on-disk-debian-cron-system-tables loaded_state=unverified package=cron version=3.0pl1-184ubuntu2 crontab_mode=0644 cron.d_mode=0755 entries=3 checked=5 violations=' + (pass ? '0' : '1') +
      ' access_acl=none default_acl=none reference=crontab<=0644,cron.d<=0755,all_entries<=0644,uid=0,gid=0' + (pass ? '' : ' examples=/etc/cron.d/task.backup:mode=0666,uid=0,gid=0')
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,${pass},${quoted(actual)},${quoted(error ? 'Unconfirmed cron package, ACL or directory changes' : pass ? '' : 'Cron system table metadata reference mismatch')},${quoted(error ? 'error' : pass ? 'pass' : 'fail')}
      FROM t_baseline_task_expected e WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',1,${pass ? 1 : 0},${pass ? 0 : 1},${pass ? 100 : 0},${error ? 1 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    cron[outcome] = await ok(cronPrefix, { token: tokens.admin })
    assert.equal(cron[outcome].testReady, !error)
    if (error) assert.equal((await request(`${cronPrefix}/publish`, { ...options, body: { note: 'Incomplete metadata blocks publication' } })).status, 400)
    else {
      const item = cron[outcome].testResults[0].items[0]
      assert.equal(item.execution_status, pass ? 'pass' : 'fail')
      assert.ok(!item.fixable && item.actual.includes('loaded_state=unverified'))
      assert.equal(cron[outcome].testResults[0].score, pass ? 100 : 0)
    }
  }
  cron.published = await ok(`${cronPrefix}/publish`, { ...options, body: { note: 'Complete system table metadata protocol fixture; no scheduler or job execution certification' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === cronRecord.id))
  cron.withdrawn = await ok(`${cronPrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } }); assert.equal(cron.withdrawn.status, 'withdrawn')

  const rsyslogCronDocument = JSON.parse(readFileSync(new URL('../baseline/packages/rsyslog-cron/linux-baseline.json', import.meta.url)))
  rsyslogCronDocument.code = `API-${mode}-rsyslog-cron`
  const invalidRsyslogCron = structuredClone(rsyslogCronDocument); invalidRsyslogCron.items[0].check.target = '/tmp/rsyslog.conf'
  assert.equal((await request('/api/baseline/packages/import', pamUpload(invalidRsyslogCron))).status, 400)
  const rsyslogCron = { candidate: await ok('/api/baseline/packages/import', pamUpload(rsyslogCronDocument)) }; fixtures.rsyslogCron = rsyslogCron
  const rsyslogCronRecord = { id: rsyslogCron.candidate.id, code: rsyslogCronDocument.code }; baselinePackages.push(rsyslogCronRecord)
  const rsyslogCronPrefix = `/api/baseline/packages/${rsyslogCronRecord.id}`
  rsyslogCron.approved = await ok(`${rsyslogCronPrefix}/review`, { ...options, body: { approved: true, note: 'Confirm exact rsyslog package and finite disk cron routing; protocol fixture' } })
  rsyslogCronRecord.template = Number(rsyslogCron.approved.template_id)
  for (const agent of ['ci-smoke-windows', 'ci-smoke-002']) assert.equal((await request(`${rsyslogCronPrefix}/test`, { ...options, body: { agentIds: [agent] } })).status, 400)
  for (const outcome of ['error', 'completed', 'pass']) {
    rsyslogCron.testing = await ok(`${rsyslogCronPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(rsyslogCron.testing.test_task_id); baselineTaskIds.push(taskId)
    const snapshots = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId} ORDER BY code;`).split('\n').map(value => JSON.parse(value))
    assert.deepEqual(snapshots, rsyslogCronDocument.items.map(item => item.check))
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    const payload = Buffer.from(stored.command_b64, 'base64').toString('utf8')
    assert.ok(payload.includes('rsyslog_cron_routing') && payload.includes(rsyslogCronDocument.items[0].check.expected))
    const pass = outcome === 'pass', error = outcome === 'error'
    const quoted = value => "'" + value.replaceAll("'", "''") + "'"
    const actual = 'scope=on-disk-rsyslog-cron-routing loaded_state=unverified delivery_state=unverified package=rsyslog version=8.2312.0-3ubuntu9.4 imuxsock=true destination=/var/log/cron.log covered_mask=' + (pass ? '0xff missing_mask=0x00' : '0x7f missing_mask=0x80') + ' files=2 rules=4'
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,${pass},${quoted(actual)},${quoted(error ? 'Unknown rsyslog syntax, package, ACL or configuration changes' : pass ? '' : 'Cron dedicated log routing reference mismatch')},${quoted(error ? 'error' : pass ? 'pass' : 'fail')}
      FROM t_baseline_task_expected e WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',1,${pass ? 1 : 0},${pass ? 0 : 1},${pass ? 100 : 0},${error ? 1 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    rsyslogCron[outcome] = await ok(rsyslogCronPrefix, { token: tokens.admin })
    assert.equal(rsyslogCron[outcome].testReady, !error)
    if (error) assert.equal((await request(`${rsyslogCronPrefix}/publish`, { ...options, body: { note: 'Incomplete configuration blocks publication' } })).status, 400)
    else {
      const item = rsyslogCron[outcome].testResults[0].items[0]
      assert.equal(item.execution_status, pass ? 'pass' : 'fail')
      assert.ok(!item.fixable && item.actual.includes('loaded_state=unverified'))
      assert.equal(rsyslogCron[outcome].testResults[0].score, pass ? 100 : 0)
    }
  }
  rsyslogCron.published = await ok(`${rsyslogCronPrefix}/publish`, { ...options, body: { note: 'Complete routing protocol fixture; no loaded state or event delivery certification' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === rsyslogCronRecord.id))
  rsyslogCron.withdrawn = await ok(`${rsyslogCronPrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } }); assert.equal(rsyslogCron.withdrawn.status, 'withdrawn')

  const sudoersDocument = JSON.parse(readFileSync(new URL('../baseline/packages/sudoers/linux-baseline.json', import.meta.url)))
  sudoersDocument.code = `API-${mode}-sudoers`
  const invalidSudoers = structuredClone(sudoersDocument); invalidSudoers.items[0].check.expected = 'on'
  assert.equal((await request('/api/baseline/packages/import', pamUpload(invalidSudoers))).status, 400)
  const sudoers = { candidate: await ok('/api/baseline/packages/import', pamUpload(sudoersDocument)) }; fixtures.sudoers = sudoers
  const sudoersRecord = { id: sudoers.candidate.id, code: sudoersDocument.code }; baselinePackages.push(sudoersRecord)
  const sudoersPrefix = `/api/baseline/packages/${sudoersRecord.id}`
  sudoers.approved = await ok(`${sudoersPrefix}/review`, { ...options, body: { approved: true, note: 'Confirm exact sudo package and finite disk declarations; protocol fixture' } })
  sudoersRecord.template = Number(sudoers.approved.template_id)
  for (const agent of ['ci-smoke-windows', 'ci-smoke-002']) assert.equal((await request(`${sudoersPrefix}/test`, { ...options, body: { agentIds: [agent] } })).status, 400)
  for (const outcome of ['error', 'completed', 'pass']) {
    sudoers.testing = await ok(`${sudoersPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(sudoers.testing.test_task_id); baselineTaskIds.push(taskId)
    const snapshots = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId} ORDER BY code;`).split('\n').map(value => JSON.parse(value))
    assert.deepEqual(snapshots, sudoersDocument.items.map(item => item.check))
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    const payload = Buffer.from(stored.command_b64, 'base64').toString('utf8')
    assert.ok(payload.includes('sudoers_policy') && sudoersDocument.items.every(item => payload.includes(item.check.expected)))
    const pass = outcome === 'pass', error = outcome === 'error'
    const badLogging = "i.code='BL-LINUX-0029'"
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,${error ? 'false' : pass ? 'true' : `NOT (${badLogging})`},
        'scope=on-disk-sudoers-declarations authorization_state=unverified authentication_state=unverified delivery_state=unverified package=sudo version=1.9.15p5-3ubuntu5.24.04.3 authenticate=on exempt_group=unset nopasswd_tags=0 log_allowed=on logfile=${pass ? '/var/log/sudo.log' : '/var/log/other.log'} files=2 commands=3',
        ${error ? "'Unknown sudoers policy, ACL or changed configuration'" : pass ? "''" : `CASE WHEN ${badLogging} THEN 'Sudoers declared policy reference mismatch' ELSE '' END`},
        ${error ? "'error'" : pass ? "'pass'" : `CASE WHEN ${badLogging} THEN 'fail' ELSE 'pass' END`}
      FROM t_baseline_task_expected e JOIN t_baseline_task_item i ON i.task_id=e.task_id AND i.item_id=e.item_id WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',2,${error ? 0 : pass ? 2 : 1},${error ? 2 : pass ? 0 : 1},${error ? 0 : pass ? 100 : 50},${error ? 2 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    sudoers[outcome] = await ok(sudoersPrefix, { token: tokens.admin })
    assert.equal(sudoers[outcome].testReady, !error)
    if (error) assert.equal((await request(`${sudoersPrefix}/publish`, { ...options, body: { note: 'Incomplete declarations block publication' } })).status, 400)
    else {
      assert.ok(sudoers[outcome].testResults[0].items.every(item => !item.fixable && item.actual.includes('authorization_state=unverified')))
      assert.equal(sudoers[outcome].testResults[0].score, pass ? 100 : 50)
    }
  }
  sudoers.published = await ok(`${sudoersPrefix}/publish`, { ...options, body: { note: 'Complete declaration protocol fixture; no authorization, authentication or delivery certification' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === sudoersRecord.id))
  sudoers.withdrawn = await ok(`${sudoersPrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } }); assert.equal(sudoers.withdrawn.status, 'withdrawn')

  const auditdDocument = JSON.parse(readFileSync(new URL('../baseline/packages/auditd/linux-baseline.json', import.meta.url)))
  auditdDocument.code = `API-${mode}-auditd`
  const invalidAuditd = structuredClone(auditdDocument); invalidAuditd.items[0].check.target = '/tmp/auditd.conf'
  assert.equal((await request('/api/baseline/packages/import', pamUpload(invalidAuditd))).status, 400)
  const auditd = { candidate: await ok('/api/baseline/packages/import', pamUpload(auditdDocument)) }; fixtures.auditd = auditd
  const auditdRecord = { id: auditd.candidate.id, code: auditdDocument.code }; baselinePackages.push(auditdRecord)
  const auditdPrefix = `/api/baseline/packages/${auditdRecord.id}`
  auditd.approved = await ok(`${auditdPrefix}/review`, { ...options, body: { approved: true, note: 'Confirm on-disk auditd 3.1.2 declarations and numeric log GID; protocol fixture' } })
  auditdRecord.template = Number(auditd.approved.template_id)
  for (const agent of ['ci-smoke-windows', 'ci-smoke-002']) assert.equal((await request(`${auditdPrefix}/test`, { ...options, body: { agentIds: [agent] } })).status, 400)
  for (const outcome of ['error', 'completed']) {
    auditd.testing = await ok(`${auditdPrefix}/test`, { ...options, body: { agentIds: ['ci-smoke-001'] } })
    const taskId = Number(auditd.testing.test_task_id); baselineTaskIds.push(taskId)
    const snapshots = sql(`SELECT CAST("check" AS TEXT) FROM t_baseline_task_item WHERE task_id=${taskId} ORDER BY code;`).split('\n').map(value => JSON.parse(value))
    assert.deepEqual(snapshots, auditdDocument.items.map(item => item.check))
    const stored = JSON.parse(sql("SELECT CAST(payload AS TEXT) FROM t_command WHERE agent_id='ci-smoke-001' AND type='baseline_check' ORDER BY id DESC LIMIT 1;"))
    const payload = Buffer.from(stored.command_b64, 'base64').toString('utf8')
    assert.ok(payload.includes('auditd_config') && auditdDocument.items.every(item => payload.includes(item.check.expected)))
    const badRetention = "i.code='BL-AUDITD-0002'"
    sql(`BEGIN;
      INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
      SELECT e.task_id,e.agent_id,e.item_id,${outcome === 'error' ? 'false' : `NOT (${badRetention})`},
        'scope=on-disk-auditd-3.1.2 config=/etc/audit/auditd.conf loaded_state=unverified local_events=yes write_logs=yes log_format=enriched ' ||
        CASE WHEN ${badRetention} THEN 'option=keep_logs max_log_file=8 max_log_file_action=rotate'
        WHEN i.code='BL-AUDITD-0003' THEN 'option=log_file_metadata log_file=/var/log/audit/custom.log log_group=0 kind=regular mode=0600 uid=0 gid=0 access_acl=none allowed_mode=0640 expected_uid=0 expected_gid=0'
        ELSE 'option=local_logging' END,
        ${outcome === 'error' ? "'Unsupported auditd configuration or symbolic log GID'" : `CASE WHEN ${badRetention} THEN 'On-disk keep_logs declaration reference mismatch' ELSE '' END`},
        ${outcome === 'error' ? "'error'" : `CASE WHEN ${badRetention} THEN 'fail' ELSE 'pass' END`}
      FROM t_baseline_task_expected e JOIN t_baseline_task_item i ON i.task_id=e.task_id AND i.item_id=e.item_id WHERE e.task_id=${taskId};
      INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
      VALUES (${taskId},'ci-smoke-001',3,${outcome === 'error' ? 0 : 2},${outcome === 'error' ? 3 : 1},${outcome === 'error' ? 0 : 67},${outcome === 'error' ? 3 : 0});
      UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
    auditd[outcome] = await ok(auditdPrefix, { token: tokens.admin })
    assert.equal(auditd[outcome].testReady, outcome !== 'error')
    if (outcome === 'error') assert.equal((await request(`${auditdPrefix}/publish`, { ...options, body: { note: 'Unconfirmed on-disk configuration blocks publication' } })).status, 400)
    else {
      const items = auditd.completed.testResults[0].items
      assert.equal(items.filter(item => item.execution_status === 'pass').length, 2)
      assert.equal(items.filter(item => item.execution_status === 'fail').length, 1)
      assert.ok(items.every(item => !item.fixable && item.actual.includes('loaded_state=unverified')))
    }
  }
  auditd.published = await ok(`${auditdPrefix}/publish`, { ...options, body: { note: 'Complete on-disk declaration protocol fixture; no daemon loading or log delivery certification' } })
  fixtures.list.push((await ok('/api/baseline/packages', { token: tokens.viewer })).find(pkg => pkg.id === auditdRecord.id))
  auditd.withdrawn = await ok(`${auditdPrefix}/withdraw`, { ...options, body: { note: 'Fixture cleanup' } }); assert.equal(auditd.withdrawn.status, 'withdrawn')
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
