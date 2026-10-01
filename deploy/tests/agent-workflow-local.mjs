import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { randomUUID, X509Certificate } from 'node:crypto'
import { closeSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, openSync,
  readFileSync, rmSync, writeFileSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import net from 'node:net'
import { networkInterfaces } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

assert.equal(process.env.ALINKSEC_SMOKE_ALLOW_FIXTURES, 'true')
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const root = mkdtempSync(join(repo, '.tmp/agent-workflow.'))
const image = process.env.ALINKSEC_SMOKE_AGENT_IMAGE || 'alinksec-agent-validation'
const exec = promisify(execFile)
const containers = []
const password = 'agent-workflow-admin-password'
let server, proxy, business, token, passed = false
let accessHost = 'ci.alinksec.test'
const controller = new AbortController()
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  controller.abort(new Error(signal))
  server?.child.kill('SIGTERM')
})
async function command(exe, args, options = {}) {
  return (await exec(exe, args, { encoding: 'utf8', timeout: 60_000,
    maxBuffer: 1024 * 1024, signal: controller.signal, ...options })).stdout.trim()
}
async function port(host) {
  const listener = net.createServer()
  await new Promise((ok, fail) => { listener.once('error', fail); listener.listen(0, host, ok) })
  const value = listener.address().port
  await new Promise(ok => listener.close(ok))
  return value
}
async function until(condition, message, timeout = 30_000) {
  const end = Date.now() + timeout
  while (Date.now() < end) {
    controller.signal.throwIfAborted()
    if (await condition()) return
    await delay(250)
  }
  throw new Error(message)
}
function sql(statement, ...args) {
  const db = new DatabaseSync(join(root, 'data/alinksec.db'))
  try {
    db.exec('PRAGMA busy_timeout=5000')
    return db.prepare(statement).all(...args)
  } finally { db.close() }
}
let gateway, httpPort, grpcPort, tlsPort
async function api(path, body, method = body ? 'POST' : 'GET') {
  const response = await fetch(`http://${gateway}:${httpPort}${path}`, {
    method, headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined, signal: AbortSignal.timeout(3000),
  })
  const result = await response.json()
  assert.equal(response.status, 200, path)
  assert.equal(result.code, 0, `${path}: ${result.msg}`)
  return result.data
}
async function startServer(host = accessHost, expectFailure = false) {
  const previousLog = existsSync(join(root, 'server.log')) ? readFileSync(join(root, 'server.log'), 'utf8').length : 0
  const log = openSync(join(root, 'server.log'), 'a')
  const child = spawn(process.env.JAVA_BIN, ['-Xmx256m', '-XX:MaxMetaspaceSize=128m',
    '-XX:ActiveProcessorCount=1', '-jar', join(repo, 'server/alinksec-bootstrap/target/alinksec-bootstrap.jar'),
    `--server.address=${gateway}`, `--server.port=${httpPort}`, `--alinksec.server.port=${grpcPort}`], {
    cwd: root, stdio: ['ignore', log, log], env: { ...process.env, SPRING_PROFILES_ACTIVE: 'sqlite',
      ALINKSEC_METRICS_ENABLED: 'false', ALINKSEC_SQLITE_PATH: join(root, 'data/alinksec.db'),
      ALINKSEC_CERT_DIR: join(root, 'data/certs'), ALINKSEC_WEB_TLS_DIR: join(root, 'data/web-tls'),
      ALINKSEC_SIG_DIR: join(root, 'data/signature'), ALINKSEC_PATCH_DIR: join(root, 'data/patch'),
      ALINKSEC_UPGRADE_DIR: join(root, 'data/upgrade'), ALINKSEC_PUBLIC_HOST: host,
      ALINKSEC_SERVER_TLS_SANS: `localhost,127.0.0.1,${host}`, ALINKSEC_SIG_BASE: `${host}:${tlsPort}`,
      ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD: password, ALINKSEC_BOOTSTRAP_ENROLL_TOKEN: 'ENROLL-agent-workflow',
      ALINKSEC_JWT_SECRET: 'agent-workflow-jwt-secret' },
  })
  closeSync(log)
  const current = { child }
  current.closed = new Promise(ok => child.once('close', code => { current.code = code; ok(code) }))
  server = current
  if (expectFailure) {
    const code = await Promise.race([current.closed, delay(30_000).then(() => { throw new Error('Stale certificate did not prevent startup') })])
    assert.notEqual(code, 0)
    assert.match(readFileSync(join(root, 'server.log'), 'utf8').slice(previousLog), /SAN/)
    server = undefined
    return
  }
  await until(async () => {
    try { token = (await api('/api/auth/login', { username: 'admin', password })).token; return !!token }
    catch { return false }
  }, 'Server did not start', 45_000)
}
async function stopServer() {
  if (!server) return
  server.child.kill('SIGTERM')
  const timer = setTimeout(() => server?.child.kill('SIGKILL'), 15_000)
  await server.closed
  clearTimeout(timer)
  server = undefined
}
async function stopAgent(agent) { await command('docker', ['stop', '--time', '10', agent.container]) }
async function startAgent(agent) {
  await command('docker', ['start', agent.container])
  await until(() => sql('SELECT status FROM t_agent WHERE agent_id=?', agent.id)[0]?.status === 1,
    'Agent did not reconnect')
}
async function makeAgent(label, machineId = randomUUID().replaceAll('-', '')) {
  const dir = join(root, label)
  const fixtures = join(dir, 'fixtures')
  mkdirSync(fixtures, { recursive: true })
  mkdirSync(join(dir, 'work'))
  copyFileSync(process.env.ALINKSEC_SMOKE_AGENT_BIN, join(fixtures, 'alinksec-agent'))
  copyFileSync(join(repo, 'deploy/tests/fixtures/agent-entry.sh'), join(fixtures, 'agent-entry.sh'))
  copyFileSync(join(root, 'data/certs/ca.crt'), join(fixtures, 'ca.crt'))
  writeFileSync(join(fixtures, 'machine-id'), machineId + '\n')
  const hardwareId = machineId.replace(/^(........)(....)(....)(....)(............)$/, '$1-$2-$3-$4-$5')
  writeFileSync(join(fixtures, 'product_uuid'), hardwareId + '\n')
  writeFileSync(join(fixtures, 'agent.yml'), `server_addr: ${accessHost}:${grpcPort}\nheartbeat_interval: 1s\ncollect_interval: 24h\ndecoy:\n  enabled: false\n`)
  const enrollment = await api('/api/hosts/enroll-token?maxUses=1', {})
  const container = await command('docker', ['run', '-d', '--init', '--name', `alinksec-agent-${process.pid}-${label}`,
    '--memory=256m', '--memory-swap=384m', '--cpus=1', '--pids-limit=96', '--cap-add=NET_ADMIN',
    '--add-host', `ci.alinksec.test:${gateway}`, '--add-host', `ci-repaired.alinksec.test:${gateway}`, '--hostname', `ci-agent-${label}`,
    '--mount', `type=bind,src=${fixtures},dst=/fixtures,readonly`,
    '--mount', `type=bind,src=${fixtures}/machine-id,dst=/etc/machine-id,readonly`,
    '--mount', `type=bind,src=${fixtures}/product_uuid,dst=/sys/class/dmi/id/product_uuid,readonly`,
    '--mount', `type=bind,src=${dir}/work,dst=/work`,
    '-e', `ALINKSEC_TEST_SERVER=${accessHost}:${grpcPort}`, '-e', `ALINKSEC_TEST_TOKEN=${enrollment.token}`, image])
  containers.push(container)
  await until(() => existsSync(join(dir, 'work/state.yml')), 'Actual Agent did not enroll')
  const id = readFileSync(join(dir, 'work/state.yml'), 'utf8').match(/^agent_id: (.+)$/m)?.[1]
  assert.match(id, /^[\da-f-]{36}$/)
  const agent = { id, dir, fixtures, container }
  await until(() => sql('SELECT status FROM t_agent WHERE agent_id=?', id)[0]?.status === 1,
    'Actual Agent did not establish mTLS channel')
  assert.equal(sql('SELECT machine_id FROM t_agent WHERE agent_id=?', id)[0].machine_id,
    hardwareId)
  return agent
}
async function patchFile() {
  const pkgDir = join(root, 'deb')
  mkdirSync(join(pkgDir, 'DEBIAN'), { recursive: true })
  mkdirSync(join(pkgDir, 'usr/share/alinksec-smoke'), { recursive: true })
  writeFileSync(join(pkgDir, 'DEBIAN/control'), 'Package: alinksec-smoke-package\nVersion: 2.0\nArchitecture: all\nMaintainer: CI <ci@example.test>\nDescription: disposable validation fixture\n')
  writeFileSync(join(pkgDir, 'usr/share/alinksec-smoke/version'), '2.0\n')
  const file = join(root, 'fixture.deb')
  await command('dpkg-deb', ['--build', '--root-owner-group', pkgDir, file])
  const form = new FormData()
  form.set('file', new Blob([readFileSync(file)]), 'fixture.deb')
  for (const [key, value] of Object.entries({ osType: '1', pkgName: 'alinksec-smoke-package', targetVersion: '2.0', repoType: 'deb' })) form.set(key, value)
  const response = await fetch(`http://${gateway}:${httpPort}/api/fix/patches`, {
    method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: form,
  })
  const result = await response.json()
  assert.equal(response.status, 200)
  assert.equal(result.code, 0, result.msg)
}
try {
  assert.equal(await command('docker', ['ps', '-q']), '', 'Stop other validation scenarios first')
  await command('docker', ['image', 'inspect', image])
  gateway = JSON.parse(await command('docker', ['network', 'inspect', 'bridge']))[0].IPAM.Config.find(c => net.isIP(c.Gateway) === 4).Gateway
  httpPort = await port(gateway); grpcPort = await port('127.0.0.1'); tlsPort = await port(gateway)
  mkdirSync(join(root, 'data'))
  await startServer()
  await api('/api/protect/rules/PR-0010', { enabled: false, actions: ['alert'], match: { dirs: ['/work/decoys'] } }, 'PUT')
  proxy = https.createServer({ key: readFileSync(join(root, 'data/web-tls/server.key')),
    cert: readFileSync(join(root, 'data/web-tls/server.crt')) }, (req, res) => {
    const upstream = http.request({ host: gateway, port: httpPort, path: req.url, method: req.method,
      headers: req.headers }, reply => { res.writeHead(reply.statusCode, reply.headers); reply.pipe(res) })
    upstream.on('error', () => { res.writeHead(502); res.end() })
    req.pipe(upstream)
  })
  await new Promise(ok => proxy.listen(tlsPort, gateway, ok))
  const first = await makeAgent('first')
  await until(() => existsSync(join(first.dir, 'work/policy.json')), 'Initial policy was not applied')
  await api('/api/protect/rules/PR-0010', { enabled: true, actions: ['alert'], match: { dirs: ['/work/decoys'], count_per_dir: 2 } }, 'PUT')
  await until(() => JSON.parse(readFileSync(join(first.dir, 'work/policy.json'), 'utf8')).decoy.enabled === true,
    'Enabled policy did not reach Agent')
  await api('/api/protect/rules/PR-0010', { enabled: false }, 'PUT')
  await until(() => JSON.parse(readFileSync(join(first.dir, 'work/policy.json'), 'utf8')).decoy.enabled === false,
    'Disabled policy did not reach Agent')
  console.log('ok - actual Go Agent TLS enrollment, mTLS heartbeat and enabled/disabled policy persistence')
  const businessAddress = Object.values(networkInterfaces()).flat().find(a => a.family === 'IPv4' && !a.internal && a.address !== gateway)?.address
  assert.ok(businessAddress, 'An additional local IPv4 is required to check blocked business traffic')
  business = http.createServer((req, res) => res.end('business-fixture'))
  await new Promise(ok => business.listen(0, businessAddress, ok))
  const businessURL = `http://${businessAddress}:${business.address().port}`
  const probe = ['exec', first.container, 'curl', '--noproxy', '*', '--fail', '--silent', '--show-error', '--max-time', '2', businessURL]
  assert.equal(await command('docker', probe), 'business-fixture')
  await api(`/api/hosts/${first.id}/isolate`, { isolate: true })
  await until(() => sql('SELECT isolation_status FROM t_agent WHERE agent_id=?', first.id)[0].isolation_status === 2,
    'Agent isolation ACK did not complete')
  assert.ok(existsSync(join(first.dir, 'work/isolated.json')))
  assert.match(await command('docker', ['exec', first.container, 'iptables', '-S', 'ALINKSEC_ISO']), /-j DROP/)
  await assert.rejects(command('docker', probe), error => error.code === 28)
  await stopAgent(first)
  await stopServer()
  await startServer()
  await startAgent(first)
  assert.equal(sql('SELECT isolation_status FROM t_agent WHERE agent_id=?', first.id)[0].isolation_status, 2)
  await api(`/api/hosts/${first.id}/unisolate`, {})
  await until(() => sql('SELECT isolation_status FROM t_agent WHERE agent_id=?', first.id)[0].isolation_status === 0,
    'Agent restore ACK did not complete')
  assert.equal(existsSync(join(first.dir, 'work/isolated.json')), false)
  assert.equal(await command('docker', probe), 'business-fixture')
  console.log('ok - actual iptables isolation, Agent/server restart, heartbeat and restoration')
  await stopAgent(first)
  const second = await makeAgent('second')
  await patchFile()
  const findings = [first, second].map(agent => ({ agentId: agent.id, findingId: sql(`
    INSERT INTO t_vuln_finding(task_id,agent_id,cve_id,software,installed_version,fixed_version,severity)
    VALUES (0,?,'CVE-2099-0001','alinksec-smoke-package','1.0','2.0',3) RETURNING id`, agent.id)[0].id }))
  const task = await api('/api/fix/tasks/package', { items: findings, approver: 'CI', name: 'Actual Agent repair' })
  assert.equal(task.pendingApprove, true)
  await api(`/api/fix/tasks/${task.taskId}/approve`, { operator: 'CI' })
  async function fixed(agent) {
    await until(() => sql('SELECT status FROM t_fix_record WHERE task_id=? AND agent_id=?', task.taskId, agent.id)[0]?.status !== 0,
      'Agent did not return package result', 60_000)
    const record = sql('SELECT status,log FROM t_fix_record WHERE task_id=? AND agent_id=?', task.taskId, agent.id)[0]
    assert.equal(record.status, 1, record.log)
    assert.equal(await command('docker', ['exec', agent.container, 'dpkg-query', '-W', '-f=${Version}', 'alinksec-smoke-package']), '2.0')
  }
  await fixed(second)
  await stopAgent(second)
  await startAgent(first)
  await fixed(first)
  assert.equal(sql('SELECT status FROM t_fix_task WHERE id=?', task.taskId)[0].status, 2)
  assert.ok(findings.every(item => sql('SELECT status FROM t_vuln_finding WHERE id=?', item.findingId)[0].status === 3))
  assert.equal(new X509Certificate(readFileSync(join(root, 'data/certs/server.crt'))).checkHost('ci.alinksec.test'), 'ci.alinksec.test')
  console.log('ok - two actual Agents serially install CA-verified packages and complete approved findings')
  await stopAgent(first)
  const oldCA = new X509Certificate(readFileSync(join(root, 'data/certs/ca.crt'))).fingerprint256
  await stopServer()
  accessHost = 'ci-repaired.alinksec.test'
  await startServer(accessHost, true)
  rmSync(join(root, 'data/certs'), { recursive: true })
  rmSync(join(root, 'data/web-tls'), { recursive: true })
  await startServer()
  proxy.setSecureContext({ key: readFileSync(join(root, 'data/web-tls/server.key')),
    cert: readFileSync(join(root, 'data/web-tls/server.crt')) })
  const newCA = new X509Certificate(readFileSync(join(root, 'data/certs/ca.crt'))).fingerprint256
  assert.notEqual(newCA, oldCA)
  sql('UPDATE t_agent SET status=2 WHERE agent_id=? RETURNING id', first.id)
  writeFileSync(join(first.fixtures, 'agent.yml'), `server_addr: ${accessHost}:${grpcPort}\nheartbeat_interval: 1s\ncollect_interval: 24h\ndecoy:\n  enabled: false\n`)
  const previousAgentLog = (await command('docker', ['logs', first.container])).length
  await command('docker', ['start', first.container])
  await until(async () => /unknown authority|certificate signed/.test((await command('docker', ['logs', first.container])).slice(previousAgentLog)),
    'Old Agent CA was not rejected', 30_000)
  assert.equal(sql('SELECT status FROM t_agent WHERE agent_id=?', first.id)[0].status, 2)
  await stopAgent(first)
  const machineId = readFileSync(join(first.fixtures, 'machine-id'), 'utf8').trim()
  sql('DELETE FROM t_agent WHERE agent_id=? RETURNING id', first.id)
  const repaired = await makeAgent('repaired', machineId)
  assert.notEqual(repaired.id, first.id)
  assert.equal(new X509Certificate(readFileSync(join(repaired.dir, 'work/certs/ca.crt'))).fingerprint256, newCA)
  assert.equal(new X509Certificate(readFileSync(join(root, 'data/certs/server.crt'))).checkHost(accessHost), accessHost)
  console.log('ok - stale SAN blocks startup; new CA rejects old Agent trust and permits re-enrollment')
  passed = true
} finally {
  let cleanupFailed = false
  for (const id of containers) {
    try { writeFileSync(join(root, `${id.slice(0, 12)}.log`), await command('docker', ['logs', id])) } catch {}
    try { await exec('docker', ['rm', '-f', id], { timeout: 30_000 }) } catch { cleanupFailed = true }
  }
  if (proxy) await new Promise(ok => proxy.close(ok))
  if (business) await new Promise(ok => business.close(ok))
  await stopServer()
  if (passed && !cleanupFailed) rmSync(root, { recursive: true, force: true })
  else console.error(`Validation artifacts: ${root}`)
  if (cleanupFailed) throw new Error('Could not remove Agent validation containers')
}
