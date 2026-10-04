import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { createHash, randomUUID } from 'node:crypto'
import { appendFileSync, closeSync, mkdirSync, mkdtempSync, openSync, readFileSync,
  readdirSync, rmSync, statSync, writeFileSync } from 'node:fs'
import net from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

assert.equal(process.env.ALINKSEC_MAINTENANCE_TEST_ALLOW_FIXTURES, 'true')
const scriptDir = dirname(fileURLToPath(import.meta.url))
const repoDir = resolve(scriptDir, '../..')
const testRoot = mkdtempSync(join(repoDir, '.tmp/sqlite-maintenance-local.'))
const dataDir = join(testRoot, 'data')
const backupDir = join(testRoot, 'backups')
const dbFile = join(dataDir, 'alinksec.db')
const composeFile = join(testRoot, 'compose.json')
const envFile = join(testRoot, 'env.lite')
const password = 'maintenance-smoke-admin-password'
const fixtureId = `ci-maintenance-${randomUUID()}`
const projectName = `alinksec-maintenance-${process.pid}-${randomUUID().slice(0, 8)}`
const abort = new AbortController()
const exec = promisify(execFile)
let server
let writer
let serverRun = 0
let composeCreated = false
let passed = false
let checks = 0
for (const signal of ['SIGINT', 'SIGTERM']) {
  process.once(signal, () => {
    abort.abort(new Error(`Validation interrupted by ${signal}`))
    server?.child.kill('SIGTERM')
  })
}

async function command(executable, args, options = {}) {
  try {
    const result = await exec(executable, args, { encoding: 'utf8', timeout: 60_000,
      maxBuffer: 2 * 1024 * 1024, signal: abort.signal, ...options })
    appendFileSync(join(testRoot, 'maintenance.log'), result.stdout + result.stderr)
    return result.stdout.trim()
  } catch (error) {
    appendFileSync(join(testRoot, 'maintenance.log'), `${error.message}\n${error.stdout || ''}${error.stderr || ''}`)
    throw error
  }
}

const composeArgs = ['compose', '-p', projectName, '--env-file', envFile, '-f', composeFile, '--profile', 'maintenance']
async function sql(file, statement) {
  return command('docker', [...composeArgs, 'run', '--rm', '-T', '--no-deps',
    'sqlite-maintenance', file, statement])
}

async function maintenance(...args) {
  return command('bash', [join(repoDir, 'deploy/sqlite-maintenance.sh'), ...args], {
    env: { ...process.env, ALINKSEC_LITE_COMPOSE_FILE: composeFile,
      ALINKSEC_LITE_ENV_FILE: envFile, ALINKSEC_BACKUP_DIR: backupDir, COMPOSE_PROJECT_NAME: projectName },
  })
}

function query(file, statement) {
  const db = new DatabaseSync(file, { readOnly: true })
  try {
    db.exec('PRAGMA busy_timeout=5000;')
    return db.prepare(statement).all()
  } finally {
    db.close()
  }
}

function digest(file) {
  return createHash('sha256').update(readFileSync(file)).digest('hex')
}

function check(message) {
  checks++
  console.log(`ok - ${message}`)
}

async function stopServer() {
  if (!server) return
  const current = server
  current.child.kill('SIGTERM')
  const timer = setTimeout(() => current.child.kill('SIGKILL'), 15_000)
  try { await current.closed } finally { clearTimeout(timer); server = undefined }
}

let httpPort
async function request(path, { token, body } = {}) {
  const response = await fetch(`http://127.0.0.1:${httpPort}${path}`, {
    method: body ? 'POST' : 'GET',
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.any([abort.signal, AbortSignal.timeout(2000)]),
  })
  assert.equal(response.status, 200, path)
  const result = await response.json()
  assert.equal(result.code, 0, `${path}: ${result.msg}`)
  return result.data
}

async function startServer(expectFailure = false) {
  assert.equal(server, undefined)
  abort.signal.throwIfAborted()
  const log = join(testRoot, `server-${++serverRun}.log`)
  const fd = openSync(log, 'a')
  const child = spawn(process.env.JAVA_BIN, ['-Xmx256m', '-XX:MaxMetaspaceSize=128m',
    '-XX:ActiveProcessorCount=1', '-jar',
    join(repoDir, 'server/alinksec-bootstrap/target/alinksec-bootstrap.jar'),
    '--server.address=127.0.0.1', `--server.port=${httpPort}`, '--alinksec.server.port=0'], {
    cwd: testRoot, stdio: ['ignore', fd, fd], env: {
      ...process.env, SPRING_PROFILES_ACTIVE: 'sqlite', ALINKSEC_METRICS_ENABLED: 'false',
      ALINKSEC_SQLITE_PATH: dbFile, ALINKSEC_CERT_DIR: join(dataDir, 'certs'),
      ALINKSEC_WEB_TLS_DIR: join(dataDir, 'web-tls'), ALINKSEC_SIG_DIR: join(dataDir, 'signature'),
      ALINKSEC_PATCH_DIR: join(dataDir, 'patch'), ALINKSEC_UPGRADE_DIR: join(dataDir, 'agent-upgrade'),
      ALINKSEC_PUBLIC_HOST: '', ALINKSEC_SERVER_TLS_SANS: 'localhost,127.0.0.1,::1',
      ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD: password, ALINKSEC_BOOTSTRAP_ENROLL_TOKEN: 'ENROLL-maintenance-smoke',
      ALINKSEC_JWT_SECRET: '',
    },
  })
  closeSync(fd)
  const current = { child, log }
  current.closed = new Promise(resolve => {
    child.once('close', (code, signal) => { current.result = { code, signal }; resolve(current.result) })
    child.once('error', error => { current.result = { error }; resolve(current.result) })
  })
  server = current
  if (expectFailure) {
    const result = await Promise.race([current.closed,
      delay(30_000, undefined, { ref: false, signal: abort.signal }).then(() => {
        throw new Error('Incompatible restored database did not stop the application')
      })])
    assert.notEqual(result.code, 0)
    assert.match(readFileSync(log, 'utf8'), /Checksum mismatch for SQLite migration V001/)
    server = undefined
    return
  }
  for (let attempt = 0; attempt < 90; attempt++) {
    abort.signal.throwIfAborted()
    assert.equal(current.result, undefined, `Server exited during startup: ${log}`)
    try {
      return (await request('/api/auth/login', { body: { username: 'admin', password } })).token
    } catch (error) {
      if (attempt === 89) throw error
      await delay(500, undefined, { signal: abort.signal })
    }
  }
}

async function assertHost(token, version, isolationStatus) {
  const host = await request(`/api/hosts/${fixtureId}`, { token })
  assert.equal(host.hostname, 'maintenance-persistent-host')
  assert.equal(host.status, 2)
  assert.equal(host.isolation_status, isolationStatus)
  const software = await request(`/api/hosts/${fixtureId}/software`, { token })
  assert.equal(software.length, 1)
  assert.equal(software[0].version, version)
}

try {
  mkdirSync(dataDir)
  mkdirSync(backupDir, { mode: 0o700 })
  writeFileSync(envFile, '')
  const config = JSON.parse(await command('docker', ['compose', '-f',
    join(repoDir, 'deploy/docker/docker-compose.lite.yml'), '--profile', 'maintenance',
    'config', '--format', 'json'], {
    env: { ...process.env, HOST_IP: 'ci.alinksec.test', ALINKSEC_BIND_ADDRESS: '127.0.0.1',
      ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD: password, ALINKSEC_BOOTSTRAP_ENROLL_TOKEN: 'ENROLL-maintenance-smoke',
      ALINKSEC_BACKUP_DIR: backupDir },
  }))
  const service = config.services['sqlite-maintenance']
  assert.deepEqual(service.entrypoint, ['/usr/bin/sqlite3'])
  assert.equal(service.user, '0:0')
  assert.deepEqual(service.cap_add, ['DAC_OVERRIDE'])
  assert.equal(Number(service.mem_limit), 64 * 1024 * 1024)
  service.image = process.env.ALINKSEC_MAINTENANCE_TEST_IMAGE || service.image
  await command('docker', ['image', 'inspect', service.image])
  service.network_mode = 'none'
  delete service.networks
  service.volumes = [
    { type: 'bind', source: dataDir, target: '/data' },
    { type: 'bind', source: backupDir, target: '/backups' },
  ]
  writeFileSync(composeFile, JSON.stringify({ name: projectName,
    services: { 'sqlite-maintenance': service } }, null, 2))
  composeCreated = true
  const version = await command('docker', [...composeArgs, 'run', '--rm', '-T', '--no-deps',
    'sqlite-maintenance', '--version'])
  assert.match(version, /^3\.46\.1\s/, 'Use SQLite 3.46.1, matching the production maintenance version')
  console.log(`SQLite maintenance image: ${service.image}`)
  check('production maintenance entrypoint, volume user and CLI version')

  httpPort = await new Promise((resolve, reject) => {
    const socket = net.createServer()
    socket.once('error', reject)
    socket.listen(0, '127.0.0.1', () => {
      const port = socket.address().port
      socket.close(() => resolve(port))
    })
  })
  const token = await startServer()
  writer = new DatabaseSync(dbFile)
  writer.exec('PRAGMA busy_timeout=5000; PRAGMA wal_autocheckpoint=0; PRAGMA wal_checkpoint(TRUNCATE);')
  assert.equal(writer.prepare('PRAGMA journal_mode').get().journal_mode, 'wal')
  writer.prepare(`INSERT INTO t_agent(agent_id, hostname, os_type, status, isolation_status)
    VALUES (?, 'maintenance-persistent-host', 1, 2, 2)`).run(fixtureId)
  writer.prepare(`INSERT INTO t_asset_software(agent_id, name, version)
    VALUES (?, 'maintenance-persistent-software', '1.0')`).run(fixtureId)
  assert.ok(statSync(`${dbFile}-wal`).size > 32, 'Committed fixture writes must remain in WAL')
  const migrations = query(dbFile, 'SELECT version, checksum, applied_at FROM t_schema_migration ORDER BY version')
  assert.deepEqual(migrations.map(migration => migration.version), ['001', '002', '003', '004'])
  await maintenance('backup', 'online.db')
  await maintenance('verify', 'online.db')
  assert.equal(query(join(backupDir, 'online.db'), 'SELECT version FROM t_asset_software')[0].version, '1.0')
  assert.deepEqual(query(join(backupDir, 'online.db'),
    'SELECT version, checksum, applied_at FROM t_schema_migration ORDER BY version'), migrations)
  await assertHost(token, '1.0', 2)
  check('online VACUUM backup includes committed WAL assets and migration history')

  const onlineHash = digest(join(backupDir, 'online.db'))
  await assert.rejects(maintenance('backup', 'online.db'), error => /backup already exists/.test(error.stderr))
  assert.equal(digest(join(backupDir, 'online.db')), onlineHash)
  await assert.rejects(maintenance('backup', '../escape.db'), error => /backup name must contain/.test(error.stderr))
  await assert.rejects(maintenance('verify', 'missing.db'), error => /backup not found/.test(error.stderr))
  writeFileSync(join(backupDir, 'corrupt.db'), 'This is not a SQLite database')
  await assert.rejects(maintenance('restore', 'corrupt.db', '--yes'),
    error => /integrity check failed/.test(error.stderr))
  assert.equal(readdirSync(backupDir).some(name => name.startsWith('pre-restore-')), false)
  assert.equal(server.result, undefined, 'Rejected restore must leave the application running')
  assert.equal(digest(join(backupDir, 'online.db')), onlineHash)
  await assertHost(token, '1.0', 2)
  check('duplicate, unsafe, missing and corrupt backups fail without stopping or overwriting data')

  writer.prepare('UPDATE t_asset_software SET version=? WHERE agent_id=?').run('1.1', fixtureId)
  writer.prepare('UPDATE t_agent SET isolation_status=? WHERE agent_id=?').run(4, fixtureId)
  await assertHost(token, '1.1', 4)
  await maintenance('backup', 'safety.db')
  writer.close()
  writer = undefined
  await stopServer()
  await sql('/data/alinksec.db', '.restore /backups/online.db')
  assert.equal(await sql('/data/alinksec.db', 'PRAGMA integrity_check;'), 'ok')
  await startServer()
  await assertHost(token, '1.0', 2)
  assert.deepEqual(query(dbFile, 'SELECT version, checksum, applied_at FROM t_schema_migration ORDER BY version'), migrations)
  check('CLI restore and real application restart recover assets, isolation state, JWT and migration history')

  await sql('/backups/online.db', "VACUUM INTO '/backups/incompatible.db';")
  await sql('/backups/incompatible.db', "UPDATE t_schema_migration SET checksum='incompatible-release';")
  assert.equal(await sql('/backups/incompatible.db', 'PRAGMA integrity_check;'), 'ok')
  await stopServer()
  await sql('/data/alinksec.db', '.restore /backups/incompatible.db')
  await startServer(true)
  await sql('/data/alinksec.db', '.restore /backups/safety.db')
  assert.equal(await sql('/data/alinksec.db', 'PRAGMA integrity_check;'), 'ok')
  await startServer()
  await assertHost(token, '1.1', 4)
  assert.deepEqual(query(dbFile, 'SELECT version, checksum, applied_at FROM t_schema_migration ORDER BY version'), migrations)
  check('incompatible restored migration stops startup; restoring the safety snapshot recovers newer data')

  await command(process.execPath, ['--test', '--test-concurrency=1', join(scriptDir, 'api-smoke.test.mjs')], {
    env: { ...process.env, ALINKSEC_SMOKE_DB: 'sqlite', ALINKSEC_SMOKE_ALLOW_FIXTURES: 'true',
      ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD: password, ALINKSEC_SMOKE_BASE_URL: `http://127.0.0.1:${httpPort}`,
      ALINKSEC_SMOKE_SQLITE_FILE: dbFile },
  })
  check('shared API contracts pass after safety snapshot recovery')
  console.log(`${checks} real SQLite maintenance checks passed.`)
  passed = true
} catch (error) {
  console.error(error)
  process.exitCode = 1
} finally {
  try { writer?.close() } catch (error) { console.error(error); passed = false; process.exitCode = 1 }
  await stopServer()
  if (composeCreated) {
    try { await command('docker', [...composeArgs, 'down', '--remove-orphans'], { signal: undefined }) }
    catch (error) { console.error(error); passed = false; process.exitCode = 1 }
  }
  if (passed && !abort.signal.aborted) rmSync(testRoot, { recursive: true })
  else {
    process.exitCode = 1
    console.error(`Validation artifacts: ${testRoot}`)
  }
}
