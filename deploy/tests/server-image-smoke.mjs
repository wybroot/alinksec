import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { randomUUID, X509Certificate } from 'node:crypto'
import { existsSync, readFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import tls from 'node:tls'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

assert.equal(process.env.ALINKSEC_SMOKE_ALLOW_FIXTURES, 'true')
const baseUrl = new URL(process.env.ALINKSEC_SMOKE_BASE_URL)
assert.equal(baseUrl.hostname, '127.0.0.1')
const containerId = process.env.ALINKSEC_SMOKE_CONTAINER_ID
assert.match(containerId, /^[a-f0-9]{64}$/)
const databaseFile = process.env.ALINKSEC_SMOKE_SQLITE_FILE
const dataDir = dirname(databaseFile)
let grpcPort = Number(process.env.ALINKSEC_SMOKE_GRPC_PORT)
assert.ok(Number.isInteger(grpcPort) && grpcPort > 0 && grpcPort < 65536)

async function request(path, { token, body } = {}) {
  const response = await fetch(new URL(path, baseUrl), {
    method: body ? 'POST' : 'GET',
    headers: { ...(token ? { Authorization: `Bearer ${token}` } : {}),
      ...(body ? { 'Content-Type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
    signal: AbortSignal.timeout(2000),
  })
  assert.equal(response.status, 200, path)
  const result = await response.json()
  assert.equal(result.code, 0, path)
  return result.data
}

async function ready() {
  for (let attempt = 0; attempt < 90; attempt++) {
    assert.equal(execFileSync('docker', ['inspect', '--format', '{{.State.Running}}', containerId],
      { encoding: 'utf8', timeout: 5000 }).trim(), 'true', 'Server container stopped during startup')
    try {
      return (await request('/api/auth/login', { body: {
        username: 'admin', password: process.env.ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD,
      } })).token
    } catch (error) {
      if (attempt === 89) throw error
      await delay(500)
    }
  }
}

function database(callback) {
  const db = new DatabaseSync(databaseFile)
  try {
    db.exec('PRAGMA busy_timeout = 5000;')
    return callback(db)
  } finally {
    db.close()
  }
}

async function checkTls() {
  const ca = readFileSync(join(dataDir, 'certs/ca.crt'))
  const certificate = new X509Certificate(readFileSync(join(dataDir, 'certs/server.crt')))
  assert.equal(certificate.checkHost('ci.alinksec.test'), 'ci.alinksec.test')
  assert.equal(certificate.checkIP('127.0.0.1'), '127.0.0.1')
  assert.ok(certificate.verify(new X509Certificate(ca).publicKey))
  assert.equal(existsSync(join(dataDir, 'web-tls/ca.key')), false)
  assert.equal(existsSync(join(dataDir, 'web-tls/ca.crt')), false)
  assert.equal(new X509Certificate(readFileSync(join(dataDir, 'web-tls/server.crt'))).fingerprint256,
    certificate.fingerprint256)
  const handshake = () => new Promise((resolve, reject) => {
    const socket = tls.connect({ host: '127.0.0.1', port: grpcPort, ca,
      servername: 'ci.alinksec.test', ALPNProtocols: ['h2'] })
    socket.setTimeout(5000, () => socket.destroy(new Error('gRPC TLS handshake timed out')))
    socket.once('error', reject)
    socket.once('secureConnect', () => {
      try {
        assert.equal(socket.authorized, true)
        assert.equal(socket.alpnProtocol, 'h2')
        assert.equal(socket.getPeerCertificate().fingerprint256, certificate.fingerprint256)
        socket.end()
        resolve()
      } catch (error) {
        socket.destroy()
        reject(error)
      }
    })
  })
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      await handshake()
      return certificate.fingerprint256
    } catch (error) {
      if (attempt === 59 || !['ECONNREFUSED', 'ECONNRESET'].includes(error.code)) throw error
      await delay(500)
    }
  }
}

const token = await ready()
await request('/api/health')
const fingerprint = await checkTls()
console.log('ok - server image boots with SQLite and a CA-verified gRPC TLS endpoint')
execFileSync(process.execPath, ['--test', '--test-concurrency=1',
  fileURLToPath(new URL('./api-smoke.test.mjs', import.meta.url))], { stdio: 'inherit', timeout: 90_000 })

const agentId = `ci-image-${randomUUID()}`
const migrations = database(db => {
  db.prepare(`INSERT INTO t_agent(agent_id, hostname, os_type, status, isolation_status)
    VALUES (?, 'image-persistent-host', 1, 2, 2)`).run(agentId)
  db.prepare(`INSERT INTO t_asset_software(agent_id, name, version)
    VALUES (?, 'image-persistent-software', '1.0')`).run(agentId)
  return db.prepare('SELECT version, checksum, applied_at FROM t_schema_migration ORDER BY version').all()
})
assert.equal(migrations.length, 1)
execFileSync('docker', ['restart', '--timeout', '15', containerId], { timeout: 30_000, stdio: 'pipe' })
// Docker may allocate new ephemeral host ports when the same container restarts.
const ports = JSON.parse(execFileSync('docker', ['inspect', '--format',
  '{{json .NetworkSettings.Ports}}', containerId], { encoding: 'utf8', timeout: 5000 }))
for (const port of ['8080/tcp', '9443/tcp']) {
  assert.equal(ports[port][0].HostIp, '127.0.0.1')
}
baseUrl.port = ports['8080/tcp'][0].HostPort
grpcPort = Number(ports['9443/tcp'][0].HostPort)
await ready()
await request('/api/health')
const host = await request(`/api/hosts/${agentId}`, { token })
assert.equal(host.hostname, 'image-persistent-host')
assert.equal(host.status, 2)
assert.equal(host.isolation_status, 2)
const software = await request(`/api/hosts/${agentId}/software`, { token })
assert.equal(software.length, 1)
assert.equal(software[0].name, 'image-persistent-software')
assert.deepEqual(database(db => db.prepare(
  'SELECT version, checksum, applied_at FROM t_schema_migration ORDER BY version').all()), migrations)
assert.equal(await checkTls(), fingerprint)
console.log('ok - container restart preserves assets, isolation, JWT, certificates and migration history')
