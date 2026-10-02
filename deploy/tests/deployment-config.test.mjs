import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { resolve } from 'node:path'
import test from 'node:test'

const root = resolve(new URL('../..', import.meta.url).pathname)
const environment = { ...process.env, HOST_IP: 'ci.alinksec.test', ALINKSEC_BIND_ADDRESS: '127.0.0.1',
  ALINKSEC_POSTGRES_PASSWORD: 'config-owner-fixture', ALINKSEC_POSTGRES_APP_PASSWORD: 'config-app-fixture',
  ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD: 'config-admin-fixture', ALINKSEC_BOOTSTRAP_ENROLL_TOKEN: 'ENROLL-config-fixture' }
function config(file, overrides = {}) {
  return JSON.parse(execFileSync('docker', ['compose', '--env-file', '/dev/null', '-f',
    `${root}/deploy/docker/${file}`, '--profile', 'maintenance', 'config', '--format', 'json'],
  { encoding: 'utf8', env: { ...environment, ...overrides }, stdio: ['ignore', 'pipe', 'pipe'] }))
}

for (const file of ['docker-compose.yml', 'docker-compose.lite.yml']) {
  test(`${file}: missing access host or bind address rejects configuration`, () => {
    for (const field of ['HOST_IP', 'ALINKSEC_BIND_ADDRESS']) {
      assert.throws(() => config(file, { [field]: '' }), error => error.stderr.includes(field))
    }
  })
  test(`${file}: explicit port binding, SAN and download address`, () => {
    const services = config(file).services
    const ports = Object.values(services).flatMap(service => service.ports || [])
    assert.deepEqual(ports.map(port => Number(port.published)).sort((a, b) => a - b), [8081, 8443, 9443])
    assert.ok(ports.every(port => port.host_ip === environment.ALINKSEC_BIND_ADDRESS))
    assert.ok(services.server.environment.ALINKSEC_SERVER_TLS_SANS.split(',').includes(environment.HOST_IP))
    assert.equal(services.server.environment.ALINKSEC_SIG_BASE, `${environment.HOST_IP}:8443`)
    assert.equal(services.web.volumes.find(volume => volume.target === '/etc/nginx/tls').read_only, true)
  })
  test(`${file}: image digest overrides are preserved`, () => {
    const overrides = { ALINKSEC_SERVER_IMAGE: `wangyanbiao/alinksec@sha256:${'a'.repeat(64)}`,
      ALINKSEC_WEB_IMAGE: `wangyanbiao/alinksec@sha256:${'b'.repeat(64)}`,
      ALINKSEC_SQLITE_MAINTENANCE_IMAGE: `wangyanbiao/alinksec@sha256:${'c'.repeat(64)}` }
    const services = config(file, overrides).services
    assert.equal(services.server.image, overrides.ALINKSEC_SERVER_IMAGE)
    assert.equal(services.web.image, overrides.ALINKSEC_WEB_IMAGE)
    if (services['sqlite-maintenance']) assert.equal(services['sqlite-maintenance'].image, overrides.ALINKSEC_SQLITE_MAINTENANCE_IMAGE)
  })
}
test('PostgreSQL: application credentials are separate and migration gates startup', () => {
  const services = config('docker-compose.yml').services
  assert.equal(services.server.environment.PG_USER, 'alinksec_app')
  assert.notEqual(services.server.environment.PG_PASSWORD, services.postgres.environment.POSTGRES_PASSWORD)
  assert.equal(services.migrate.environment.PGUSER, services.postgres.environment.POSTGRES_USER)
  assert.equal(services.server.depends_on.migrate.condition, 'service_completed_successfully')
  assert.equal(services.postgres.ports, undefined)
  assert.equal(services.victoriametrics.ports, undefined)
})
test('SQLite: maintenance profile is isolated and resource limited', () => {
  const services = config('docker-compose.lite.yml').services
  const tool = services['sqlite-maintenance']
  assert.equal(services.server.environment.SPRING_PROFILES_ACTIVE, 'sqlite')
  assert.deepEqual(tool.profiles, ['maintenance'])
  assert.deepEqual(tool.entrypoint, ['/usr/bin/sqlite3'])
  assert.equal(tool.user, '0:0')
  assert.equal(tool.network_mode, 'none')
  assert.deepEqual(tool.cap_drop, ['ALL'])
  assert.deepEqual(tool.cap_add, ['DAC_OVERRIDE'])
  assert.ok(tool.security_opt.includes('no-new-privileges:true'))
  assert.equal(Number(tool.mem_limit), 64 * 1024 * 1024)
  assert.equal(Number(tool.memswap_limit), 96 * 1024 * 1024)
  assert.equal(Number(tool.cpus), 1)
  assert.equal(tool.pids_limit, 32)
})
test('SQLite: application containers keep bounded memory and CPU', () => {
  const services = config('docker-compose.lite.yml').services
  assert.equal(Number(services.server.mem_limit), 512 * 1024 * 1024)
  assert.equal(Number(services.server.memswap_limit), 768 * 1024 * 1024)
  assert.equal(Number(services.server.cpus), 1)
  assert.equal(services.server.pids_limit, 128)
  assert.ok(services.server.environment.JAVA_TOOL_OPTIONS.includes('-Xmx256m'))
  assert.equal(Number(services.web.mem_limit), 96 * 1024 * 1024)
  assert.equal(Number(services.web.memswap_limit), 128 * 1024 * 1024)
  assert.equal(Number(services.web.cpus), 0.25)
  assert.equal(services.web.pids_limit, 64)
})
