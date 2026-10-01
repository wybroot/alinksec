import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { closeSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync } from 'node:fs'
import net from 'node:net'
import { dirname, join, resolve } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'
import { promisify } from 'node:util'

assert.equal(process.env.ALINKSEC_SMOKE_ALLOW_FIXTURES, 'true')
const repo = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const root = mkdtempSync(join(repo, '.tmp/postgres-validation.'))
const exec = promisify(execFile)
const password = 'postgres-validation-admin-password'
const env = { PGHOST: '127.0.0.1', PGDATABASE: 'alinksec', PGUSER: 'alinksec',
  PGPASSWORD: 'postgres-validation-owner', ALINKSEC_APP_DB_USER: 'alinksec_app',
  ALINKSEC_APP_DB_PASSWORD: 'postgres-validation-app', ALINKSEC_BIND_ADDRESS: '127.0.0.1',
  ALINKSEC_MIGRATIONS_DIR: '/tmp/alinksec-validation/deploy/migrations' }
let container, server, passed = false
const controller = new AbortController()
for (const signal of ['SIGINT', 'SIGTERM']) process.once(signal, () => {
  controller.abort(new Error(signal))
  server?.child.kill('SIGTERM')
})
async function command(executable, args, options = {}) {
  try {
    const result = await exec(executable, args, { encoding: 'utf8', timeout: 120_000,
      maxBuffer: 4 * 1024 * 1024, signal: controller.signal, ...options })
    if (options.log) console.log(result.stdout.trim())
    return result.stdout.trim()
  } catch (error) {
    console.error(error.stdout || '', error.stderr || '')
    throw error
  }
}
function dockerExecEnvironment(values) {
  return Object.entries(values).flatMap(([key, value]) => ['-e', `${key}=${value}`])
}
async function owner(...args) {
  return command('docker', ['exec', ...dockerExecEnvironment(Object.fromEntries(Object.entries(env)
    .filter(([key]) => key.startsWith('PG') || key.startsWith('ALINKSEC_')))), container, ...args])
}
try {
  assert.equal(await command('docker', ['ps', '-q']), '', 'Run PostgreSQL validation after other scenarios stop')
  const image = process.env.ALINKSEC_SMOKE_POSTGRES_IMAGE || 'postgres:17'
  await command('docker', ['image', 'inspect', image])
  container = await command('docker', ['run', '-d', '--rm', '--name', `alinksec-postgres-validation-${process.pid}`,
    '--memory=256m', '--memory-swap=384m', '--cpus=1', '--pids-limit=128',
    '-e', 'POSTGRES_USER=alinksec', '-e', `POSTGRES_PASSWORD=${env.PGPASSWORD}`, '-e', 'POSTGRES_DB=alinksec',
    '--mount', `type=bind,src=${repo}/deploy/sql,dst=/docker-entrypoint-initdb.d,readonly`,
    '--publish', '127.0.0.1::5432', image, 'postgres', '-c', 'shared_buffers=32MB',
    '-c', 'max_connections=20', '-c', 'work_mem=2MB'])
  for (let i = 0; i < 90; i++) {
    try {
      await owner('psql', '-X', '-v', 'ON_ERROR_STOP=1', '-Atc', 'SELECT count(*) FROM t_agent')
      break
    } catch (error) { if (i === 89) throw error; await delay(500) }
  }
  await command('docker', ['exec', container, 'mkdir', '-p', '/tmp/alinksec-validation/deploy'])
  for (const directory of ['sql', 'migrations', 'tests']) {
    await command('docker', ['cp', join(repo, 'deploy', directory), `${container}:/tmp/alinksec-validation/deploy/${directory}`])
  }
  await owner('bash', '/tmp/alinksec-validation/deploy/migrations/run-migrations.sh')
  const dangerous = await owner('psql', '-X', '-Atc', `SELECT NOT (rolsuper OR rolcreatedb OR rolcreaterole OR rolinherit OR rolreplication OR rolbypassrls)
    FROM pg_roles WHERE rolname='alinksec_app'`)
  assert.equal(dangerous, 't')
  console.log(await command('docker', ['exec', ...dockerExecEnvironment({ PGHOST: '127.0.0.1',
    PGDATABASE: 'alinksec', PGUSER: 'alinksec', PGPASSWORD: env.PGPASSWORD,
    ALINKSEC_MIGRATION_TEST_ALLOW_FIXTURES: 'true' }), container, 'bash',
    '/tmp/alinksec-validation/deploy/tests/postgres-migrations.test.sh']))
  const pgPort = await command('docker', ['inspect', '--format', '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}', container])
  const mavenArgs = ['-B', '-ntp', '-T1', '-f', join(repo, 'server/pom.xml'), '-pl', 'alinksec-bootstrap', '-am',
    '-Dtest=AgentChannelSecurityIntegrationTest', '-Dsurefire.failIfNoSpecifiedTests=false',
    '-Dalinksec.integration.database=postgres', '-DargLine=-Xmx192m -XX:MaxMetaspaceSize=128m -XX:ActiveProcessorCount=1', 'test']
  if (process.env.ALINKSEC_MAVEN_REPO) mavenArgs.unshift(`-Dmaven.repo.local=${process.env.ALINKSEC_MAVEN_REPO}`)
  await command(process.env.MAVEN_BIN, mavenArgs, { log: true, env: { ...process.env,
    MAVEN_OPTS: '-Xmx256m -XX:MaxMetaspaceSize=128m -XX:ActiveProcessorCount=1',
    ALINKSEC_INTEGRATION_PG_URL: `jdbc:postgresql://127.0.0.1:${pgPort}/alinksec?stringtype=unspecified`,
    ALINKSEC_INTEGRATION_PG_USER: 'alinksec_app', ALINKSEC_INTEGRATION_PG_PASSWORD: env.ALINKSEC_APP_DB_PASSWORD } })
  const listener = net.createServer()
  await new Promise(ok => listener.listen(0, '127.0.0.1', ok))
  const httpPort = listener.address().port
  await new Promise(ok => listener.close(ok))
  mkdirSync(join(root, 'data'))
  const fd = openSync(join(root, 'server.log'), 'a')
  const child = spawn(process.env.JAVA_BIN, ['-Xmx256m', '-XX:MaxMetaspaceSize=128m', '-XX:ActiveProcessorCount=1',
    '-jar', join(repo, 'server/alinksec-bootstrap/target/alinksec-bootstrap.jar'),
    '--server.address=127.0.0.1', `--server.port=${httpPort}`, '--alinksec.server.port=0'], {
    cwd: root, stdio: ['ignore', fd, fd], env: { ...process.env, SPRING_PROFILES_ACTIVE: 'postgres',
      PG_HOST: '127.0.0.1', PG_PORT: pgPort, PG_USER: 'alinksec_app', PG_PASSWORD: env.ALINKSEC_APP_DB_PASSWORD,
      ALINKSEC_METRICS_ENABLED: 'false', ALINKSEC_CERT_DIR: join(root, 'data/certs'),
      ALINKSEC_WEB_TLS_DIR: join(root, 'data/web-tls'), ALINKSEC_PUBLIC_HOST: '',
      ALINKSEC_SERVER_TLS_SANS: 'localhost,127.0.0.1', ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD: password,
      ALINKSEC_BOOTSTRAP_ENROLL_TOKEN: 'ENROLL-postgres-validation', ALINKSEC_JWT_SECRET: 'postgres-validation-secret' },
  })
  closeSync(fd)
  server = { child, closed: new Promise(ok => child.once('close', ok)) }
  for (let i = 0; i < 90; i++) {
    try {
      const response = await fetch(`http://127.0.0.1:${httpPort}/api/auth/login`, { method: 'POST',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password }),
        signal: AbortSignal.timeout(1000) })
      if ((await response.json()).code === 0) break
    } catch {}
    if (i === 89) throw new Error('PostgreSQL application did not start')
    await delay(500)
  }
  await command(process.execPath, ['--test', '--test-concurrency=1', join(repo, 'deploy/tests/api-smoke.test.mjs')],
    { log: true, env: { ...process.env, ALINKSEC_SMOKE_DB: 'postgres', ALINKSEC_SMOKE_ALLOW_FIXTURES: 'true',
      ALINKSEC_SMOKE_PG_CONTAINER: container, ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD: password,
      ALINKSEC_SMOKE_BASE_URL: `http://127.0.0.1:${httpPort}` } })
  passed = true
} finally {
  if (server) {
    server.child.kill('SIGTERM')
    const timer = setTimeout(() => server.child.kill('SIGKILL'), 15_000)
    await server.closed
    clearTimeout(timer)
  }
  if (container) await exec('docker', ['rm', '-f', container], { timeout: 30_000 })
  if (passed) rmSync(root, { recursive: true, force: true })
  else {
    try { console.error(readFileSync(join(root, 'server.log'), 'utf8').slice(-12_000)) } catch {}
    console.error(`Validation artifacts: ${root}`)
  }
}
