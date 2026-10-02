import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const root = fileURLToPath(new URL('../../', import.meta.url))
const read = name => readFileSync(new URL(`../../${name}`, import.meta.url), 'utf8')
const version = read('VERSION').trim()
assert.match(version, /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/)
if (process.argv[2]) assert.equal(process.argv[2], `v${version}`, 'Tag must match VERSION')
assert.equal(JSON.parse(read('web/package.json')).version, version)
const lock = JSON.parse(read('web/package-lock.json'))
assert.equal(lock.version, version)
assert.equal(lock.packages[''].version, version)
assert.equal(read('agent/internal/identity/identity.go').match(/^const AgentVersion = "([^"]+)"$/m)?.[1], version)
execFileSync(process.env.JAVA_BIN || 'java', ['-Xmx64m', `${root}deploy/release/CheckVersion.java`, root, version], { stdio: 'inherit' })
for (const [file, components] of [
  ['docker-compose.yml', ['server', 'web']],
  ['docker-compose.lite.yml', ['server', 'web', 'sqlite-maintenance']],
]) {
  const config = JSON.parse(execFileSync('docker', ['compose', '--env-file', '/dev/null', '-f',
    `${root}deploy/docker/${file}`, '--profile', 'maintenance', 'config', '--format', 'json'], {
    encoding: 'utf8', env: { ...process.env, HOST_IP: 'release.alinksec.test', ALINKSEC_BIND_ADDRESS: '127.0.0.1',
      ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD: 'release-version-fixture', ALINKSEC_BOOTSTRAP_ENROLL_TOKEN: 'ENROLL-version-fixture',
      ALINKSEC_POSTGRES_PASSWORD: 'release-owner-fixture', ALINKSEC_POSTGRES_APP_PASSWORD: 'release-app-fixture',
      ALINKSEC_SERVER_IMAGE: '', ALINKSEC_WEB_IMAGE: '', ALINKSEC_SQLITE_MAINTENANCE_IMAGE: '' },
  }))
  for (const component of components) assert.equal(config.services[component].image, `wangyanbiao/alinksec:${component}-v${version}`)
}
console.log(`Release versions and default images match v${version}`)
