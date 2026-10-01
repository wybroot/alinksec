import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { X509Certificate } from 'node:crypto'
import { readFileSync } from 'node:fs'
import http from 'node:http'
import https from 'node:https'
import { setTimeout as delay } from 'node:timers/promises'
import { fileURLToPath } from 'node:url'

assert.equal(process.env.ALINKSEC_SMOKE_ALLOW_FIXTURES, 'true')
const baseUrl = new URL(process.env.ALINKSEC_SMOKE_BASE_URL)
assert.equal(baseUrl.protocol, 'https:')
assert.equal(baseUrl.hostname, '127.0.0.1')
const containerId = process.env.ALINKSEC_SMOKE_CONTAINER_ID
assert.match(containerId, /^[a-f0-9]{64}$/)
const httpPort = Number(process.env.ALINKSEC_SMOKE_HTTP_PORT)
assert.ok(Number.isInteger(httpPort) && httpPort > 0 && httpPort < 65536)
const ca = readFileSync(process.env.ALINKSEC_SMOKE_CA_FILE)

function request(path, options = {}, url = baseUrl) {
  const transport = url.protocol === 'https:' ? https : http
  return new Promise((resolve, reject) => {
    const req = transport.request(new URL(path, url), { ca, ...options }, res => {
      const chunks = []
      const peer = res.socket.getPeerCertificate?.()
      res.on('data', chunk => chunks.push(chunk))
      res.on('error', reject)
      res.on('end', () => resolve({ status: res.statusCode, headers: res.headers,
        body: Buffer.concat(chunks), certificate: peer?.raw }))
    })
    req.on('error', reject)
    req.setTimeout(5000, () => req.destroy(new Error(`${path}: timeout`)))
    req.end()
  })
}

for (let attempt = 0; attempt < 60; attempt++) {
  assert.equal(execFileSync('docker', ['inspect', '--format', '{{.State.Running}}', containerId],
    { encoding: 'utf8', timeout: 5000 }).trim(), 'true', 'Web container stopped during startup')
  try {
    const health = await request('/api/health')
    assert.equal(health.status, 200)
    assert.equal(JSON.parse(health.body).code, 0)
    break
  } catch (error) {
    if (attempt === 59) throw error
    await delay(500)
  }
}

const redirect = await request('/hosts?keyword=ci-smoke', {}, new URL(`http://127.0.0.1:${httpPort}`))
assert.equal(redirect.status, 308)
assert.equal(redirect.headers.location, 'https://127.0.0.1:8443/hosts?keyword=ci-smoke')
await assert.rejects(request('/api/health', { ca: undefined }),
  error => ['UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'SELF_SIGNED_CERT_IN_CHAIN',
    'DEPTH_ZERO_SELF_SIGNED_CERT'].includes(error.code))
await assert.rejects(request('/api/health', { servername: 'wrong.alinksec.test' }),
  error => error.code === 'ERR_TLS_CERT_ALTNAME_INVALID')
const index = await request('/index.html')
assert.equal(index.status, 200)
assert.match(index.headers['content-type'], /^text\/html/)
assert.match(index.headers['cache-control'], /no-cache/)
assert.equal(index.headers['x-content-type-options'], 'nosniff')
assert.equal(index.headers['x-frame-options'], 'DENY')
assert.equal(index.headers['referrer-policy'], 'no-referrer')
assert.match(index.headers['content-security-policy'], /script-src 'self'/)
assert.match(index.headers['content-security-policy'], /frame-ancestors 'none'/)
assert.equal(new X509Certificate(index.certificate).checkHost('ci.alinksec.test'), 'ci.alinksec.test')
for (const version of ['TLSv1.2', 'TLSv1.3']) {
  assert.equal((await request('/api/health', { minVersion: version, maxVersion: version })).status, 200)
}
console.log('ok - web image verifies platform CA, certificate SAN, HTTPS redirect and security headers')

for (const path of ['/', '/login', '/dashboard', '/hosts', '/vuln', '/protect', '/screen']) {
  const page = await request(path)
  assert.equal(page.status, 200, path)
  assert.match(page.headers['content-type'], /^text\/html/, path)
  assert.deepEqual(page.body, index.body, `${path}: SPA fallback`)
}
const assets = execFileSync('docker', ['exec', containerId, 'find', '/usr/share/nginx/html/assets',
  '-type', 'f'], { encoding: 'utf8', timeout: 5000 }).trim().split('\n')
assert.ok(assets.length > 10, 'Expected built route chunks and styles')
const entryScripts = assets.filter(path => /\/index-[\w-]+\.js$/.test(path)
  && index.body.toString().includes(path.replace('/usr/share/nginx/html', '')))
assert.equal(entryScripts.length, 1, 'index.html must reference a built application entry')
for (const asset of assets) {
  assert.match(asset, /^\/usr\/share\/nginx\/html\/assets\/[\w.-]+$/)
  const path = asset.replace('/usr/share/nginx/html', '')
  const response = await request(path)
  assert.equal(response.status, 200, path)
  assert.ok(response.body.length > 0, path)
  assert.match(response.headers['cache-control'], /max-age=2592000/, path)
  assert.equal(response.headers['x-content-type-options'], 'nosniff', path)
  if (path.endsWith('.js')) assert.match(response.headers['content-type'], /javascript/, path)
  if (path.endsWith('.css')) assert.match(response.headers['content-type'], /text\/css/, path)
}
const missing = await request('/assets/ci-smoke-does-not-exist.js')
assert.equal(missing.status, 404, 'Missing scripts must not fall back to HTML')
const map = await request('/china.json')
assert.equal(map.status, 200)
assert.match(map.headers['content-type'], /application\/json/)
const geometry = JSON.parse(map.body)
assert.equal(geometry.type, 'FeatureCollection')
assert.ok(geometry.features.length > 0, 'The screen map must include geographical features')
console.log(`ok - SPA routes and ${assets.length} built assets load over HTTPS with expected cache policies`)

execFileSync(process.execPath, ['--test', '--test-concurrency=1',
  fileURLToPath(new URL('./api-smoke.test.mjs', import.meta.url))], { stdio: 'inherit', timeout: 90_000 })
console.log('ok - shared API contracts pass through the production Nginx reverse proxy')
