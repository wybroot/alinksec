import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..'), dist = resolve(web, 'dist')
const root = resolve(web, '../.tmp/vendor-advisory-browser'), fixtures = resolve(web, '../.tmp/vendor-advisory-fixtures')
const load = name => JSON.parse(readFileSync(resolve(fixtures, name + '.json')))
const status = load('status'), documents = load('documents'), document = load('document'), raw = load('raw')
const source = status.sources.find(s => s.id === document.source_id), prefix = '/api/libraries/sources/' + source.id
const hash = bytes => createHash('sha256').update(bytes).digest('hex'), bytes = Buffer.from(raw.base64, 'base64')
assert.equal(hash(bytes), document.sha256)
mkdirSync(root, { recursive: true })
const server = createServer((req, res) => {
  let file
  try { file = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) } catch { res.writeHead(400); res.end(); return }
  if (!file.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
  if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' }[extname(file)] || 'application/octet-stream')
  createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
const base = 'http://127.0.0.1:' + server.address().port
let browser, role = 'admin', unavailable = false, tamper = false, pruned = false
const errors = [], unexpected = [], writes = [], checks = [], screenshots = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1080 }, acceptDownloads: true })
  context.setDefaultTimeout(10000)
  await context.addInitScript(() => { localStorage.setItem('alinksec_token', 'fixture'); localStorage.setItem('alinksec_user', JSON.stringify({ username: 'fixture', role: sessionStorage.getItem('role') || 'admin' })) })
  await context.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
    const ok = data => route.fulfill({ json: { code: 0, data } })
    if (method === 'GET' && path === '/api/libraries') return ok(status)
    if (method === 'GET' && path === prefix + '/advisories') return unavailable ? route.fulfill({ status: 503, json: { code: 503, msg: '公告归档暂不可用' } }) : ok(documents)
    if (method === 'GET' && path === prefix + '/advisories/' + document.id) return ok(pruned ? { ...document, raw_available: 0 } : document)
    if (method === 'GET' && path === prefix + '/advisories/' + document.id + '/raw') return route.fulfill({ body: bytes, headers: { 'Content-Type': 'application/octet-stream', 'X-Content-SHA256': tamper ? '0'.repeat(64) : hash(bytes) } })
    if (method === 'GET' && path === prefix + '/runs') return ok([])
    if (method === 'POST' && path === prefix + '/sync') { assert.equal(role, 'admin'); writes.push('sync'); return ok({ accepted: true }) }
    unexpected.push(method + ' ' + path); return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected request' } })
  })
  const page = await context.newPage(); page.on('pageerror', e => errors.push(e.message))
  const shot = async name => { await page.screenshot({ path: root + '/' + name, fullPage: true, animations: 'disabled' }); screenshots.push(name) }
  async function open() {
    await page.getByRole('button', { name: '厂商公告', exact: true }).click()
    await expect(page.getByRole('dialog', { name: source.id + ' · 厂商公告原件', exact: true })).toBeVisible()
    await page.getByRole('button', { name: '查看原件记录', exact: true }).click()
    await expect(page.getByRole('dialog', { name: '厂商公告原件记录', exact: true })).toBeVisible()
  }
  await page.goto(base + '/libraries')
  await expect(page.getByRole('button', { name: '厂商公告', exact: true })).toBeVisible()
  await page.getByRole('button', { name: '立即同步', exact: true }).click()
  await expect.poll(() => writes.length).toBe(1)
  await open()
  const detail = page.getByRole('dialog', { name: '厂商公告原件记录', exact: true })
  await expect(detail).toContainText(document.sha256)
  await expect(detail).toContainText('未验证厂商签名')
  await expect(detail).toContainText('不表示所有更早版本受影响')
  await expect(detail).toContainText('部署配置的镜像地址')
  const event = page.waitForEvent('download')
  await page.getByRole('button', { name: '下载原件并校验摘要', exact: true }).click()
  assert.equal(hash(readFileSync(await (await event).path())), document.sha256)
  await shot('native-document-desktop.png')
  checks.push('captured-SQLite-REST-document-and-origin-provenance; verified-original-byte-download; applicability-boundaries-visible; admin-sync')
  tamper = true
  await page.getByRole('button', { name: '下载原件并校验摘要', exact: true }).click()
  await expect(detail.getByText('公告原件摘要不匹配', { exact: true })).toBeVisible(); tamper = false
  checks.push('tampered-download-blocked')
  for (const next of ['viewer', 'operator']) {
    role = next; await page.evaluate(value => sessionStorage.setItem('role', value), role); await page.goto(base + '/libraries')
    await expect(page.getByRole('button', { name: '厂商公告', exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: '立即同步', exact: true })).toHaveCount(0)
    await expect(page.getByRole('button', { name: '同步计划', exact: true })).toHaveCount(0)
    await expect(page.getByRole('button', { name: '退役来源', exact: true })).toHaveCount(0)
    await open()
    await expect(page.getByRole('button', { name: '下载原件并校验摘要', exact: true })).toBeVisible()
  }
  checks.push('viewer-and-operator-readonly-controls-with-raw-access')
  await page.setViewportSize({ width: 390, height: 844 }); await shot('native-document-mobile.png')
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false)
  await detail.getByRole('button', { name: 'Close this dialog' }).click()
  await shot('native-archive-mobile.png')
  checks.push('mobile-document-and-archive-dialogs-have-no-page-overflow')
  unavailable = true
  await page.getByRole('button', { name: '刷新公告', exact: true }).click()
  await expect(page.getByText('公告归档暂不可用', { exact: true })).toBeVisible(); await shot('native-archive-error-mobile.png')
  checks.push('archive-fetch-error-visible')
  unavailable = false; pruned = true
  await page.getByRole('button', { name: '刷新公告', exact: true }).click()
  await page.getByRole('button', { name: '查看原件记录', exact: true }).click()
  await expect(detail).toContainText('原件已按保留策略清理')
  await expect(page.getByRole('button', { name: '下载原件并校验摘要', exact: true })).toHaveCount(0)
  checks.push('explicit-retention-state-keeps-digest-and-hides-unavailable-download')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
  writeFileSync(root + '/result.json', JSON.stringify({ checks, writes, errors, unexpected, screenshots,
    fixtureSource: 'SQLite HTTP importer and actual REST responses; unavailable/tampered/pruned states are explicit browser fault injections, not live publisher failures.' }, null, 2))
} finally { await browser?.close(); await new Promise(done => server.close(done)) }
