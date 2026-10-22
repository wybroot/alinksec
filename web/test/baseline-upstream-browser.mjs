import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..'), dist = resolve(web, 'dist')
const root = resolve(web, '../.tmp/baseline-upstream-browser'), fixture = JSON.parse(readFileSync(resolve(web, '../.tmp/baseline-upstream-fixtures/sqlite.json')))
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
const base = 'http://127.0.0.1:' + server.address().port, source = fixture.imported.sources.find(s => s.id === fixture.imported.detail.id), prefix = '/api/baseline/upstreams/' + source.id
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
let stage = 'imported', role = 'admin', unavailable = false, tamper = false, browser
const errors = [], unexpected = [], writes = [], checks = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1080 }, acceptDownloads: true })
  context.setDefaultTimeout(10000)
  await context.addInitScript(() => { localStorage.setItem('alinksec_token', 'fixture'); localStorage.setItem('alinksec_user', JSON.stringify({ username: 'fixture', role: sessionStorage.getItem('role') || 'admin' })) })
  await context.route('**/api/**', async route => {
    const req = route.request(), path = new URL(req.url()).pathname, method = req.method(), data = fixture[stage]
    const ok = value => route.fulfill({ json: { code: 0, data: value } })
    const binary = bytes => route.fulfill({ body: bytes, headers: { 'Content-Type': 'application/octet-stream', 'X-Content-SHA256': tamper ? '0'.repeat(64) : hash(bytes) } })
    if (method === 'GET' && path === '/api/baseline/upstreams') return unavailable ? route.fulfill({ status: 503, json: { code: 503, msg: '更新来源暂不可用' } }) : ok(data.sources.filter(s => s.id === source.id))
    if (method === 'GET' && path === prefix) return ok(data.detail)
    if (method === 'GET' && path.startsWith(prefix + '/receipts/')) return binary(Buffer.from(data.receiptBase64, 'base64'))
    if (method === 'GET' && path.endsWith('/artifact') && path.startsWith(prefix + '/releases/')) return binary(Buffer.from(data.artifactBase64, 'base64'))
    if (method === 'PUT' && path === prefix + '/schedule') { assert.equal(role, 'admin'); const plan = req.postDataJSON(); assert.equal(plan.revision, data.detail.revision); assert.ok(plan.note.trim()); writes.push({ action: 'schedule', ...plan }); return ok(data.detail) }
    if (method === 'POST' && path === prefix + '/sync') { assert.equal(role, 'admin'); writes.push({ action: 'sync' }); return ok({ attemptId: 'browser-trigger', state: 'queued' }) }
    if (method === 'POST' && path.endsWith('/retry') && path.startsWith(prefix + '/releases/')) { assert.equal(role, 'admin'); writes.push({ action: 'retry' }); return ok(data.detail) }
    if (path === '/api/baseline/packages') return ok([data.candidate])
    if (path === '/api/baseline/templates') return ok([])
    if (path === '/api/baseline/packages/' + data.candidate.id) return ok(data.candidate)
    unexpected.push(method + ' ' + path);return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected request' } })
  })
  const page = await context.newPage(); page.on('pageerror', e => errors.push(e.message))
  await page.goto(base + '/baseline-upstreams')
  await expect(page.getByRole('heading', { name: source.name, exact: true })).toBeVisible()
  await expect(page.getByText(source.keySha256, { exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '查看候选版本', exact: true })).toBeVisible()
  async function download(name, bytes) { const event = page.waitForEvent('download'); await page.getByRole('button', { name, exact: true }).click(); assert.equal(hash(readFileSync(await (await event).path())), hash(bytes)) }
  await download('下载原件', Buffer.from(fixture.imported.artifactBase64, 'base64'))
  await download('下载当前签名索引', Buffer.from(fixture.imported.receiptBase64, 'base64'))
  await page.getByPlaceholder('填写本次调整原因').fill('已核对签名来源与包范围')
  await page.getByRole('button', { name: '保存更新计划', exact: true }).click(); assert.equal(writes.at(-1).action, 'schedule')
  await page.getByRole('button', { name: '立即同步', exact: true }).click(); await expect(page.getByText('同步已提交，请查看更新记录')).toBeVisible()
  await expect(page.locator('.el-loading-mask')).toHaveCount(0); await expect(page.locator('.el-message')).toHaveCount(0, { timeout: 10000 })
  await page.locator('main.content').evaluate(el => { el.scrollTop = 0 })
  await page.screenshot({ path: root + '/imported-desktop.png', fullPage: true, animations: 'disabled' })
  checks.push('signed-source-key-scope-provenance; real-byte-verified-artifact-and-envelope-downloads; optimistic-admin-schedule; explicit-sync')
  await page.getByRole('button', { name: '查看候选版本', exact: true }).click()
  await expect(page.getByRole('dialog')).toBeVisible(); await expect(page.locator('.provenance')).toContainText(source.id)
  await expect(page.locator('.provenance')).toContainText(fixture.imported.detail.releases[0].sha256)
  checks.push('candidate-deep-link-preserves-upstream-source-and-raw-digest')
  stage = 'failed'; await page.goto(base + '/baseline-upstreams')
  await expect(page.getByText(/原件大小或摘要不匹配/).first()).toBeVisible()
  await page.getByRole('button', { name: '重新尝试', exact: true }).click(); await expect(page.getByText('版本已加入下一轮重试')).toBeVisible()
  await expect(page.getByText('上游已撤回', { exact: true })).toBeVisible()
  await expect(page.locator('.el-loading-mask')).toHaveCount(0); await expect(page.locator('.el-message')).toHaveCount(0, { timeout: 10000 })
  await page.getByRole('heading', { name: '发现的版本', exact: true }).scrollIntoViewIfNeeded()
  await page.screenshot({ path: root + '/failed-withdrawn-desktop.png', fullPage: true, animations: 'disabled' })
  checks.push('captured-real-failure-and-withdrawal-states; explicit-admin-retry')
  stage = 'withdrawn'; await page.goto(base + '/baseline-templates?package=' + fixture.withdrawn.candidate.id)
  await expect(page.getByRole('dialog')).toBeVisible(); await expect(page.locator('.provenance .el-alert')).toContainText('上游内容已撤回')
  await page.screenshot({ path: root + '/withdrawn-candidate-desktop.png', fullPage: true, animations: 'disabled' })
  checks.push('withdrawn-provenance-visible-in-existing-review-flow')
  for (const nextRole of ['viewer', 'operator']) {
    role = nextRole; await page.evaluate(r => sessionStorage.setItem('role', r), role); stage = 'failed'; await page.goto(base + '/baseline-upstreams')
    await expect(page.getByRole('heading', { name: source.name, exact: true })).toBeVisible(); await expect(page.getByRole('button', { name: '保存更新计划' })).toHaveCount(0); await expect(page.getByRole('button', { name: '立即同步' })).toHaveCount(0); await expect(page.getByRole('button', { name: '重新尝试' })).toHaveCount(0)
  }
  checks.push('viewer-and-operator-readonly-controls')
  await page.setViewportSize({ width: 390, height: 844 }); await page.screenshot({ path: root + '/viewer-mobile.png', fullPage: true, animations: 'disabled' })
  await page.getByRole('heading', { name: '发现的版本', exact: true }).scrollIntoViewIfNeeded()
  await page.screenshot({ path: root + '/viewer-versions-mobile.png', fullPage: true, animations: 'disabled' })
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false)
  checks.push('mobile-has-no-page-horizontal-overflow')
  role = 'admin'; await page.evaluate(() => sessionStorage.setItem('role', 'admin')); stage = 'paused'; await page.goto(base + '/baseline-upstreams'); await expect(page.getByRole('button', { name: '立即同步', exact: true })).toBeDisabled()
  checks.push('paused-source-cannot-sync')
  stage = 'imported'; tamper = true; await page.goto(base + '/baseline-upstreams'); await page.getByRole('button', { name: '下载原件', exact: true }).click(); await expect(page.getByText('导出内容摘要不匹配', { exact: true })).toBeVisible();tamper = false
  unavailable = true;await page.getByRole('button', { name: '刷新', exact: true }).click();await expect(page.getByText('更新来源暂不可用', { exact: true })).toBeVisible()
  checks.push('tampered-download-blocked; fetch-error-visible')
  assert.deepEqual(errors, []);assert.deepEqual(unexpected, [])
  writeFileSync(root + '/result.json', JSON.stringify({ checks, writes, errors, unexpected, screenshots: ['imported-desktop.png', 'failed-withdrawn-desktop.png', 'withdrawn-candidate-desktop.png', 'viewer-mobile.png', 'viewer-versions-mobile.png'], fixtureSource: 'SQLite integration HTTP publisher and actual REST/database lifecycle responses' }, null, 2))
} finally { await browser?.close(); await new Promise(done => server.close(done)) }
