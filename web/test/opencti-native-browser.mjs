import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..'), dist = resolve(web, 'dist')
const root = resolve(web, '../.tmp/opencti-browser'), fixtures = resolve(web, '../.tmp/opencti-fixtures')
const load = name => JSON.parse(readFileSync(resolve(fixtures, name + '.json')))
const status = load('status'), indicators = load('indicators'), indicator = load('indicator')
const source = status.sources.find(item => item.id === indicator.sourceId), prefix = '/api/libraries/sources/' + source.id
assert.equal(createHash('sha256').update(JSON.stringify(indicator.document)).digest('hex'), indicator.document_sha256)
assert.equal(indicators.state.visible_count, 3); assert.equal(indicators.state.candidate_hashes, 1)
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
let browser, role = 'admin', unavailable = false, empty = false, expiry = false, holdDetail = false, releaseDetail, detailStarted = false
const errors = [], unexpected = [], writes = [], checks = [], screenshots = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1080 } })
  context.setDefaultTimeout(10000)
  await context.addInitScript(() => { localStorage.setItem('alinksec_token', 'fixture'); localStorage.setItem('alinksec_user', JSON.stringify({ username: 'fixture', role: sessionStorage.getItem('role') || 'admin' })) })
  await context.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
    const ok = data => route.fulfill({ json: { code: 0, data } })
    if (method === 'GET' && path === '/api/libraries') return ok(status)
    if (method === 'GET' && path === prefix + '/indicators') {
      if (unavailable) return route.fulfill({ status: 503, json: { code: 503, msg: '指标依据暂不可用' } })
      if (empty) return ok({ ...indicators, total: 0, items: [], state: { ...indicators.state, visible_count: 0, candidate_hashes: 0, hash_count: 0, statistics: {} } })
      if (expiry) return ok({ ...indicators, state: { ...indicators.state, expiry_pending: true, delivery_deferred: 1 } })
      return ok(indicators)
    }
    if (method === 'GET' && path === prefix + '/indicators/' + indicator.indicator_id) {
      if (holdDetail) { detailStarted = true; await new Promise(done => { releaseDetail = done }) }
      return ok(indicator)
    }
    if (method === 'POST' && path === prefix + '/sync') { assert.equal(role, 'admin'); writes.push('sync'); return ok({ accepted: true }) }
    unexpected.push(method + ' ' + path); return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected request' } })
  })
  const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message))
  const shot = async name => { await page.screenshot({ path: root + '/' + name, fullPage: true, animations: 'disabled' }); screenshots.push(name) }
  const list = page.getByRole('dialog', { name: source.id + ' · OpenCTI 指标', exact: true })
  const detail = page.getByRole('dialog', { name: 'OpenCTI 指标依据', exact: true })
  async function openList() { await page.getByRole('button', { name: 'OpenCTI 指标', exact: true }).click(); await expect(list).toContainText('置信度 ≥ 75') }
  async function openDetail() { await list.getByRole('button', { name: '查看指标依据', exact: true }).first().click(); await expect(detail).toContainText(indicator.document_sha256) }
  await page.goto(base + '/libraries')
  await page.getByRole('button', { name: '立即同步', exact: true }).click(); await expect.poll(() => writes.length).toBe(1)
  await openList(); await expect(list).toContainText(indicators.state.snapshot_sha256)
  await expect(list).toContainText('不支持的模式'); await expect(list).toContainText('上游已撤销'); await expect(list).toContainText('离线 Agent')
  await shot('opencti-snapshot-desktop.png'); await openDetail()
  await expect(detail).toContainText('当前全局选择已采用此来源'); await expect(detail).toContainText('未验证情报内容真实性')
  checks.push('database-captured-full-snapshot-decisions-and-selected-field-digest; admin-sync; delivery-boundary-visible')
  for (const next of ['viewer', 'operator']) {
    role = next; await page.evaluate(value => sessionStorage.setItem('role', value), role); await page.goto(base + '/libraries')
    await expect(page.getByRole('button', { name: '立即同步', exact: true })).toHaveCount(0)
    await expect(page.getByRole('button', { name: '同步计划', exact: true })).toHaveCount(0)
    await expect(page.getByRole('button', { name: '退役来源', exact: true })).toHaveCount(0)
    await openList(); await openDetail()
  }
  checks.push('viewer-and-operator-readonly-indicator-access')
  await page.setViewportSize({ width: 390, height: 844 }); await shot('opencti-indicator-mobile.png')
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false)
  await detail.getByRole('button', { name: 'Close this dialog' }).click(); await expect(detail).toBeHidden()
  await shot('opencti-snapshot-mobile.png'); assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false)
  checks.push('mobile-detail-and-scrollable-indicator-table-with-no-page-overflow')
  unavailable = true; await list.getByRole('button', { name: '刷新指标', exact: true }).click()
  await expect(list.getByText('指标依据暂不可用', { exact: true })).toBeVisible(); await shot('opencti-error-mobile.png')
  await expect(list.getByText('完整快照为空，本来源没有有效指标贡献', { exact: true })).toHaveCount(0)
  checks.push('fetch-failure-is-visible-and-not-presented-as-empty-collection')
  unavailable = false; empty = true; await list.getByRole('button', { name: '刷新指标', exact: true }).click()
  await expect(list.getByText('完整快照为空，本来源没有有效指标贡献', { exact: true })).toBeVisible()
  checks.push('accepted-empty-collection-explicitly-has-no-source-contribution')
  empty = false; expiry = true; await list.getByRole('button', { name: '刷新指标', exact: true }).click()
  await expect(list).toContainText('正在等待撤出发布'); await expect(list).toContainText('Agent 下发待重试')
  checks.push('pending-expiry-publication-and-deferred-delivery-are-visible')
  expiry = false; await list.getByRole('button', { name: '刷新指标', exact: true }).click()
  holdDetail = true; await list.getByRole('button', { name: '查看指标依据', exact: true }).first().click()
  await expect.poll(() => detailStarted).toBe(true)
  await list.getByRole('button', { name: 'Close this dialog' }).click(); await expect(list).toBeHidden()
  await openList(); holdDetail = false
  const lateResponse = page.waitForResponse(response => new URL(response.url()).pathname === prefix + '/indicators/' + indicator.indicator_id)
  releaseDetail(); await (await lateResponse).finished()
  await page.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))))
  await expect(detail).toBeHidden()
  checks.push('closed-dialog-rejects-late-indicator-response')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); assert.deepEqual(writes, ['sync'])
  writeFileSync(root + '/result.json', JSON.stringify({ checks, writes, errors, unexpected, screenshots,
    fixtureSource: 'Real SQLite HTTP adapter and REST responses. Error, empty, pending expiry, deferred delivery and delayed response states are explicit browser fault injections; production-instance OpenCTI validation is separate.' }, null, 2))
} finally { releaseDetail?.(); await browser?.close(); await new Promise(done => server.close(done)) }
