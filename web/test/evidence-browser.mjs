import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..'), dist = resolve(web, 'dist')
const fixtures = resolve(web, '../.tmp/evidence-fixtures'), output = resolve(web, '../.tmp/evidence-browser')
const fixture = JSON.parse(readFileSync(resolve(fixtures, 'console-sqlite.json')))
assert.equal(fixture.database, 'sqlite')
assert.equal(fixture.history.length, 5)
assert.deepEqual([...new Set(fixture.history.map(row => row.state))].sort(), ['expired', 'failed', 'pending', 'ready'])
assert.ok(fixture.history.every(row => !Object.hasOwn(row, 'content_b64')))
const diagnostic = fixture.history.find(row => row.kind === 'diagnostic' && row.state === 'ready')
const sample = fixture.history.find(row => row.kind === 'quarantine_sample' && row.state === 'ready')
const pending = fixture.history.find(row => row.state === 'pending')
mkdirSync(output, { recursive: true })
const server = createServer((req, res) => {
  let file
  try { file = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) } catch { res.writeHead(400); res.end(); return }
  if (!file.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
  if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' }[extname(file)] || 'application/octet-stream')
  createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
const base = 'http://127.0.0.1:' + server.address().port
let browser, role = 'admin', badDigest = false, failList = false, holdSamples = false, releaseSamples
const checks = [], screenshots = [], downloads = [], writes = [], unexpected = [], errors = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 }, acceptDownloads: true })
  context.setDefaultTimeout(10000)
  await context.addInitScript(() => {
    localStorage.setItem('alinksec_token', 'evidence-fixture')
    localStorage.setItem('alinksec_user', JSON.stringify({ username: 'fixture', role: sessionStorage.getItem('role') || 'admin' }))
  })
  await context.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
    const ok = data => route.fulfill({ json: { code: 0, data } })
    if (method === 'GET' && ['/api/upgrade/packages', '/api/upgrade/versions', '/api/notify/channels'].includes(path)) return ok([])
    if (method === 'GET' && path === '/api/audit/logs') return ok({ total: 0, list: [] })
    if (path.startsWith('/api/evidence')) {
      assert.equal(role, 'admin'); assert.equal(request.headers().authorization, 'Bearer evidence-fixture')
      if (method === 'GET' && path === '/api/evidence') return failList ? route.fulfill({ status: 503, json: { code: 50300, msg: '取证记录暂不可用' } }) : ok(fixture.history)
      if (method === 'GET' && path === '/api/evidence/targets') return ok(fixture.targets)
      if (method === 'GET' && path === `/api/evidence/targets/${fixture.agent}/samples`) {
        if (holdSamples) await new Promise(done => { releaseSamples = done })
        return ok(fixture.samples)
      }
      if (method === 'POST' && path === '/api/evidence') {
        const body = request.postDataJSON(); assert.equal(body.agentId, fixture.agent); assert.equal(body.kind, 'diagnostic'); assert.equal(body.findingId, null); assert.equal(body.reason, '排查 SEC-456'); assert.equal(body.actor, undefined)
        writes.push({ method, path, body }); return ok(pending)
      }
      const match = path.match(/^\/api\/evidence\/([0-9a-f-]+)\/download$/)
      if (method === 'GET' && match) {
        const row = fixture.history.find(row => row.id === match[1]); assert.equal(row.state, 'ready')
        const bytes = readFileSync(resolve(fixtures, row.kind === 'diagnostic' ? 'diagnostic-sqlite.zip' : 'sample-sqlite.bin'))
        const digest = createHash('sha256').update(bytes).digest('hex'); assert.equal(digest, row.content_sha256)
        return route.fulfill({ body: bytes, headers: { 'Content-Type': 'application/octet-stream', 'X-Content-SHA256': badDigest ? '0'.repeat(64) : digest, 'Cache-Control': 'no-store' } })
      }
      if (method === 'DELETE' && path === '/api/evidence/' + sample.id) { writes.push({ method, path }); return ok(null) }
    }
    unexpected.push(method + ' ' + path)
    return route.fulfill({ status: 500, json: { code: 50000, msg: 'Unexpected request' } })
  })
  const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message))
  const panel = page.locator('.evidence-panel')
  const open = async () => { await page.goto(base + '/system'); await page.getByRole('tab', { name: '集中取证', exact: true }).click(); await expect(panel).toContainText(diagnostic.content_sha256) }
  const row = item => panel.locator('.el-table__body tr').filter({ hasText: item.content_sha256 })
  const shot = async name => { await page.screenshot({ path: resolve(output, name), animations: 'disabled' }); screenshots.push(name) }
  await open()
  for (const state of ['文件已就绪', '采集中', '采集失败', '请求已超时']) await expect(panel).toContainText(state)
  await expect(panel.getByRole('button', { name: '发起采集', exact: true })).toBeDisabled()
  await shot('evidence-desktop.png'); checks.push('real_database_states_metadata_digest_and_empty_form')
  const download = async item => {
    const waiting = page.waitForEvent('download'); await row(item).getByRole('button', { name: '下载', exact: true }).click()
    if (item.kind === 'quarantine_sample') await page.getByRole('button', { name: '下载样本', exact: true }).click()
    const file = await waiting, target = resolve(output, item.kind === 'diagnostic' ? 'download-diagnostic.zip' : 'download-sample.bin')
    await file.saveAs(target); const bytes = readFileSync(target)
    assert.equal(createHash('sha256').update(bytes).digest('hex'), item.content_sha256)
    assert.equal(file.suggestedFilename(), `alinksec-${item.id}-${item.kind === 'diagnostic' ? 'diagnostic.zip' : 'quarantine.sample.bin'}`)
    downloads.push({ kind: item.kind, sha256: item.content_sha256, size: bytes.length })
  }
  await download(diagnostic); await download(sample); checks.push('exact_private_diagnostic_and_sample_downloads_with_explicit_sample_confirmation')
  badDigest = true; let unexpectedDownload = false
  const unexpectedListener = () => { unexpectedDownload = true }; page.on('download', unexpectedListener)
  await row(diagnostic).getByRole('button', { name: '下载', exact: true }).click()
  await expect(panel).toContainText('文件完整性校验失败'); assert.equal(unexpectedDownload, false)
  page.off('download', unexpectedListener); badDigest = false; checks.push('tampered_download_is_blocked_before_saving')
  holdSamples = true
  await panel.locator('.el-select').nth(0).click(); await page.getByRole('option', { name: '诊断主机', exact: true }).click()
  await panel.locator('.el-select').nth(1).click(); await page.getByRole('option', { name: '已隔离样本', exact: true }).click()
  await panel.getByRole('textbox', { name: '取证用途', exact: true }).fill('排查 SEC-456')
  await expect(panel.getByRole('button', { name: '发起采集', exact: true })).toBeDisabled()
  await expect.poll(() => typeof releaseSamples).toBe('function'); holdSamples = false; releaseSamples()
  await expect(panel.locator('.el-select').nth(2)).not.toHaveClass(/is-loading/)
  await panel.locator('.el-select').nth(1).click(); await page.getByRole('option', { name: '主机诊断包', exact: true }).click()
  await expect(panel.getByRole('button', { name: '发起采集', exact: true })).toBeEnabled()
  await panel.getByRole('button', { name: '发起采集', exact: true }).click(); await expect.poll(() => writes.filter(write => write.method === 'POST').length).toBe(1)
  checks.push('pending_sample_lookup_disables_collection_and_actor_free_request_is_bound_to_selected_host')
  await row(sample).getByRole('button', { name: '删除', exact: true }).click(); await page.getByRole('button', { name: '删除记录', exact: true }).click()
  await expect.poll(() => writes.filter(write => write.method === 'DELETE').length).toBe(1); checks.push('deletion_requires_explicit_review_and_keeps_agent_capture')
  await page.setViewportSize({ width: 390, height: 844 }); await panel.scrollIntoViewIfNeeded(); await page.evaluate(() => window.scrollTo(0, 0)); await shot('evidence-mobile.png')
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1)); checks.push('mobile_controls_fit_and_file_table_scrolls_inside_panel')
  failList = true; await panel.getByRole('button', { name: '刷新状态', exact: true }).click(); await expect(panel).toContainText('取证记录暂不可用'); await shot('evidence-error-mobile.png')
  checks.push('failed_refresh_remains_visible')
  failList = false
  for (role of ['operator', 'viewer']) {
    await page.evaluate(role => sessionStorage.setItem('role', role), role); await page.goto(base + '/system')
    await expect(page.getByRole('tab', { name: '集中取证', exact: true })).toHaveCount(0)
  }
  checks.push('sensitive_evidence_tab_hidden_for_operator_and_viewer')
  assert.deepEqual(unexpected, []); assert.deepEqual(errors, [])
  writeFileSync(resolve(output, 'result.json'), JSON.stringify({ passed: true, checks, screenshots, downloads, writes, unexpected, errors }, null, 2) + '\n')
} finally { if (browser) await browser.close(); await new Promise(done => server.close(done)) }
