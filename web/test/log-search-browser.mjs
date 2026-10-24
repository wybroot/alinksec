import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..'), dist = resolve(process.env.ALINKSEC_LOG_BROWSER_DIST || resolve(web, 'dist'))
const fixtures = resolve(web, '../.tmp/log-search-fixtures'), output = resolve(web, '../.tmp/log-search-browser')
const fixture = JSON.parse(readFileSync(resolve(fixtures, 'console-sqlite.json')))
assert.equal(fixture.database, 'sqlite'); assert.equal(fixture.search.items.length, 4)
assert.equal(fixture.literal.items.length, 1); assert.equal(fixture.empty.scanComplete, true)
assert.equal(fixture.paging.first.items.length, 50); assert.equal(fixture.paging.second.items.length, 10)
assert.deepEqual(fixture.authority, { unauthenticated: 401, viewer: 403, operator: 403, disabledCurrentAdmin: 400 })
mkdirSync(output, { recursive: true })
const server = createServer((req, res) => {
  let file
  try { file = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) } catch { res.writeHead(400); res.end(); return }
  if (!file.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
  if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' }[extname(file)] || 'application/octet-stream')
  createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done)); const base = 'http://127.0.0.1:' + server.address().port
const checks = [], screenshots = [], downloads = [], requests = [], unexpected = [], errors = []
let browser, failList = false, failDetail = false, badDigest = false
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 }, acceptDownloads: true }); context.setDefaultTimeout(10000)
  await context.addInitScript(() => { localStorage.setItem('alinksec_token', 'raw-log-fixture'); localStorage.setItem('alinksec_user', JSON.stringify({ username: 'fixture', role: sessionStorage.getItem('logrole') || 'admin' })) })
  await context.route('**/api/**', async route => {
    const req = route.request(), url = new URL(req.url()), path = url.pathname, method = req.method(), ok = data => route.fulfill({ json: { code: 0, data } })
    assert.equal(req.headers().authorization, 'Bearer raw-log-fixture'); requests.push({ method, path })
    if (path === '/api/logs' && method === 'GET') {
      assert.ok(Number.isFinite(Number(url.searchParams.get('from')))); assert.ok(Number(url.searchParams.get('to')) > Number(url.searchParams.get('from')))
      if (failList) return route.fulfill({ status: 503, json: { code: 50300, msg: '日志检索暂不可用，请稍后重新检索' } })
      const keyword = url.searchParams.get('keyword') || ''
      if (keyword === 'paging') {
        const cursor = url.searchParams.get('cursor'); if (cursor) assert.equal(cursor, fixture.paging.first.nextCursor)
        return ok(cursor ? fixture.paging.second : fixture.paging.first)
      }
      if (keyword === 'absent-keyword') return ok(fixture.empty)
      if (keyword === '%_') return ok(fixture.literal)
      assert.equal(keyword, ''); return ok(fixture.search)
    }
    if (path === '/api/logs/export' && method === 'POST') {
      const body = req.postDataJSON(); assert.deepEqual(body.ids, fixture.search.items.map(row => row.id)); assert.ok(['ndjson', 'csv'].includes(body.format)); assert.equal(body.actor, undefined)
      const bytes = readFileSync(resolve(fixtures, `logs-sqlite.${body.format}`)), hash = createHash('sha256').update(bytes).digest('hex'); assert.equal(hash, fixture[body.format + 'Sha256'])
      return route.fulfill({ body: bytes, headers: { 'Content-Type': 'application/octet-stream', 'X-Content-SHA256': badDigest ? '0'.repeat(64) : hash, 'Cache-Control': 'no-store' } })
    }
    const detail = path.match(/^\/api\/logs\/([1-9][0-9]*)$/)
    if (detail && method === 'GET') {
      if (failDetail) return route.fulfill({ status: 400, json: { code: 40000, msg: '日志已过保留期或被清理，请重新检索' } })
      assert.ok(fixture.details[detail[1]]); return ok(fixture.details[detail[1]])
    }
    unexpected.push(method + ' ' + path); return route.fulfill({ status: 500, json: { code: 50000, msg: 'Unexpected request' } })
  })
  const page = await context.newPage(); page.on('pageerror', e => errors.push(e.message))
  const panel = page.locator('.log-search'), tableRows = panel.locator('.el-table__body tr')
  const search = () => panel.getByRole('button', { name: '检索', exact: true }).click()
  const keyword = panel.getByRole('textbox', { name: '原文字面关键词', exact: true })
  const shot = async name => { await page.screenshot({ path: resolve(output, name), animations: 'disabled', fullPage: true }); screenshots.push(name) }
  await page.goto(base + '/logs'); await expect(panel).toContainText('尚未检索'); assert.equal(requests.length, 0)
  await search(); await expect(tableRows).toHaveCount(4); await expect(panel).toContainText('原文已截断'); await expect(panel).toContainText('采集状态')
  await expect(panel).toContainText('<img src=x onerror=window.logXss=true>'); assert.equal(await page.evaluate(() => !!window.logXss), false)
  assert.equal(await panel.locator('img').count(), 0); await shot('logs-desktop.png'); checks.push('captured_database_raw_sources_truncation_metadata_and_safe_text')
  const rawRow = tableRows.filter({ hasText: 'onerror=window.logXss' }); await rawRow.getByRole('button', { name: '查看原文', exact: true }).click()
  await expect(panel.locator('.log-raw')).toHaveText(fixture.detail.content); await expect(panel.locator('.log-detail')).toContainText(fixture.detail.content_sha256)
  assert.equal(await panel.locator('.log-detail script,.log-detail img').count(), 0); checks.push('original_whitespace_newlines_digest_time_semantics_and_no_markup_execution')
  for (const format of ['ndjson', 'csv']) {
    const pending = page.waitForEvent('download'); await panel.getByRole('button', { name: `导出本页 ${format.toUpperCase()}`, exact: true }).click()
    const file = await pending, target = resolve(output, 'download.' + format); await file.saveAs(target)
    const bytes = readFileSync(target), hash = createHash('sha256').update(bytes).digest('hex'); assert.equal(hash, fixture[format + 'Sha256']); assert.equal(file.suggestedFilename(), 'alinksec-logs.' + format)
    if (format === 'ndjson') assert.equal(bytes.toString('utf8').trim().split('\n').map(JSON.parse).length, 4)
    downloads.push({ format, sha256: hash, bytes: bytes.length })
  }
  checks.push('exact_current_page_ndjson_and_csv_downloads_with_sha256')
  badDigest = true; let invalidSaved = false; const onDownload = () => { invalidSaved = true }; page.on('download', onDownload)
  await panel.getByRole('button', { name: '导出本页 NDJSON', exact: true }).click(); await expect(panel).toContainText('日志导出摘要不匹配'); assert.equal(invalidSaved, false); page.off('download', onDownload); badDigest = false
  checks.push('invalid_export_digest_blocks_save')
  await search(); await expect(tableRows).toHaveCount(4); await rawRow.getByRole('button', { name: '查看原文', exact: true }).click(); await expect(panel.locator('.log-raw')).toHaveText(fixture.detail.content)
  await page.setViewportSize({ width: 390, height: 844 }); await shot('logs-detail-mobile.png')
  const bounds = await panel.boundingBox(); assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 391)
  const width = await page.evaluate(() => ({ scroll: document.documentElement.scrollWidth, client: document.documentElement.clientWidth })); assert.ok(width.scroll <= width.client + 1)
  await panel.getByRole('button', { name: '关闭原文', exact: true }).click()
  const truncated = tableRows.filter({ hasText: 'retained raw prefix' }); await truncated.getByRole('button', { name: '查看原文', exact: true }).click(); await expect(panel.locator('.log-detail')).toContainText('完整原文未上传')
  checks.push('mobile_internal_table_scroll_and_explicit_prefix_boundary')
  failDetail = true; await rawRow.getByRole('button', { name: '查看原文', exact: true }).click(); await expect(panel.locator('.log-detail')).toContainText('日志已过保留期'); await expect(panel.locator('.log-raw')).toHaveCount(0); failDetail = false
  checks.push('expired_detail_clears_previous_original_text')
  await keyword.fill('paging'); await expect(panel).toContainText('当前结果已过期'); await expect(panel.getByRole('button', { name: '导出本页 CSV', exact: true })).toBeDisabled()
  await search(); await expect(tableRows).toHaveCount(50); await panel.getByRole('button', { name: '继续扫描', exact: true }).click(); await expect(tableRows).toHaveCount(10); await expect(panel).toContainText('本次扫描已完成')
  checks.push('filter_changes_disable_stale_actions_and_real_cursor_continuation')
  await keyword.fill('%_'); await search(); await expect(tableRows).toHaveCount(1); await expect(tableRows).toContainText('auth%_')
  await keyword.fill('absent-keyword'); await search(); await expect(tableRows).toHaveCount(0); await expect(panel).toContainText('本次检索范围内没有匹配日志'); await shot('logs-empty-mobile.png')
  checks.push('literal_keyword_and_true_empty_results')
  await keyword.fill(''); await search(); await expect(tableRows).toHaveCount(4); failList = true; await search(); await expect(panel).toContainText('日志检索暂不可用'); await expect(panel).toContainText('当前结果已过期'); await expect(panel.getByRole('button', { name: '导出本页 CSV', exact: true })).toBeDisabled(); await shot('logs-error-mobile.png')
  failList = false; await search(); await expect(panel.getByRole('button', { name: '导出本页 CSV', exact: true })).toBeEnabled(); checks.push('failed_refresh_marks_stale_and_retry_restores_actions')
  const previous = requests.length; await page.evaluate(() => sessionStorage.setItem('logrole', 'viewer')); await page.reload(); await expect(panel).toContainText('需要当前有效管理员账号'); await expect(panel.getByRole('button', { name: '检索', exact: true })).toHaveCount(0); assert.equal(requests.length, previous)
  checks.push('viewer_page_makes_no_sensitive_requests')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
  writeFileSync(resolve(output, 'result.json'), JSON.stringify({ passed: true, checks, screenshots, downloads, requests, errors, unexpected, mobileBounds: bounds }, null, 2))
  console.log(JSON.stringify({ passed: true, checks: checks.length, screenshots, downloads }))
} finally { await browser?.close(); await new Promise(done => server.close(done)) }
