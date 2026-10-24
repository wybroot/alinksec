import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { createHash } from 'node:crypto'
import { chromium, expect } from '@playwright/test'

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..'), dist = resolve(web, 'dist')
const fixtures = resolve(web, '../.tmp/cluster-fixtures'), output = resolve(web, '../.tmp/cluster-browser')
const read = name => JSON.parse(readFileSync(resolve(fixtures, `console-${name}.json`)))
const dead = read('dead'), healthy = read('healthy'), live = read('live')
const native = JSON.parse(readFileSync(resolve(web, '../.tmp/cluster-native/result.json')))
assert.equal(native.passed, true); assert.equal(native.arch, 'amd64')
assert.equal(createHash('sha256').update(readFileSync(resolve(fixtures, 'console-live.json'))).digest('hex'), native.consoleSha256)
assert.equal(dead.mode, 'cluster'); assert.equal(dead.nodes.length, 2); assert.equal(dead.deadReports.length, 1)
assert.equal(healthy.deadReports.length, 0); assert.equal(live.ready, true)
assert.ok(!JSON.stringify(dead).includes('content_b64'))
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
let browser, data = structuredClone(dead), failList = false, failRetry = true
const checks = [], screenshots = [], writes = [], unexpected = [], errors = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } })
  context.setDefaultTimeout(10000)
  await context.addInitScript(() => {
    localStorage.setItem('alinksec_token', 'cluster-console-capture')
    localStorage.setItem('alinksec_user', JSON.stringify({ username: 'capture', role: sessionStorage.getItem('role') || 'admin' }))
  })
  await context.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname, method = request.method()
    const ok = data => route.fulfill({ json: { code: 0, data } })
    if (method === 'GET' && ['/api/upgrade/packages', '/api/upgrade/versions', '/api/notify/channels'].includes(path)) return ok([])
    if (method === 'GET' && path.startsWith('/api/audit')) return ok({ total: 0, list: [] })
    if (path === '/api/cluster' && method === 'GET') {
      if (failList) return route.fulfill({ status: 503, json: { code: 50300, msg: '集群状态暂不可用' } })
      return ok(data)
    }
    if (path === `/api/cluster/reports/${dead.deadReports[0].id}/retry` && method === 'POST') {
      const body = request.postDataJSON()
      assert.deepEqual(Object.keys(body).sort(), ['note', 'sha256'])
      assert.equal(body.sha256, dead.deadReports[0].content_sha256); assert.ok(body.note.trim())
      writes.push({ path, body })
      if (failRetry) return route.fulfill({ status: 400, json: { code: 40000, msg: '主机已停用或删除，不能重试' } })
      data = structuredClone(healthy); return ok(null)
    }
    unexpected.push(method + ' ' + path)
    return route.fulfill({ status: 500, json: { code: 50000, msg: 'Unexpected request' } })
  })
  const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message))
  const panel = page.locator('.cluster-panel')
  const refresh = panel.getByRole('button', { name: '刷新集群状态', exact: true })
  const shot = async name => { await page.screenshot({ path: resolve(output, name), animations: 'disabled' }); screenshots.push(name) }
  await page.goto(base + '/system'); await page.getByRole('tab', { name: '服务集群', exact: true }).click()
  await expect(panel).toContainText('当前服务节点就绪'); await expect(panel).toContainText(dead.deadReports[0].content_sha256)
  await expect(panel).toContainText('node-a'); await expect(panel).toContainText('node-b')
  await shot('cluster-desktop.png'); checks.push('actual_database_node_queue_failure_and_digest_metadata')
  await panel.getByRole('button', { name: '重试报告', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: '重试失败报告', exact: true })
  await expect(dialog).toContainText(dead.deadReports[0].content_sha256)
  await expect(dialog.getByRole('button', { name: '确认重试', exact: true })).toBeDisabled()
  await dialog.getByRole('textbox', { name: '报告重试说明', exact: true }).fill('复核主机状态后重试，工单 SEC-223')
  await dialog.getByRole('button', { name: '确认重试', exact: true }).click()
  await expect(dialog).toContainText('主机已停用或删除，不能重试')
  await expect(dialog.getByRole('button', { name: '确认重试', exact: true })).toBeDisabled()
  await dialog.getByRole('button', { name: '取消', exact: true }).click()
  await expect(panel.getByRole('button', { name: '重试报告', exact: true })).toBeDisabled()
  checks.push('failed_retry_stays_visible_and_requires_fresh_review')
  failRetry = false; await refresh.click()
  await expect(panel.getByRole('button', { name: '重试报告', exact: true })).toBeEnabled()
  await panel.getByRole('button', { name: '重试报告', exact: true }).click()
  await dialog.getByRole('textbox', { name: '报告重试说明', exact: true }).fill('重新核验已启用主机，SEC-223')
  await dialog.getByRole('button', { name: '确认重试', exact: true }).click()
  await expect(panel).toContainText('暂无失败报告'); assert.equal(writes.length, 2)
  checks.push('explicit_digest_bound_retry_has_no_client_actor_and_refreshes_committed_state')
  data = structuredClone(live); await refresh.click(); await expect(panel).toContainText('当前服务节点就绪')
  await page.setViewportSize({ width: 390, height: 844 })
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth + 1))
  checks.push('actual_live_rest_capture_and_mobile_controls_fit')
  data = { ...structuredClone(dead), ready: false, issue: 'redis_unavailable' }; await refresh.click()
  await expect(panel).toContainText('会话协调服务暂不可用')
  await expect(panel.getByRole('button', { name: '重试报告', exact: true })).toBeDisabled()
  await page.evaluate(() => window.scrollTo(0, 0)); await shot('cluster-degraded-mobile.png')
  checks.push('dependency_outage_disables_retry_and_explains_unavailable_node')
  failList = true; await refresh.click(); await expect(panel).toContainText('集群状态暂不可用')
  await expect(panel).toContainText('下方保留上次读取结果'); await shot('cluster-error-mobile.png')
  checks.push('failed_refresh_marks_retained_data_stale')
  failList = false; data = { mode: 'single', ready: true }; await refresh.click(); await expect(panel).toContainText('单实例运行')
  await expect(panel.getByRole('button', { name: '重试报告', exact: true })).toHaveCount(0)
  checks.push('ordinary_single_instance_has_clear_default_view')
  for (const role of ['operator', 'viewer']) {
    await page.evaluate(role => sessionStorage.setItem('role', role), role); await page.goto(base + '/system')
    await expect(page.getByRole('tab', { name: '服务集群', exact: true })).toHaveCount(0)
  }
  checks.push('cluster_controls_hidden_for_operator_and_viewer')
  assert.deepEqual(unexpected, []); assert.deepEqual(errors, [])
  writeFileSync(resolve(output, 'result.json'), JSON.stringify({ passed: true, head: native.head, checks, screenshots, writes, unexpected, errors, liveConsoleSha256: native.consoleSha256 }, null, 2) + '\n')
} finally { if (browser) await browser.close(); await new Promise(done => server.close(done)) }
