import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, createReadStream } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, resolve, extname, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(process.env.ALINKSEC_CLAMAV_PREVIEW_DIST || resolve(web, 'dist'))
const root = resolve(web, '../.tmp/clamav-browser')
const fixtures = resolve(process.env.ALINKSEC_CLAMAV_BROWSER_FIXTURES || resolve(web, '../.tmp/clamav-fixtures'))
const stages = Object.fromEntries(['ready', 'stale', 'unsupported', 'hosts', 'task'].map(n => [n, JSON.parse(readFileSync(resolve(fixtures, n + '.json')))]))
mkdirSync(root, { recursive: true }); assert.ok(existsSync(resolve(dist, 'index.html')))
const server = createServer((req, res) => {
  let file
  try { file = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) } catch { res.writeHead(400); res.end(); return }
  if (file !== dist && !file.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
  if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' }[extname(file)] || 'application/octet-stream')
  createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
let stage = 'ready', fail = false, browser, page
const checks = [], errors = [], unexpected = [], writes = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote', '--disable-gpu', '--js-flags=--max-old-space-size=128'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 } }); context.setDefaultTimeout(8000)
  await context.addInitScript(() => { if (!localStorage.getItem('alinksec_user')) { localStorage.setItem('alinksec_token', 'fixture'); localStorage.setItem('alinksec_user', JSON.stringify({ username: 'operator', role: 'operator' })) } })
  await context.route('**/api/**', async route => {
    const req = route.request(), path = new URL(req.url()).pathname, method = req.method(), task = stages.task
    let data
    if (path === '/api/virus/clamav-status' && method === 'GET') {
      if (fail) return route.fulfill({ status: 503, json: { code: 503, msg: 'ClamAV 状态暂不可用' } })
      data = stages[stage]
    } else if (path === '/api/hosts' && method === 'GET') data = stages.hosts
    else if (method === 'GET' && path === '/api/virus/stats') data = task.stats
    else if (method === 'GET' && path === '/api/virus/findings') data = task.findings
    else if (method === 'GET' && path === '/api/virus/tasks') data = task.tasks
    else if (method === 'GET' && path === '/api/virus/db') data = task.db
    else if (method === 'GET' && path === '/api/virus/whitelist') data = task.whitelist
    else if (method === 'GET' && /^\/api\/virus\/tasks\/\d+\/evidence$/.test(path)) data = task.evidence
    else if (method === 'POST' && path === '/api/virus/tasks') {
      const body = req.postDataJSON(); writes.push(body)
      assert.equal(body.engine, 'clamav'); assert.equal(body.mode, 1)
      assert.deepEqual(body.agentIds, [stages.ready.items.find(x => x.state === 'ready').agent_id])
      return route.fulfill({ status: 400, json: { code: 400, msg: '目标主机的 ClamAV 尚未就绪，请检查引擎状态并等待心跳' } })
    } else { unexpected.push(method + ' ' + path); return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected request' } }) }
    return route.fulfill({ json: { code: 0, data } })
  })
  page = await context.newPage(); page.on('pageerror', e => errors.push(e.message)); await page.goto(`http://127.0.0.1:${server.address().port}/virus`)
  const section = page.getByTestId('clamav-status')
  await expect(section.getByText('就绪', { exact: true })).toBeVisible(); await expect(section.getByText('引擎不可用', { exact: true })).toBeVisible(); await expect(section.getByText('引擎证书校验失败', { exact: true })).toBeVisible()
  await section.scrollIntoViewIfNeeded(); await expect(section.locator('.el-loading-mask')).toHaveCount(0); await section.screenshot({ path: root + '/ready-desktop.png', animations: 'disabled' }); checks.push('database-readiness-version-and-failure')
  stage = 'stale'; await section.getByRole('button', { name: '刷新状态' }).click(); await expect(section.getByText('状态已过期', { exact: true })).toBeVisible(); checks.push('stale-not-ready')
  stage = 'unsupported'; await section.getByRole('button', { name: '刷新状态' }).click(); await expect(section.getByText('Agent 不支持', { exact: true })).toBeVisible(); await expect(section.getByText('主机离线或禁用', { exact: true })).toBeVisible(); checks.push('old-and-offline-agents')
  fail = true; await section.getByRole('button', { name: '刷新状态' }).click(); await expect(section.getByText('ClamAV 状态暂不可用', { exact: true })).toBeVisible(); await expect(section.locator('.host')).toHaveCount(0)
  fail = false; stage = 'ready'; await section.getByRole('button', { name: '重试', exact: true }).click(); await expect(section.getByText('就绪', { exact: true })).toBeVisible(); checks.push('failed-load-hides-stale-data-and-retries')
  await page.getByRole('button', { name: '快速扫描', exact: true }).click()
  const dialog = page.getByRole('dialog', { name: '发起快速扫描', exact: true })
  await expect(dialog.locator('.el-form-item').filter({ hasText: '扫描引擎' })).toContainText('内置特征库')
  await dialog.locator('.el-form-item').filter({ hasText: '扫描引擎' }).locator('.el-select__wrapper').click(); await page.getByRole('option', { name: 'ClamAV', exact: true }).click()
  const hostSelect = dialog.getByLabel('目标主机'); await dialog.locator('.el-form-item').filter({ hasText: '目标主机' }).locator('.el-select__wrapper').click()
  const readyHost = stages.ready.items.find(x => x.state === 'ready'), unavailableHost = stages.ready.items.find(x => x.state === 'unavailable')
  await expect(page.getByRole('option').filter({ hasText: unavailableHost.hostname })).toHaveAttribute('aria-disabled', 'true')
  await page.getByRole('option').filter({ hasText: readyHost.hostname }).click(); await hostSelect.press('Escape')
  await dialog.getByRole('button', { name: '开始扫描', exact: true }).click(); await expect(page.getByText('目标主机的 ClamAV 尚未就绪，请检查引擎状态并等待心跳', { exact: true })).toBeVisible(); await expect(dialog).toBeVisible(); await dialog.getByRole('button', { name: '取消', exact: true }).click(); checks.push('explicit-engine-ready-host-filter-and-server-recheck')
  await page.getByRole('tab', { name: '扫描任务', exact: true }).click()
  const taskRow = page.getByRole('row').filter({ hasText: 'ClamAV 测试' }); await expect(taskRow).toContainText('ClamAV'); await taskRow.getByRole('button', { name: '逐主机证据', exact: true }).click()
  const evidence = page.getByRole('dialog', { name: '逐主机扫描证据', exact: true }); await expect(evidence).toContainText('ClamAV 1.4.6/fixture-a'); await expect(evidence).toContainText('ClamAV 1.4.6/fixture-b'); await expect(evidence).toContainText('固定版本'); await evidence.getByLabel('Close this dialog').click(); checks.push('per-host-engine-version-evidence')
  await page.setViewportSize({ width: 390, height: 844 }); await section.scrollIntoViewIfNeeded(); const bounds = await section.boundingBox(); assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 391); await expect(section.locator('.host')).toHaveCount(2); await section.screenshot({ path: root + '/ready-mobile.png', animations: 'disabled' }); checks.push('mobile-status-fits-viewport')
  await page.evaluate(() => localStorage.setItem('alinksec_user', JSON.stringify({ username: 'viewer', role: 'viewer' }))); await page.reload(); await expect(page.getByTestId('clamav-status').getByText('就绪', { exact: true })).toBeVisible(); await expect(page.getByRole('button', { name: '快速扫描', exact: true })).toHaveCount(0); checks.push('viewer-status-without-task-controls')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); assert.equal(writes.length, 1)
  writeFileSync(root + '/result.json', JSON.stringify({ passed: true, checks, errors, unexpected, writes, mobileSection: bounds }, null, 2) + '\n'); console.log('Passed ClamAV browser checks:', checks)
} catch (e) { if (page) await page.screenshot({ path: root + '/failure.png', fullPage: true }).catch(() => {}); writeFileSync(root + '/failure.json', JSON.stringify({ error: String(e), checks, errors, unexpected }, null, 2)); throw e }
finally { await browser?.close(); await new Promise(done => server.close(done)) }
