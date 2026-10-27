import assert from 'node:assert/strict'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const dist = resolve(process.env.ALINKSEC_YARA_UPDATE_DIST || resolve(root, 'web/dist'))
const fixture = JSON.parse(readFileSync(resolve(process.env.ALINKSEC_YARA_UPDATE_FIXTURE || resolve(root, '.tmp/virus-operations/browser-fixtures.json'))))
const output = resolve(process.env.ALINKSEC_VIRUS_OPERATIONS_OUTPUT || resolve(root, '.tmp/virus-operations/browser'))
mkdirSync(output, { recursive: true })
const ready = fixture.responses['/api/virus/yara-status'].items.find(r => r.state === 'ready')
assert.ok(ready)
const server = createServer((req, res) => {
  const filePath = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname))
  if (!filePath.startsWith(dist + sep) && filePath !== dist) { res.writeHead(403); res.end(); return }
  const file = existsSync(filePath) && statSync(filePath).isFile() ? filePath : resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' }[extname(file)] || 'application/octet-stream')
  createReadStream(file).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
const checks = [], errors = [], unexpected = [], writes = [], reads = [], tasks = []
let browser, page, createFailure = true, receiptFailure = false, partial = false
const result = () => ({ checks, errors, unexpected, writes, capturedAt: fixture.capturedAt, dist, mode: 'Frontend with captured API reads and simulated task writes/receipts' })
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote', '--disable-gpu', '--js-flags=--max-old-space-size=128'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 }, locale: 'zh-CN' })
  context.setDefaultTimeout(8000)
  await context.addInitScript(() => {
    if (!localStorage.getItem('alinksec_user')) {
      localStorage.setItem('alinksec_token', 'captured-api-replay')
      localStorage.setItem('alinksec_user', JSON.stringify({ username: 'operator', role: 'operator' }))
    }
  })
  await context.route('**/api/**', async route => {
    const req = route.request(), url = new URL(req.url()), path = url.pathname, method = req.method()
    if (method === 'POST' && path === '/api/virus/tasks') {
      const body = req.postDataJSON(); writes.push(body)
      assert.deepEqual(body.agentIds, [ready.agent_id]); assert.equal(body.engine, 'yara'); assert.equal(body.mode, 3)
      assert.ok(body.budget.timeLimitSec > 0 && body.budget.maxTotalBytes <= 20 * 1073741824)
      if (createFailure) return route.fulfill({ status: 400, json: { code: 400, msg: '规则版本已变化，请复核后重试' } })
      const id = 901 + tasks.length
      tasks.unshift({ id, task_no: `VS-operation-${id}`, name: body.name, mode: body.mode, scan_engine: body.engine, status: 1, progress: 0, total_hosts: 1, complete_hosts: 0, username: 'operator',
        scope: JSON.stringify({ paths: body.paths, time_limit_sec: body.budget.timeLimitSec, max_files: body.budget.maxFiles, max_total_bytes: body.budget.maxTotalBytes, retry_of: body.retryOf }), created_at: '2026-10-27T12:00:00Z' })
      return route.fulfill({ json: { code: 0, data: { taskId: id } } })
    }
    if (method !== 'GET') { unexpected.push(`${method} ${path}`); return route.fulfill({ status: 500, json: { code: 500 } }) }
    reads.push(path + url.search)
    let data
    if (/^\/api\/virus\/tasks\/\d+\/evidence$/.test(path)) {
      if (receiptFailure) return route.fulfill({ status: 503, json: { code: 503, msg: '回执暂不可用，请重试' } })
      const id = Number(path.split('/')[4]), done = id === 902, failed = partial && id === 901
      data = [{ agent_id: ready.agent_id, hostname: ready.hostname, ip: ready.ip, state: done ? 'complete' : failed ? 'partial' : 'pending', late: 0, expected_engine_version: ready.coverage.version,
        evidence: done || failed ? { files_scanned: 1, files_failed: failed ? 1 : 0, bytes_read: 12, scan_engine: 'yara', db_version: ready.coverage.version, budget_exhausted: failed, issues: failed ? [{ path: '/tmp/needs-review', code: 'budget_exhausted' }] : [] } : '' }]
    } else if (path === '/api/virus/tasks') {
      const pageNumber = Number(url.searchParams.get('page'))
      data = { total: 41, list: pageNumber === 1 ? tasks : [{ ...tasks[0], id: 880, name: '较早的扫描任务' }] }
    } else if (path === '/api/virus/findings') {
      const captured = fixture.responses[path]
      data = { ...captured, total: 41 }
    } else if (Object.hasOwn(fixture.responses, path)) data = fixture.responses[path]
    else { unexpected.push(`${method} ${path}`); return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected API' } }) }
    return route.fulfill({ json: { code: 0, data } })
  })
  page = await context.newPage(); page.on('pageerror', e => errors.push(e.message))
  await page.goto(`http://127.0.0.1:${server.address().port}/virus`)
  await page.getByTestId('yara-status').getByRole('button', { name: '扫描此主机', exact: true }).click()
  let scan = page.getByRole('dialog', { name: '发起自定义扫描', exact: true })
  await expect(scan).toContainText(ready.hostname)
  await expect(scan.locator('.el-form-item').filter({ hasText: '扫描引擎' })).toContainText('原生 YARA')
  await scan.getByPlaceholder('选填，便于后续追踪').fill('排查读取失败')
  await scan.locator('textarea').fill('/tmp/needs-review')
  await expect(scan.getByRole('button', { name: '开始扫描', exact: true })).toBeDisabled()
  await scan.locator('.el-checkbox__label').click()
  await scan.getByRole('button', { name: '开始扫描', exact: true }).click()
  await expect(page.getByText('规则版本已变化，请复核后重试', { exact: true })).toBeVisible()
  await expect(scan.locator('textarea')).toHaveValue('/tmp/needs-review')
  checks.push('host-and-engine-prefilled-explicit-confirmation-and-server-error-preserves-input')
  createFailure = false
  await scan.getByRole('button', { name: '开始扫描', exact: true }).click()
  let evidence = page.getByRole('dialog', { name: '逐主机扫描证据', exact: true })
  await expect(evidence).toContainText('任务 #901')
  await expect(evidence).toContainText('待回报')
  assert.deepEqual(writes[1].budget, { timeLimitSec: 300, maxFiles: 1000, maxTotalBytes: 268435456 })
  partial = true
  await expect(evidence).toContainText('部分覆盖', { timeout: 10000 })
  await expect(evidence).toContainText('达到扫描预算')
  await evidence.screenshot({ path: resolve(output, 'partial-receipt.png'), animations: 'disabled' })
  checks.push('accepted-task-opens-exact-id-and-polls-per-host-receipt-and-budget-failure')
  await evidence.getByRole('button', { name: '复核范围并复扫', exact: true }).click()
  scan = page.getByRole('dialog', { name: '发起自定义扫描', exact: true })
  await expect(scan).toContainText('复扫自任务 #901')
  await expect(scan.locator('textarea')).toHaveValue('/tmp/needs-review')
  await expect(scan.getByRole('checkbox')).not.toBeChecked()
  await scan.locator('.el-checkbox__label').click()
  await scan.getByRole('button', { name: '开始扫描', exact: true }).click()
  await expect(evidence).toContainText('任务 #902')
  await expect(evidence).toContainText('限定范围完成')
  await expect(evidence).toContainText('复扫自 #901')
  assert.equal(writes[2].retryOf, 901)
  assert.equal(writes.length, 3)
  await evidence.screenshot({ path: resolve(output, 'retry-complete.png'), animations: 'disabled' })
  checks.push('failed-path-prefills-new-task-with-lineage-and-new-confirmation-and-complete-receipt')
  receiptFailure = true
  await evidence.getByRole('button', { name: '刷新回执', exact: true }).click()
  await expect(evidence).toContainText('回执暂不可用，请重试')
  receiptFailure = false
  await evidence.getByRole('button', { name: '刷新回执', exact: true }).click()
  await expect(evidence).not.toContainText('回执暂不可用，请重试')
  await evidence.getByLabel('Close this dialog').click()
  await page.getByTestId('yara-status').getByRole('button', { name: '查看主机任务', exact: true }).click()
  const taskPane = page.getByRole('tabpanel', { name: '扫描任务', exact: true })
  await expect(taskPane.getByPlaceholder('按主机编号筛选')).toHaveValue(ready.agent_id)
  await taskPane.locator('.btn-next').click()
  await expect(taskPane).toContainText('较早的扫描任务')
  assert.ok(reads.some(p => p.includes('/api/virus/tasks?') && p.includes('page=2') && p.includes('agentId=')))
  checks.push('receipt-refresh-recovers-and-host-task-filter-keeps-pagination')
  await page.getByRole('tab', { name: '检出处置', exact: true }).click()
  const findings = page.getByRole('tabpanel', { name: '检出处置', exact: true })
  await findings.locator('.btn-next').click()
  assert.ok(reads.some(p => p.includes('/api/virus/findings?') && p.includes('page=2') && p.includes('size=20')))
  checks.push('finding-pagination-requests-next-server-page')
  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByTestId('yara-status').getByRole('button', { name: '扫描此主机', exact: true }).click()
  scan = page.getByRole('dialog', { name: '发起自定义扫描', exact: true })
  await expect(scan).toBeVisible()
  assert.ok(await scan.evaluate(el => el.scrollWidth <= el.clientWidth), 'Mobile scan form fits dialog')
  await scan.screenshot({ path: resolve(output, 'mobile-scan.png'), animations: 'disabled' })
  await scan.getByRole('button', { name: '取消', exact: true }).click()
  await page.evaluate(() => localStorage.setItem('alinksec_user', JSON.stringify({ username: 'viewer', role: 'viewer' })))
  await page.reload()
  await expect(page.getByTestId('yara-status').getByRole('button', { name: '查看主机任务', exact: true })).toBeVisible()
  await expect(page.getByRole('button', { name: '扫描此主机', exact: true })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '快速扫描', exact: true })).toHaveCount(0)
  checks.push('mobile-form-fits-and-viewer-can-read-without-management-controls')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
  writeFileSync(resolve(output, 'result.json'), JSON.stringify({ passed: true, ...result() }, null, 2))
  console.log(JSON.stringify({ passed: true, checks }))
} catch (e) {
  await page?.screenshot({ path: resolve(output, 'failure.png') }).catch(() => {})
  writeFileSync(resolve(output, 'failure.json'), JSON.stringify({ error: String(e), ...result() }, null, 2))
  throw e
} finally { await browser?.close(); await new Promise(done => server.close(done)) }
