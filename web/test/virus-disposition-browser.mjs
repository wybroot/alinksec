import assert from 'node:assert/strict'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'

const root = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
const base = resolve(process.env.ALINKSEC_VIRUS_DISPOSITION_OUTPUT || resolve(root, '.tmp/virus-disposition/browser'))
const dist = resolve(process.env.ALINKSEC_YARA_UPDATE_DIST || resolve(root, 'web/dist'))
const fixture = JSON.parse(readFileSync(resolve(process.env.ALINKSEC_VIRUS_DISPOSITION_FIXTURE || resolve(root, '.tmp/virus-disposition/console-fixtures.json'))))
const engines = JSON.parse(readFileSync(resolve(root, '.tmp/virus-disposition/browser-fixtures.json'))).responses
mkdirSync(base, { recursive: true })
const server = createServer((req, res) => {
  const target = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname))
  if (!target.startsWith(dist + sep) && target !== dist) { res.writeHead(403); return res.end() }
  const file = existsSync(target) && statSync(target).isFile() ? target : resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' }[extname(file)] || 'application/octet-stream')
  createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
let browser, page, stage = 'active', reject = true, readFailure = false
const checks = [], errors = [], unexpected = [], writes = [], reads = []
const consoleData = () => stage === 'active' ? fixture.stages.active : fixture.stages[stage].console
const result = () => ({ checks, errors, unexpected, writes, reads, dist, mode: 'Current page with real SQLite fixture responses and simulated transport; no live browser writes' })
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote', '--disable-gpu', '--js-flags=--max-old-space-size=128'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: 'zh-CN' })
  context.setDefaultTimeout(6000)
  await context.addInitScript(() => {
    if (!localStorage.getItem('alinksec_user')) {
      localStorage.setItem('alinksec_token', 'sqlite-fixture-replay')
      localStorage.setItem('alinksec_user', JSON.stringify({ username: 'operator', role: 'operator' }))
    }
  })
  await context.route('**/api/**', async route => {
    const req = route.request(), url = new URL(req.url()), path = url.pathname, method = req.method()
    if (method === 'POST' && path === '/api/virus/findings/actions') {
      const body = req.postDataJSON(); writes.push(body)
      if (reject) return route.fulfill({ status: 400, json: { code: 400, msg: '文件状态已变化，请刷新' } })
      if (body.action === 'quarantine') { assert.deepEqual([...body.findingIds].sort(), [...fixture.findingIds].sort()); stage = 'pending' }
      else if (body.action === 'restore') { assert.deepEqual(body.findingIds, [fixture.findingIds[0]]); stage = 'restored' }
      else if (body.action === 'whitelist') { assert.deepEqual(body.findingIds, [fixture.findingIds[1]]); stage = 'whitelisted' }
      else throw new Error('Unexpected action ' + body.action)
      await new Promise(done => setTimeout(done, 350))
      return route.fulfill({ json: { code: 0, data: body.action === 'restore' ? fixture.restore : body.action === 'whitelist' ? fixture.whitelist : fixture.batch } })
    }
    if (method !== 'GET') { unexpected.push(`${method} ${path}`); return route.fulfill({ status: 500, json: { code: 500 } }) }
    reads.push(path + url.search)
    let data
    if (path === '/api/virus/findings/actions/receipts') {
      if (readFailure) return route.fulfill({ status: 503, json: { code: 503, msg: '回执暂不可用' } })
      const ids = url.searchParams.get('ids').split(',')
      if (ids[0] === fixture.restore.actionIds[0]) data = fixture.stages.restored.receipts
      else if (ids[0] === fixture.whitelist.actionIds[0]) data = fixture.stages.whitelisted.receipts
      else { assert.deepEqual(ids, fixture.batch.actionIds); data = stage === 'pending' ? fixture.stages.pending.receipts : fixture.stages.partial.receipts }
    } else if (path === '/api/virus/stats') data = consoleData().stats
    else if (path === '/api/virus/findings') data = consoleData().findings
    else if (path === '/api/virus/tasks') data = consoleData().tasks
    else if (path === '/api/virus/db') data = consoleData().db
    else if (path === '/api/virus/whitelist') data = consoleData().whitelist
    else if (path === `/api/virus/findings/${fixture.findingIds[0]}/history`) data = consoleData().history
    else if (path === '/api/virus/tasks/' + fixture.task + '/evidence') data = consoleData().evidence
    else if (Object.hasOwn(engines, path)) data = engines[path]
    else { unexpected.push(`${method} ${path}`); return route.fulfill({ status: 500, json: { code: 500 } }) }
    return route.fulfill({ json: { code: 0, data } })
  })
  page = await context.newPage(); page.on('pageerror', e => errors.push(e.message))
  await page.goto(`http://127.0.0.1:${server.address().port}/virus`)
  await page.getByRole('tab', { name: '扫描任务', exact: true }).click()
  await page.getByRole('button', { name: '查看本次检出', exact: true }).click()
  const pane = page.getByRole('tabpanel', { name: '检出处置', exact: true })
  await expect(pane).toContainText('任务 #' + fixture.task)
  assert.ok(reads.some(path => path.includes('taskId=' + fixture.task)))
  checks.push('task-opens-exact-finding-filter')
  const row = path => pane.getByRole('row').filter({ hasText: path })
  await row('/tmp/harmless.sh').getByRole('button', { name: '隔离', exact: true }).click()
  let dialog = page.getByRole('dialog', { name: '确认隔离', exact: true })
  await expect(dialog).toContainText('b'.repeat(64))
  await expect(dialog.getByRole('button', { name: '确认隔离 1 项', exact: true })).toBeDisabled()
  await dialog.getByRole('button', { name: '取消', exact: true }).click()
  assert.equal(writes.length, 0)
  await row('/tmp/harmless.sh').getByRole('button', { name: '隔离', exact: true }).click()
  await dialog.locator('.el-checkbox__label').click()
  await dialog.getByRole('button', { name: '确认隔离 1 项', exact: true }).click()
  await expect(dialog).toContainText('文件状态已变化，请刷新')
  await expect(dialog.getByRole('button', { name: '确认隔离 1 项', exact: true })).toBeDisabled()
  await expect(row('/tmp/harmless.sh')).toContainText('待处置')
  await dialog.getByRole('button', { name: '取消', exact: true }).click()
  checks.push('review-cancel-never-submits-and-error-blocks-blind-resubmission')
  reject = false
  await pane.locator('.el-table__header-wrapper .el-checkbox').click()
  await pane.getByRole('button', { name: '批量隔离（2）', exact: true }).click()
  dialog = page.getByRole('dialog', { name: '确认隔离', exact: true })
  await expect(dialog).toContainText('/tmp/second.sh')
  await dialog.locator('.el-checkbox__label').click()
  const submit = dialog.getByRole('button', { name: '确认隔离 2 项', exact: true })
  await submit.click()
  await expect(submit).toBeDisabled()
  await submit.evaluate(el => el.click())
  dialog = page.getByRole('dialog', { name: '本次处置回执', exact: true })
  await expect(dialog).toContainText('待确认 2')
  assert.equal(writes.length, 2)
  stage = 'partial'
  await expect(dialog).toContainText('成功 1 · 待确认 0 · 失败 1', { timeout: 10000 })
  await expect(dialog).toContainText('identity_changed')
  await dialog.screenshot({ path: resolve(base, 'batch-partial.png'), animations: 'disabled' })
  checks.push('single-submission-exact-batch-polls-partial-per-file-success')
  readFailure = true
  await dialog.getByRole('button', { name: '刷新本次回执', exact: true }).click()
  await expect(dialog).toContainText('回执暂不可用')
  await expect(dialog).toContainText('成功 1 · 待确认 0 · 失败 1')
  readFailure = false
  await dialog.getByRole('button', { name: '刷新本次回执', exact: true }).click()
  await expect(dialog).not.toContainText('回执暂不可用')
  await dialog.getByRole('button', { name: '关闭', exact: true }).click()
  await pane.getByRole('button', { name: '刷新检出', exact: true }).click()
  await row('/tmp/harmless.sh').getByRole('button', { name: '复核恢复', exact: true }).click()
  dialog = page.getByRole('dialog', { name: '确认恢复', exact: true })
  await expect(dialog).toContainText('目标路径被占用')
  await dialog.locator('.el-checkbox__label').click()
  await dialog.getByRole('button', { name: '确认恢复 1 项', exact: true }).click()
  dialog = page.getByRole('dialog', { name: '本次处置回执', exact: true })
  await expect(dialog).toContainText('成功 1')
  await dialog.getByRole('button', { name: '查看文件完整历史', exact: true }).click()
  const history = page.getByRole('dialog', { name: '文件处置历史', exact: true })
  await expect(history).toContainText('已确认成功')
  await history.getByLabel('Close this dialog').click()
  checks.push('receipt-read-error-preserves-results-and-restore-opens-persistent-history')
  await page.setViewportSize({ width: 390, height: 844 })
  await row('/tmp/second.sh').getByRole('button', { name: '加白', exact: true }).click()
  dialog = page.getByRole('dialog', { name: '确认加白', exact: true })
  await expect(dialog).toContainText('跨主机、跨路径')
  assert.ok(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth), 'Mobile review wraps paths, digest and confirmation')
  await dialog.screenshot({ path: resolve(base, 'mobile-whitelist-review.png'), animations: 'disabled' })
  await dialog.locator('.el-checkbox__label').click()
  await dialog.getByRole('button', { name: '确认加白 1 项', exact: true }).click()
  dialog = page.getByRole('dialog', { name: '本次处置回执', exact: true })
  await expect(dialog).toContainText('策略已保存 1')
  await expect(dialog).toContainText('成功 0')
  assert.ok(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth), 'Mobile receipts fit')
  await dialog.getByRole('button', { name: '关闭', exact: true }).click()
  await page.getByTestId('yara-status').getByRole('button', { name: '扫描此主机', exact: true }).click()
  const scan = page.getByRole('dialog', { name: '发起自定义扫描', exact: true })
  assert.ok(await scan.evaluate(el => el.scrollWidth <= el.clientWidth), 'Previously fixed mobile scan confirmation fits')
  await scan.screenshot({ path: resolve(base, 'mobile-scan-followup.png'), animations: 'disabled' })
  await scan.getByRole('button', { name: '取消', exact: true }).click()
  await page.evaluate(() => localStorage.setItem('alinksec_user', JSON.stringify({ username: 'viewer', role: 'viewer' })))
  await page.reload()
  for (const name of ['隔离', '复核恢复', '删除', '加白', '快速扫描', '扫描此主机']) await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0)
  await expect(page.getByRole('button', { name: '处置历史', exact: true })).toHaveCount(2)
  checks.push('mobile-review-receipts-scan-wrap-and-viewer-readonly')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
  writeFileSync(resolve(base, 'result.json'), JSON.stringify({ passed: true, ...result() }, null, 2))
  console.log(JSON.stringify({ passed: true, checks }))
} catch (e) {
  await page?.screenshot({ path: resolve(base, 'failure.png') }).catch(() => {})
  writeFileSync(resolve(base, 'failure.json'), JSON.stringify({ error: String(e), ...result() }, null, 2))
  throw e
} finally { await browser?.close(); await new Promise(done => server.close(done)) }
