import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, createReadStream } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, resolve, extname, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(process.env.ALINKSEC_SCAP_PREVIEW_DIST || resolve(web, 'dist'))
const root = resolve(web, '../.tmp/scap-browser')
const fixtures = JSON.parse(readFileSync(resolve(web, '../.tmp/baseline-browser-fixtures-sqlite.json'))).scap
assert.equal(fixtures.nineOutcomes.hosts[0].evidence.rules.length, 9)
assert.ok(existsSync(resolve(dist, 'index.html')))
mkdirSync(root, { recursive: true })
const server = createServer((req, res) => {
  let file
  try { file = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) } catch { res.writeHead(400); res.end(); return }
  if (file !== dist && !file.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
  if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' }[extname(file)] || 'application/octet-stream')
  createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
const base = 'http://127.0.0.1:' + server.address().port
const prefix = '/api/baseline/scap', id = fixtures.candidate.id
const hash = bytes => createHash('sha256').update(bytes).digest('hex')
const source = Buffer.from(fixtures.sourceBase64, 'base64'), content = Buffer.from(fixtures.contentBase64, 'base64')
let browser, page, stage = 'candidate', tamper = false, unavailable = false
const checks = [], errors = [], unexpected = [], writes = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote', '--disable-gpu', '--js-flags=--max-old-space-size=128'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true })
  context.setDefaultTimeout(8000)
  await context.addInitScript(() => { if (!localStorage.getItem('alinksec_user')) { localStorage.setItem('alinksec_token', 'fixture'); localStorage.setItem('alinksec_user', JSON.stringify({ username: 'admin', role: 'admin' })) } })
  await context.route('**/api/**', async route => {
    const req = route.request(), path = new URL(req.url()).pathname, method = req.method()
    const ok = data => route.fulfill({ json: { code: 0, data } })
    const binary = bytes => route.fulfill({ body: bytes, headers: { 'Content-Type': 'application/octet-stream', 'X-Content-SHA256': tamper ? '0'.repeat(64) : hash(bytes) } })
    if (path === prefix + '/packages' && method === 'GET') return ok([fixtures[stage]])
    if (path === prefix + '/targets') return ok(fixtures.targets)
    if (path === prefix + '/tasks' && method === 'GET') return ok(fixtures.tasks)
    if (path === prefix + '/packages/import') {
      assert.ok(req.postDataBuffer().includes(source), 'upload must contain exact original reviewed archive')
      writes.push({ action: 'import' }); return ok(fixtures.candidate)
    }
    if (path === prefix + '/packages/' + id && method === 'GET') return ok(fixtures[stage])
    if (path === prefix + '/packages/' + id + '/source') return binary(source)
    if (path === prefix + '/packages/' + id + '/content') return binary(content)
    if (path === prefix + '/packages/' + id + '/decision') {
      const body = req.postDataJSON(); writes.push(body)
      assert.equal(body.revision, fixtures[stage].revision); assert.ok(body.note.trim())
      if (body.action === 'approve') stage = 'approved'
      else if (body.action === 'test') { assert.deepEqual(body.agentIds, ['ci-smoke-scap-ready']); stage = 'testing' }
      else if (body.action === 'publish') { assert.equal(stage, 'ready'); stage = 'published' }
      else throw new Error('Unexpected review action: ' + body.action)
      return ok(fixtures[stage])
    }
    if (path === prefix + '/tasks' && method === 'POST') {
      const body = req.postDataJSON(); writes.push({ action: 'create', ...body })
      assert.equal(body.packageId, id); assert.deepEqual(body.agentIds, ['ci-smoke-scap-ready'])
      assert.equal(body.name, '页面标准核查'); return ok({ taskId: fixtures.regular.id })
    }
    if (path === prefix + '/tasks/' + fixtures.nineOutcomes.id + '/agents/ci-smoke-scap-ready/evidence') return binary(Buffer.from(fixtures.nineEvidence))
    if (path.endsWith('/content') && path.startsWith(prefix + '/tasks/')) return binary(content)
    const task = [fixtures.nineOutcomes, fixtures.regular].find(t => path === prefix + '/tasks/' + t.id)
    if (task) return unavailable ? route.fulfill({ status: 503, json: { code: 503, msg: '标准核查结果暂不可用' } }) : ok(task)
    unexpected.push(method + ' ' + path)
    return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected request' } })
  })
  page = await context.newPage(); page.on('pageerror', e => errors.push(e.message))
  await page.goto(base + '/scap')
  await expect(page.getByRole('row').filter({ hasText: fixtures.candidate.name })).toBeVisible()
  await page.locator('input[type=file]').setInputFiles({ name: 'standards.zip', mimeType: 'application/zip', buffer: source })
  const review = page.getByRole('dialog', { name: 'SCAP 内容审核', exact: true })
  const result = page.getByRole('dialog', { name: '标准核查结果', exact: true })
  await expect(review.getByText(fixtures.candidate.source_sha256, { exact: true })).toBeVisible()
  await expect(review.getByText(/OpenSCAP command line tool/)).toBeVisible()
  await expect(review.getByRole('button', { name: '发布内容', exact: true })).toHaveCount(0)
  async function download(button, expected) {
    const pending = page.waitForEvent('download')
    await button.click()
    const bytes = readFileSync(await (await pending).path())
    assert.equal(hash(bytes), hash(expected)); return bytes
  }
  await download(review.getByRole('button', { name: '下载原始内容', exact: true }), source)
  await download(review.getByRole('button', { name: '下载下发内容', exact: true }), content)
  await review.getByPlaceholder('填写审核、测试或发布说明').fill('已核对标准来源、继承解析和适用系统范围')
  await review.getByRole('button', { name: '批准测试', exact: true }).click()
  await expect(review.getByRole('button', { name: '发布内容', exact: true })).toBeDisabled()
  await review.getByPlaceholder('选择适用且就绪的测试主机（最多 10 台）').click()
  await expect(page.getByRole('option', { name: /SCAP windows/ })).toHaveCount(0)
  await expect(page.getByRole('option', { name: /SCAP stale|SCAP unavailable/ })).toHaveCount(0)
  await page.getByRole('option', { name: /SCAP ready/ }).click(); await page.keyboard.press('Escape')
  await review.getByPlaceholder('填写审核、测试或发布说明').fill('在系统匹配且原生引擎就绪的主机上验证全部规则')
  await review.getByRole('button', { name: '下发内容测试', exact: true }).click()
  await expect(review.getByRole('button', { name: '查看最近测试', exact: true })).toBeVisible()
  await page.screenshot({ path: root + '/package-review-desktop.png', fullPage: true, animations: 'disabled' })
  checks.push('original-upload-and-source-derived-hash-downloads; admin-review-revision; ready-matching-OS-test-targets; pending-test-cannot-publish')
  await review.getByRole('button', { name: '查看最近测试', exact: true }).click()
  await expect(result.getByText('通过 (pass) 1', { exact: true })).toBeVisible()
  const names = ['通过 (pass)', '失败 (fail)', '执行异常 (error)', '未知 (unknown)', '不适用 (notapplicable)', '未检查 (notchecked)', '未选择 (notselected)', '信息项 (informational)', '已修复 (fixed)']
  for (const name of names) await expect(result.getByText(name + ' 1', { exact: true })).toBeVisible()
  await expect(result.getByText(/urn:xccdf:scoring:default：12.5 \/ 100/)).toBeVisible()
  const evidence = await download(result.getByRole('button', { name: '导出核查证据', exact: true }), Buffer.from(fixtures.nineEvidence))
  assert.equal(JSON.parse(evidence).counts.error, 1)
  await page.screenshot({ path: root + '/nine-outcomes-desktop.png', fullPage: true, animations: 'disabled' })
  tamper = true
  await result.getByRole('button', { name: '导出核查证据', exact: true }).click()
  await expect(page.getByText(/导出内容摘要不匹配/)).toBeVisible()
  tamper = false
  checks.push('nine-standard-outcomes-remain-distinct; native-weighted-score-and-evidence-digests; corrupt-download-blocked')
  await page.setViewportSize({ width: 390, height: 844 })
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'mobile viewport overflow')
  await page.screenshot({ path: root + '/nine-outcomes-mobile.png', fullPage: true, animations: 'disabled' })
  checks.push('mobile-standard-results-fit-viewport')
  unavailable = true
  await result.getByRole('button', { name: '刷新结果', exact: true }).click()
  await expect(page.getByText('标准核查结果暂不可用', { exact: true })).toBeVisible()
  await expect(result.getByRole('button', { name: '导出核查证据', exact: true })).toHaveCount(0)
  unavailable = false
  await result.getByRole('button', { name: 'Close this dialog', exact: true }).click()
  await review.getByRole('button', { name: 'Close this dialog', exact: true }).click()
  await page.setViewportSize({ width: 1440, height: 1000 })
  async function openPackage(value) { stage = value; await page.getByRole('button', { name: '刷新', exact: true }).click(); await page.getByRole('button', { name: '查看', exact: true }).first().click() }
  await openPackage('errorTest')
  await expect(review.getByRole('button', { name: '发布内容', exact: true })).toBeDisabled()
  await review.getByRole('button', { name: 'Close this dialog', exact: true }).click()
  await openPackage('ready')
  await expect(review.getByRole('button', { name: '发布内容', exact: true })).toBeEnabled()
  await review.getByPlaceholder('填写审核、测试或发布说明').fill('全部规则完成测试，确认没有 error 或 unknown 后发布')
  await review.getByRole('button', { name: '发布内容', exact: true }).click()
  await expect(review.getByRole('button', { name: '撤回内容', exact: true })).toBeVisible()
  await review.getByRole('button', { name: 'Close this dialog', exact: true }).click()
  checks.push('failed-load-clears-stale-results; error-unknown-block-publication; completed-clean-test-enables-publication')
  await page.evaluate(() => localStorage.setItem('alinksec_user', JSON.stringify({ username: 'operator', role: 'operator' })))
  await page.goto(base + '/scap')
  await expect(page.getByRole('button', { name: '导入 SCAP ZIP', exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: '发起标准核查', exact: true }).click()
  const create = page.getByRole('dialog', { name: '发起标准核查', exact: true })
  await create.getByLabel('任务名称').fill('页面标准核查')
  await create.locator('.el-select').nth(0).click()
  await page.getByRole('option', { name: /离线标准核查内容/ }).click()
  await create.locator('.el-select').nth(1).click()
  await page.getByRole('option', { name: /SCAP ready/ }).click(); await page.keyboard.press('Escape')
  await create.getByRole('button', { name: '下发核查', exact: true }).click()
  await expect(result.getByText('尚无 Agent 原生结果；终态指令状态不能替代核查证据')).toBeVisible()
  await download(result.getByRole('button', { name: '下载任务内容快照', exact: true }), content)
  await result.getByRole('button', { name: 'Close this dialog', exact: true }).click()
  checks.push('operator-creates-published-content-task; pending-command-cannot-fabricate-evidence; task-content-snapshot-download')
  await page.evaluate(() => localStorage.setItem('alinksec_user', JSON.stringify({ username: 'viewer', role: 'viewer' })))
  await page.goto(base + '/scap')
  await expect(page.getByRole('button', { name: '发起标准核查', exact: true })).toHaveCount(0)
  await page.getByRole('button', { name: '查看', exact: true }).first().click()
  await expect(review.getByRole('button', { name: '撤回内容', exact: true })).toHaveCount(0)
  await expect(review.getByRole('button', { name: '下载原始内容', exact: true })).toBeVisible()
  await review.getByRole('button', { name: 'Close this dialog', exact: true }).click()
  await page.getByRole('tab', { name: '引擎就绪状态', exact: true }).click()
  await expect(page.getByRole('row').filter({ hasText: 'SCAP stale' })).toContainText('状态已过期')
  await expect(page.getByRole('row').filter({ hasText: 'SCAP unavailable' })).toContainText('不可用')
  await page.screenshot({ path: root + '/readiness-desktop.png', fullPage: true, animations: 'disabled' })
  checks.push('viewer-read-download-without-write-controls; stale-and-unavailable-readiness-visible')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
  writeFileSync(root + '/result.json', JSON.stringify({ passed: true, evidenceKind: fixtures.evidenceKind, checks, errors, unexpected, writes }, null, 2))
  console.log('PASS SCAP review, standard outcomes, immutable downloads, readiness, roles and mobile pages')
} catch (error) {
  writeFileSync(root + '/result.json', JSON.stringify({ passed: false, error: error.message, checks, errors, unexpected, writes }, null, 2))
  await page?.screenshot({ path: root + '/failure.png', fullPage: true, timeout: 3000 }).catch(() => {})
  throw error
} finally { await browser?.close(); await new Promise(done => server.close(done)) }
