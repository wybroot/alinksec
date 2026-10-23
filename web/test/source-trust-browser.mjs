import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..'), dist = resolve(web, 'dist')
const root = resolve(web, '../.tmp/source-trust-browser'), fixtures = resolve(web, '../.tmp/source-trust-fixtures')
const fixture = JSON.parse(readFileSync(resolve(fixtures, 'console-sqlite.json')))
assert.equal(fixture.database, 'sqlite')
const stages = fixture.stages
assert.equal(stages.conflict.detail.reason, 'unresolved_conflict')
assert.equal(stages.reviewed.detail.selectedSource, fixture.z)
assert.equal(stages.stale.detail.reason, 'stale_decision')
assert.equal(stages.suppressed.detail.reason, 'suppressed')
assert.equal(stages.quarantined.policyZ.quarantined, true)
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
let browser, stage = 'conflict', role = 'admin', failDecision = false, failList = false, failPolicy = false
let holdDetail = false, releaseDetail, detailStarted = false
const errors = [], unexpected = [], writes = [], checks = [], screenshots = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1080 } })
  context.setDefaultTimeout(10000)
  await context.addInitScript(() => { localStorage.setItem('alinksec_token', 'fixture'); localStorage.setItem('alinksec_user', JSON.stringify({ username: 'fixture', role: sessionStorage.getItem('role') || 'admin' })) })
  await context.route('**/api/**', async route => {
    const request = route.request(), url = new URL(request.url()), path = url.pathname, method = request.method(), data = stages[stage]
    const ok = value => route.fulfill({ json: { code: 0, data: value } })
    const failure = msg => route.fulfill({ status: 409, json: { code: 40900, msg } })
    if (method === 'GET' && path === '/api/libraries') return ok(data.status)
    if (method === 'GET' && path === '/api/libraries/selections') {
      if (failList) return failure('来源选择列表暂不可用')
      assert.equal(url.searchParams.get('kind'), 'cve'); return ok(data.list)
    }
    if (method === 'GET' && path === '/api/libraries/selection') {
      assert.equal(url.searchParams.get('key'), fixture.cve)
      if (holdDetail) { detailStarted = true; await new Promise(done => { releaseDetail = done }) }
      return ok(data.detail)
    }
    if (method === 'GET' && path === '/api/libraries/selection/candidate') {
      const value = structuredClone(url.searchParams.get('source') === fixture.a ? data.candidateA : data.candidateZ)
      value.declaration.document.description = '<img src=x onerror="window.sourceTrustInjected=true">'
      return ok(value)
    }
    if (method === 'GET' && path === '/api/libraries/selection/history') return ok(url.searchParams.get('kind') === 'source' ? data.policyHistory : data.history)
    if (method === 'GET' && path.endsWith('/policy')) {
      if (failPolicy) return failure('来源策略暂不可用')
      return ok(path.includes(fixture.a) ? data.policyA : data.policyZ)
    }
    if (method === 'POST' && path === '/api/libraries/selection/decision') {
      assert.equal(role, 'admin'); const body = request.postDataJSON()
      assert.equal(body.kind, 'cve'); assert.equal(body.key, fixture.cve); assert.equal(body.contextDigest, data.detail.contextDigest)
      assert.equal(body.revision, data.detail.decision.revision); assert.ok(body.note.trim())
      if (failDecision) return failure('候选内容、策略或处理决定已变化，请刷新后重新确认')
      assert.equal(body.action, 'select'); assert.equal(body.source, fixture.z)
      writes.push({ operation: 'select', body }); stage = 'reviewed'; return ok(stages.reviewed.detail)
    }
    if (method === 'PUT' && path.endsWith('/policy')) {
      assert.equal(role, 'admin'); const body = request.postDataJSON()
      assert.equal(body.revision, data.policyZ.revision); assert.equal(body.tier, 'preferred'); assert.equal(body.priority, 50); assert.equal(body.quarantined, true)
      writes.push({ operation: 'policy', body }); stage = 'quarantined'; return ok({ policy: stages.quarantined.policyZ })
    }
    unexpected.push(method + ' ' + path); return route.fulfill({ status: 500, json: { code: 50000, msg: 'Unexpected request' } })
  })
  const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message))
  const shot = async name => { await page.screenshot({ path: root + '/' + name, fullPage: true, animations: 'disabled' }); screenshots.push(name) }
  const panel = page.locator('.source-trust'), detail = page.getByRole('dialog', { name: '条目来源选择', exact: true })
  const policy = page.getByRole('dialog', { name: fixture.z + ' · 来源策略', exact: true })
  const query = () => panel.getByRole('button', { name: '查询来源选择', exact: true }).click()
  const open = async () => { await panel.getByRole('button', { name: '查看与复核', exact: true }).click(); await expect(detail).toContainText(fixture.cve) }
  async function chooseZ() {
    await detail.getByText('指定来源', { exact: true }).click(); await detail.locator('.el-form-item').filter({ hasText: '采用来源' }).locator('.el-select__wrapper').click()
    await page.getByRole('option', { name: fixture.z, exact: true }).click()
    await detail.getByRole('textbox').fill('Independent applicability review')
  }
  await page.goto(base + '/libraries'); await query(); await open()
  await expect(detail).toContainText('同级冲突，等待复核'); await expect(detail).toContainText(stages.conflict.detail.contextDigest)
  await detail.getByRole('button', { name: '查看内容', exact: true }).first().click()
  await expect(detail.locator('pre')).toContainText(JSON.stringify('<img src=x onerror="window.sourceTrustInjected=true">'))
  await expect(detail.locator('img[onerror]')).toHaveCount(0)
  assert.equal(await page.evaluate(() => window.sourceTrustInjected), undefined)
  await shot('source-conflict-desktop.png'); checks.push('actual-SQLite-conflict-and-candidate-digest; raw-declaration-is-text-not-HTML')
  await chooseZ(); await detail.getByRole('button', { name: '提交处理决定', exact: true }).click()
  await expect(detail).toContainText('管理员指定来源'); await expect(detail).toContainText('Independent item review')
  assert.equal(writes.length, 1); checks.push('admin-explicit-choice-binds-exact-context-and-monotonic-revision; captured-audit-visible')
  stage = 'stale'; await detail.getByRole('button', { name: '刷新候选与决定', exact: true }).click()
  await expect(detail).toContainText('候选已变化，等待复核'); await shot('source-stale-decision-desktop.png')
  failDecision = true; await chooseZ(); await detail.getByRole('button', { name: '提交处理决定', exact: true }).click()
  await expect(detail).toContainText('候选内容、策略或处理决定已变化，请刷新后重新确认'); assert.equal(writes.length, 1)
  checks.push('stale-binding-holds-item-and-rejected-write-remains-visible-without-success-message')
  failDecision = false; await detail.getByRole('button', { name: 'Close this dialog' }).click()
  const sourceRow = panel.locator('.el-table').first().getByRole('row').filter({ hasText: fixture.z })
  await sourceRow.getByRole('button', { name: '管理策略', exact: true }).click(); await expect(policy).toContainText('当前修订 0')
  await expect(policy.getByRole('spinbutton')).toBeEnabled()
  await policy.locator('.el-form-item').filter({ hasText: '信任等级' }).locator('.el-select__wrapper').click(); await page.getByRole('option', { name: '优先采用', exact: true }).click()
  await policy.getByRole('spinbutton').fill('50'); await policy.getByRole('switch').click(); await policy.getByRole('textbox').fill('Independent quarantine review')
  await policy.getByRole('button', { name: '保存来源策略', exact: true }).click(); await expect(policy).toBeHidden()
  await expect(sourceRow).toContainText('已隔离'); assert.equal(writes.length, 2)
  checks.push('admin-policy-binds-exact-revision; quarantine-is-visible-and-pending-delivery-is-explicit')
  for (const next of ['viewer', 'operator']) {
    role = next; await page.evaluate(value => sessionStorage.setItem('role', value), role); await page.goto(base + '/libraries'); await query(); await open()
    await expect(detail.getByRole('button', { name: '提交处理决定', exact: true })).toHaveCount(0)
    await detail.getByRole('button', { name: 'Close this dialog' }).click()
    await panel.getByRole('row').filter({ hasText: fixture.z }).getByRole('button', { name: '查看策略', exact: true }).click()
    await expect(policy.getByRole('button', { name: '保存来源策略', exact: true })).toHaveCount(0)
    await expect(policy.getByRole('spinbutton')).toBeDisabled(); await policy.getByRole('button', { name: 'Close this dialog' }).click()
  }
  checks.push('viewer-and-operator-can-audit-but-cannot-edit-policy-or-item-decisions')
  await page.setViewportSize({ width: 390, height: 844 }); await open(); await shot('source-selection-mobile.png')
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth > innerWidth), false)
  await detail.getByRole('button', { name: 'Close this dialog' }).click(); failList = true; await query()
  await expect(panel).toContainText('来源选择列表暂不可用'); await shot('source-error-mobile.png')
  await expect(panel.getByRole('button', { name: '查看与复核', exact: true })).toHaveCount(0)
  checks.push('mobile-details-and-failure-remain-readable-without-page-overflow; failure-clears-stale-list')
  failList = false; await query(); holdDetail = true
  await panel.getByRole('button', { name: '查看与复核', exact: true }).click(); await expect.poll(() => detailStarted).toBe(true)
  await detail.getByRole('button', { name: 'Close this dialog' }).click(); await expect(detail).toBeHidden()
  const late = page.waitForResponse(response => new URL(response.url()).pathname === '/api/libraries/selection')
  releaseDetail(); await (await late).finished(); await page.evaluate(() => new Promise(done => requestAnimationFrame(() => requestAnimationFrame(done))))
  await expect(detail).toBeHidden(); checks.push('closed-detail-rejects-late-response')
  role = 'admin'; holdDetail = false; await page.evaluate(() => sessionStorage.setItem('role', 'admin')); await page.goto(base + '/libraries')
  failPolicy = true; await panel.getByRole('row').filter({ hasText: fixture.z }).getByRole('button', { name: '管理策略', exact: true }).click()
  await expect(policy).toContainText('来源策略暂不可用'); await expect(policy.getByRole('button', { name: '保存来源策略', exact: true })).toBeDisabled()
  checks.push('policy-fetch-failure-never-enables-default-unreviewed-form-write')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, []); assert.equal(writes.length, 2)
  writeFileSync(root + '/result.json', JSON.stringify({ checks, writes, errors, unexpected, screenshots,
    fixtureSource: 'Real SQLite catalog transactions captured for conflict, selected, stale, suppressed and quarantined states. Rejections, delayed response, XSS-shaped declaration text and unavailable endpoints are explicit browser fault injections.' }, null, 2))
} finally { releaseDetail?.(); await browser?.close(); await new Promise(done => server.close(done)) }
