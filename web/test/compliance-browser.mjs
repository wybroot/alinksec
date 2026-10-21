import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, createReadStream } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, resolve, extname, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(process.env.ALINKSEC_COMPLIANCE_PREVIEW_DIST || resolve(web, 'dist'))
const root = resolve(web, '../.tmp/compliance-browser')
const fixtures = JSON.parse(readFileSync(resolve(web, '../.tmp/baseline-browser-fixtures-sqlite.json'))).compliance
assert.equal(fixtures.profiles.length, 4)
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
let browser, page, selected = fixtures.profiles.at(-1), stage = 'pass', unavailable = false
const checks = [], errors = [], unexpected = [], writes = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote', '--disable-gpu', '--js-flags=--max-old-space-size=128'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, acceptDownloads: true })
  context.setDefaultTimeout(8000)
  await context.addInitScript(() => { if (!localStorage.getItem('alinksec_user')) { localStorage.setItem('alinksec_token', 'fixture'); localStorage.setItem('alinksec_user', JSON.stringify({ username: 'admin', role: 'admin' })) } })
  await context.route('**/api/**', async route => {
    const req = route.request(), path = new URL(req.url()).pathname
    const ok = data => route.fulfill({ json: { code: 0, data } })
    if (path === '/api/baseline/packages') return ok(fixtures.profiles.map(p => p.candidate))
    if (path === '/api/baseline/templates') return ok([])
    const pkg = fixtures.profiles.find(p => path === '/api/baseline/packages/' + p.candidate.id)
    if (pkg) return ok(pkg.candidate)
    if (path === '/api/baseline/latest') return ok(selected.latest)
    if (path.endsWith('/category-stats')) return ok(selected.categories)
    if (path.endsWith('/items')) return ok(selected.items)
    if (path.endsWith('/compliance') && req.method() === 'GET') return unavailable ? route.fulfill({ status: 503, json: { code: 503, msg: '条款证据暂不可用' } }) : ok(selected[stage])
    if (path.endsWith('/compliance/review') && req.method() === 'POST') {
      const body = req.postDataJSON(); writes.push(body)
      assert.equal(body.templateId, selected.pass[0].templateId)
      assert.equal(body.controlId, selected.pass[0].controls[0].id)
      assert.equal(body.revision, 0); assert.equal(body.decision, 'pass')
      assert.ok(body.note.length >= 10 && body.evidenceRef)
      stage = 'reviewed'; return ok(selected.reviewed)
    }
    unexpected.push(req.method() + ' ' + path)
    return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected request' } })
  })
  page = await context.newPage(); page.on('pageerror', e => errors.push(e.message))
  await page.goto(base + '/baseline-templates')
  const dialog = page.getByRole('dialog', { name: '基线模板版本', exact: true })
  for (const profile of fixtures.profiles) {
    await page.getByRole('row').filter({ hasText: profile.candidate.name }).getByRole('button', { name: '查看版本' }).click()
    await expect(dialog.getByText(/全部条款均需人工复核证据/)).toBeVisible()
    await expect(dialog.getByText(new RegExp('条款覆盖 ' + (profile.level === 2 ? 23 : 34)))).toBeVisible()
    await page.screenshot({ path: `${root}/package-${profile.platform}-level${profile.level}.png`, fullPage: true, animations: 'disabled' })
    await dialog.getByRole('button', { name: '关闭', exact: true }).click()
  }
  checks.push('four-compiled-catalogs-show-complete-clauses-and-explicit-manual-evidence')
  async function openAssessment() {
    await page.goto(base + '/baseline')
    await page.getByRole('button', { name: '明细', exact: true }).first().click()
    await page.getByRole('button', { name: '等保条款与证据', exact: true }).click()
    return page.locator('.compliance-panel')
  }
  let panel = await openAssessment()
  await expect(panel.getByText(/已确认通过 0/)).toBeVisible()
  await expect(panel.getByText(/待核验 34/)).toBeVisible()
  await panel.getByRole('button', { name: '复核', exact: true }).first().click()
  const review = page.getByRole('dialog', { name: '条款证据复核', exact: true })
  await review.locator('.el-select__wrapper').click()
  await page.getByRole('option', { name: '确认通过', exact: true }).click()
  await review.getByRole('textbox', { name: '条款复核依据', exact: true }).fill('已核验现场全部账户与有效口令策略的测试证据')
  await review.getByRole('textbox', { name: '条款证据索引', exact: true }).fill('case:browser-review;sha256=' + 'a'.repeat(64))
  await review.getByRole('button', { name: '保存复核记录' }).click()
  await expect(panel.getByText(/已确认通过 1/)).toBeVisible(); assert.equal(writes.length, 1)
  checks.push('all-automatic-passes-remain-pending-until-versioned-human-review')
  const downloaded = page.waitForEvent('download')
  await panel.getByRole('button', { name: '导出证据与复核记录' }).click()
  const exported = JSON.parse(readFileSync(await (await downloaded).path()))
  assert.equal(exported.profiles[0].counts.pass, 1)
  assert.equal(exported.profiles[0].controls[0].history[0].revision, 1)
  assert.equal(exported.profiles[0].contentSha256, selected.reviewed[0].contentSha256)
  checks.push('export-retains-package-digest-automatic-evidence-and-review-history')
  await page.screenshot({ path: root + '/assessment-desktop.png', fullPage: true, animations: 'disabled' })
  stage = 'error'; await panel.getByRole('button', { name: '刷新条款证据' }).click()
  await expect(panel.getByText(/异常 [1-9]/)).toBeVisible()
  await panel.getByRole('button', { name: '复核', exact: true }).first().click()
  await review.locator('.el-select__wrapper').click()
  await expect(page.getByRole('option', { name: '确认通过', exact: true })).toHaveClass(/is-disabled/)
  await expect(page.getByRole('option', { name: '确认不适用', exact: true })).toHaveClass(/is-disabled/)
  await page.keyboard.press('Escape'); await review.getByRole('button', { name: '取消', exact: true }).click()
  checks.push('errors-stay-visible-and-cannot-be-confirmed-as-pass-or-not-applicable')
  unavailable = true; await panel.getByRole('button', { name: '刷新条款证据' }).click()
  await expect(panel.getByText('条款证据暂不可用', { exact: true })).toBeVisible()
  await expect(panel.getByText(/已确认通过/)).toHaveCount(0)
  unavailable = false; stage = 'reviewed'; await panel.getByRole('button', { name: '刷新条款证据' }).click()
  await expect(panel.getByText(/已确认通过 1/)).toBeVisible()
  checks.push('load-failure-clears-stale-assessment-and-retry-recovers')
  await page.setViewportSize({ width: 390, height: 844 })
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'mobile viewport overflow')
  await page.screenshot({ path: root + '/assessment-mobile.png', fullPage: true, animations: 'disabled' })
  checks.push('mobile-evidence-dialog-fits-viewport')
  await page.evaluate(() => localStorage.setItem('alinksec_user', JSON.stringify({ username: 'viewer', role: 'viewer' })))
  panel = await openAssessment()
  await expect(panel.getByText(/已确认通过 1/)).toBeVisible()
  await expect(panel.getByRole('button', { name: '复核', exact: true })).toHaveCount(0)
  checks.push('viewer-can-read-and-export-evidence-without-review-controls')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
  writeFileSync(root + '/result.json', JSON.stringify({ passed: true, checks, errors, unexpected, writes }, null, 2))
  console.log('PASS complete compliance catalogs, evidence review, errors, export, roles and mobile layouts')
} catch (error) {
  writeFileSync(root + '/result.json', JSON.stringify({ passed: false, error: error.message, checks, errors, unexpected }, null, 2))
  await page?.screenshot({ path: root + '/failure.png', fullPage: true, timeout: 3000 }).catch(() => {})
  throw error
} finally { await browser?.close(); await new Promise(done => server.close(done)) }
