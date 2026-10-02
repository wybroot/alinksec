import assert from 'node:assert/strict'
import { createHash, X509Certificate } from 'node:crypto'
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { chromium, expect as playwrightExpect } from '@playwright/test'

const expect = playwrightExpect.configure({ timeout: 30_000 })

assert.equal(process.env.ALINKSEC_SMOKE_ALLOW_FIXTURES, 'true')
const baseURL = process.env.ALINKSEC_SMOKE_BASE_URL
const database = new DatabaseSync(process.env.ALINKSEC_SMOKE_SQLITE_FILE)
database.exec('PRAGMA busy_timeout=5000')
const prefix = 'ci-browser-'
assert.equal(database.prepare('SELECT count(*) AS n FROM t_agent WHERE agent_id LIKE ?').get(`${prefix}%`).n, 0)
const malicious = '<img src="xss-fixture" onerror="window.__xss=1">'
const artifacts = resolve(process.env.ALINKSEC_SMOKE_BROWSER_ARTIFACTS || `.tmp/browser-artifacts-${Date.now()}`)
mkdirSync(artifacts, { recursive: true })
const errors = []
let browser, page
try {
  database.exec('BEGIN')
  const insertHost = database.prepare('INSERT INTO t_agent(agent_id,hostname,os_type,status,last_heartbeat) VALUES(?,?,1,1,CURRENT_TIMESTAMP)')
  for (let i = 1; i <= 105; i++) {
    const suffix = String(i).padStart(3, '0')
    insertHost.run(`${prefix}${suffix}`, i === 1 ? malicious : `${prefix}host-${suffix}`)
  }
  database.prepare(`INSERT INTO t_alert(alert_no,agent_id,event_type,severity,title,detail)
    VALUES('ci-browser-alert',?,'process',4,?,'{}')`).run(`${prefix}001`, malicious)
  const insertFinding = database.prepare(`INSERT INTO t_vuln_finding(task_id,agent_id,cve_id,software,installed_version,fixed_version,severity,status)
    VALUES(0,?,?,?,'1.0',?,4,?) RETURNING id`)
  const items = [
    { agentId: `${prefix}001`, findingId: insertFinding.get(`${prefix}001`, 'CVE-2099-1001', 'browser-openssl', '2.0', 0).id },
    { agentId: `${prefix}002`, findingId: insertFinding.get(`${prefix}002`, 'CVE-2099-1001', 'browser-openssl', '2.0', 0).id },
    { agentId: `${prefix}004`, findingId: insertFinding.get(`${prefix}004`, 'CVE-2099-1002', 'browser-libcurl', '3.0', 0).id },
  ]
  insertFinding.get(`${prefix}003`, 'CVE-2099-1001', 'browser-openssl', '2.0', 3)
  database.exec('COMMIT')
  const leaf = new X509Certificate(readFileSync(process.env.ALINKSEC_SMOKE_CA_FILE.replace('/certs/ca.crt', '/web-tls/server.crt')))
  const pin = createHash('sha256').update(leaf.publicKey.export({ format: 'der', type: 'spki' })).digest('base64')
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage',
    '--renderer-process-limit=1', `--ignore-certificate-errors-spki-list=${pin}`] })
  const context = await browser.newContext({ baseURL, viewport: { width: 1440, height: 1000 } })
  page = await context.newPage()
  page.on('pageerror', error => errors.push(error.message))
  page.on('console', message => { if (message.type() === 'error') errors.push(message.text()) })
  await page.goto('/login')
  await page.getByPlaceholder('用户名').fill('admin')
  await page.getByPlaceholder('密码', { exact: true }).fill(process.env.ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD)
  await page.getByRole('button', { name: '登 录' }).click()
  await expect(page).toHaveURL(/\/dashboard$/)

  async function canvasCheck(minimum) {
    await expect.poll(async () => page.locator('canvas').count()).toBeGreaterThanOrEqual(minimum)
    await expect.poll(() => page.evaluate(() => Array.from(document.querySelectorAll('canvas')).filter(canvas => {
      if (canvas.width <= 0 || canvas.height <= 0) return false
      const pixels = canvas.getContext('2d')?.getImageData(0, 0, canvas.width, canvas.height).data
      if (!pixels) return false
      let nonblank = 0
      for (let i = 3; i < pixels.length; i += 128) if (pixels[i] > 0) nonblank++
      return nonblank > 10
    }).length)).toBeGreaterThanOrEqual(minimum)
  }
  await canvasCheck(3)
  await page.screenshot({ path: `${artifacts}/dashboard-desktop.png`, fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await canvasCheck(3)
  assert.ok(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), 'Mobile document overflows horizontally')
  const overview = page.locator('.ops-overview')
  assert.ok((await overview.boundingBox()).width > 250, 'Mobile navigation leaves too little content space')
  await page.screenshot({ path: `${artifacts}/dashboard-mobile.png`, fullPage: true })
  await page.setViewportSize({ width: 1440, height: 1000 })
  console.log('ok - actual login and nonblank dashboard canvases on desktop/mobile')

  await page.goto('/hosts')
  await expect(page.locator('.el-pagination__total')).toContainText('105')
  assert.equal(await page.locator('.el-switch').count(), 0, 'Host policy status must be read-only')
  for (let next = 2; next <= 6; next++) {
    await page.locator('.el-pagination .btn-next').click()
    await expect(page.locator('.el-pager li.is-active')).toHaveText(String(next))
    await expect(page.locator('.el-table__body tr').first()).toContainText(`${prefix}host-${String((next - 1) * 20 + 1).padStart(3, '0')}`)
  }
  const later = page.locator('.el-table__body tr').filter({ hasText: `${prefix}host-105` })
  await later.getByRole('button', { name: '详情', exact: true }).click()
  await expect(page.getByRole('button', { name: '立即采集', exact: true })).toBeVisible()
  await canvasCheck(1)
  await page.getByRole('button', { name: '立即采集', exact: true }).click()
  await expect.poll(() => database.prepare("SELECT count(*) AS n FROM t_command WHERE agent_id=? AND type='collect_now'").get(`${prefix}105`).n).toBe(1)
  await page.screenshot({ path: `${artifacts}/hosts-last-page.png`, fullPage: true })
  console.log('ok - 105-host browser pagination, later-page detail/collection and read-only policy status')

  await page.goto('/vuln')
  await expect(page.locator('.chip').filter({ hasText: '修复率' })).toContainText('25%')
  async function importPatch(pkgName, targetVersion) {
    const result = await page.evaluate(async ({ pkgName, targetVersion }) => {
      const token = localStorage.getItem('alinksec_token')
      const form = new FormData()
      form.set('file', new Blob(['browser fixture']), 'patch.deb')
      for (const [name, value] of Object.entries({ osType: '1', pkgName, targetVersion, repoType: 'deb' })) form.set(name, value)
      return (await fetch('/api/fix/patches', { method: 'POST', headers: { Authorization: `Bearer ${token}` }, body: form })).json()
    }, { pkgName, targetVersion })
    assert.equal(result.code, 0, result.msg)
  }
  await importPatch('browser-openssl', '2.0')
  await importPatch('browser-libcurl', '3.0')
  const firstVuln = page.locator('.el-table__body tr').filter({ hasText: 'CVE-2099-1001' })
  await expect(firstVuln).toContainText('2.0')
  await firstVuln.getByRole('button', { name: '一键修复', exact: true }).click()
  await page.getByPlaceholder('必填（提交后由该人员审批放行）').fill('Browser CI')
  let submitted = page.waitForRequest(request => request.url().endsWith('/api/fix/tasks/package') && request.method() === 'POST')
  await page.getByRole('button', { name: '提交审批', exact: true }).click()
  const singleRequest = await submitted
  assert.deepEqual(singleRequest.postDataJSON().items.sort((a, b) => a.findingId - b.findingId), items.slice(0, 2))
  await expect(page.locator('.el-dialog').filter({ hasText: '一键修复' })).not.toBeVisible()
  await page.locator('.el-table__header-wrapper .el-checkbox').first().click()
  await page.getByRole('button', { name: /批量修复/ }).click()
  await page.getByPlaceholder('必填（提交后由该人员审批放行）').fill('Browser CI')
  submitted = page.waitForRequest(request => request.url().endsWith('/api/fix/tasks/package') && request.method() === 'POST')
  await page.getByRole('button', { name: '提交审批', exact: true }).click()
  const batchRequest = await submitted
  assert.deepEqual(batchRequest.postDataJSON().items.sort((a, b) => a.findingId - b.findingId), items)
  await expect.poll(() => database.prepare("SELECT count(*) AS n FROM t_fix_task WHERE approver='Browser CI' AND status=0").get().n).toBe(2)
  console.log('ok - browser single/batch repair submits the correct pending findings and renders versions/rate')

  await page.goto('/protect')
  await expect(page.locator('.prot-card')).toHaveCount(4)
  await expect(page.locator('.evt-item .el-tag').first()).toHaveText('严重')
  await expect(page.locator('.evt-item .t').first()).toHaveText(/\d{2}-\d{2} \d{2}:\d{2}/)
  assert.equal(await page.locator('.prot-card .el-switch').count(), 0, 'Engine cards must be read-only')
  const rule = page.locator('.el-table__body tr').first()
  await expect(rule.locator('.el-switch')).toBeVisible()
  const enabledBefore = await rule.locator('input[role="switch"]').getAttribute('aria-checked')
  assert.ok(enabledBefore === 'true' || enabledBefore === 'false')
  await rule.locator('.el-switch').click()
  await expect.poll(() => database.prepare("SELECT enabled FROM t_protect_rule WHERE type='process' ORDER BY rule_id LIMIT 1").get().enabled).toBe(enabledBefore === 'true' ? 0 : 1)
  await page.reload()
  await expect(page.locator('.el-table__body tr').first().locator('input[role="switch"]')).toHaveAttribute('aria-checked', enabledBefore === 'true' ? 'false' : 'true')
  console.log('ok - editable rule toggle persists through the real API and refresh')
  const fileSettings = page.locator('.protection-setting').filter({hasText:'关键文件完整性防护'})
  await expect(fileSettings.locator('textarea')).toHaveValue(/\/etc\/passwd/)
  await fileSettings.locator('textarea').fill('/work/browser-protected')
  await fileSettings.getByRole('button',{name:'保存配置'}).click()
  await expect.poll(()=>JSON.parse(database.prepare("SELECT match FROM t_protect_rule WHERE rule_id='PR-0002'").get().match).paths).toEqual(['/work/browser-protected'])
  const loginSettings = page.locator('.protection-setting').filter({hasText:'SSH 登录防护'})
  const loginThreshold = loginSettings.locator('input[role="spinbutton"]').first()
  await expect(loginThreshold).toBeEnabled()
  await expect(loginThreshold).toHaveAttribute('aria-disabled','false')
  await loginThreshold.fill('4')
  await loginSettings.getByText('限时封禁',{exact:true}).click()
  const loginDuration = loginSettings.locator('input[role="spinbutton"]').nth(3)
  await expect(loginDuration).toBeEnabled()
  await expect(loginDuration).toHaveAttribute('aria-disabled','false')
  await loginDuration.fill('120')
  await loginSettings.getByRole('button',{name:'保存配置'}).click()
  await expect.poll(()=>JSON.parse(database.prepare("SELECT match FROM t_protect_rule WHERE rule_id='PR-0003'").get().match).failure_threshold).toBe(4)
  await expect.poll(()=>JSON.parse(database.prepare("SELECT match FROM t_protect_rule WHERE rule_id='PR-0003'").get().match).block_duration_sec).toBe(120)
  await page.reload()
  await expect(fileSettings.locator('textarea')).toHaveValue('/work/browser-protected')
  await expect(loginSettings.locator('input[role="spinbutton"]').first()).toHaveValue('4')
  await page.setViewportSize({width:390,height:844})
  assert.ok(await page.evaluate(()=>document.documentElement.scrollWidth<=innerWidth),'Mobile protection settings overflow')
  await page.screenshot({path:`${artifacts}/protection-mobile.png`,fullPage:true})
  await page.setViewportSize({width:1440,height:1000})
  console.log('ok - file and SSH protection configuration persists through API and browser refresh')

  await page.goto('/screen')
  await canvasCheck(6)
  const brandBounds = await page.locator('.header .sub').boundingBox()
  const controlsBounds = await page.locator('.deco-btn').boundingBox()
  assert.ok(brandBounds.x + brandBounds.width <= controlsBounds.x, 'Screen controls overlap the brand')
  const risk = page.locator('.panel').filter({ has: page.getByRole('heading', { name: /主机风险值 TOP5/ }) }).locator('canvas').first()
  const bounds = await risk.boundingBox()
  for (let row = 0; row < 10; row++) {
    await page.mouse.move(bounds.x + bounds.width * 0.75, bounds.y + bounds.height * (row + 0.5) / 10)
    await page.waitForTimeout(60)
    if (await page.getByText('待处置告警 1 条', { exact: false }).last().isVisible()) break
  }
  await expect(page.getByText('待处置告警 1 条', { exact: false }).last()).toBeVisible()
  assert.equal(await page.locator('img[src="xss-fixture"]').count(), 0, 'Malicious label created an HTML element')
  assert.equal(await page.evaluate(() => window.__xss), undefined)
  await page.screenshot({ path: `${artifacts}/screen-desktop.png`, fullPage: true })
  await page.setViewportSize({ width: 390, height: 844 })
  await canvasCheck(6)
  await page.screenshot({ path: `${artifacts}/screen-mobile.png`, fullPage: true })
  console.log('ok - screen canvases render malicious host labels as text, including hovered tooltip')
  await page.setViewportSize({ width: 1440, height: 1000 })
  await page.getByRole('button', { name: '返回控制台', exact: true }).click()
  await expect(page).toHaveURL(/\/dashboard$/)
  await page.locator('.nav-item').filter({ hasText: '主机管理' }).click()
  await expect(page.locator('.el-pagination__total')).toContainText('105')
  assert.equal(await page.locator('.panel').first().evaluate(panel => getComputedStyle(panel).backgroundColor), 'rgb(255, 255, 255)')
  await page.screenshot({ path: `${artifacts}/console-after-screen.png`, fullPage: true })
  console.log('ok - return from screen restores the console theme and navigation')
  assert.deepEqual(errors, [], 'Browser console or page errors')
  writeFileSync(`${artifacts}/result.json`, JSON.stringify({ passed: true, errors }, null, 2))
  console.log(`Browser artifacts: ${artifacts}`)
} catch (error) {
  if (page) {
    await page.screenshot({ path: `${artifacts}/failure.png`, fullPage: true }).catch(() => {})
    await page.content().then(html => writeFileSync(`${artifacts}/failure.html`, html)).catch(() => {})
  }
  writeFileSync(`${artifacts}/result.json`, JSON.stringify({ passed: false, error: error.message, errors }, null, 2))
  throw error
} finally {
  await browser?.close()
  database.close()
}
