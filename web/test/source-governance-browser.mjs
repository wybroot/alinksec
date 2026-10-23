import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, createReadStream } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, resolve, extname, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const preview = process.env.ALINKSEC_GOVERNANCE_PREVIEW_DIST
const dist = preview ? resolve(preview) : resolve(web, 'dist')
const root = resolve(web, preview ? '../.tmp/source-governance-preview' : '../.tmp/source-governance-browser')
const fixture = JSON.parse(readFileSync(resolve(process.env.ALINKSEC_GOVERNANCE_FIXTURE_DIR || resolve(web, '../.tmp/source-governance-fixtures'), 'console-sqlite.json')))
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
let stage = 'active', rejectDecision = true, browser
const errors = [], unexpected = [], writes = [], scenarios = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote', '--disable-gpu', '--js-flags=--max-old-space-size=128'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } }); context.setDefaultTimeout(8000)
  await context.addInitScript(() => { if (!localStorage.getItem('alinksec_user')) { localStorage.setItem('alinksec_token', 'fixture'); localStorage.setItem('alinksec_user', JSON.stringify({ username: 'admin', role: 'admin' })) } })
  await context.route('**/api/**', async route => {
    const req = route.request(), path = new URL(req.url()).pathname, method = req.method(), current = fixture.stages[stage]
    let data
    if (method === 'GET' && path === '/api/libraries') data = current.status
    else if (method === 'GET' && path === '/api/libraries/cves') data = current.rules
    else if (method === 'GET' && path === `/api/libraries/cves/${fixture.cve}/declarations`) data = current.declarations
    else if (method === 'GET' && path === `/api/libraries/sources/${fixture.source}/governance`) data = current.history
    else if (method === 'POST' && path === `/api/libraries/sources/${fixture.source}/cves/${fixture.cve}/decision`) {
      const body = req.postDataJSON(); writes.push({ path, body, rejected: rejectDecision })
      assert.equal(body.documentDigest, current.declarations.find(d => d.source_id === fixture.source).documentDigest)
      assert.ok(body.note.trim())
      if (rejectDecision) return route.fulfill({ status: 400, json: { code: 400, msg: '治理操作暂时失败' } })
      stage = body.withdraw ? 'withdrawn' : 'restored'; data = { locallyWithdrawn: body.withdraw }
    } else if (method === 'POST' && path === `/api/libraries/sources/${fixture.source}/retire`) {
      const body = req.postDataJSON(); writes.push({ path, body }); assert.ok(body.note.trim())
      stage = 'retired'; data = { changed: false }
    } else { unexpected.push(`${method} ${path}`); return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected request' } }) }
    return route.fulfill({ json: { code: 0, data } })
  })
  const page = await context.newPage(); page.on('pageerror', e => errors.push(e.message))
  await page.goto(`http://127.0.0.1:${server.address().port}/libraries`)
  await expect(page.getByRole('heading', { name: '来源治理', exact: true })).toBeVisible()
  await expect(page.getByText('部署已移除，数据仍有效', { exact: true })).toHaveCount(2)
  await page.getByRole('button', { name: '查看漏洞规则依据', exact: true }).click()
  await page.getByRole('row').filter({ hasText: fixture.cve }).getByRole('button', { name: '查看依据', exact: true }).click()
  const ruleDialog = page.getByRole('dialog', { name: fixture.cve, exact: true })
  await expect(ruleDialog.getByRole('button', { name: '撤销本地声明', exact: true })).toHaveCount(2)
  await expect(ruleDialog).toContainText('选中的撤销公告继续阻止较低来源回填')
  await page.screenshot({ path: root + '/active-declarations.png', fullPage: true, animations: 'disabled' })
  await ruleDialog.getByRole('button', { name: '查看原始声明', exact: true }).first().click()
  const original = page.getByRole('dialog', { name: '原始公告声明', exact: true })
  await expect(original).toContainText('Browser governance declaration')
  await original.getByText('完整公告声明', { exact: true }).click()
  await expect(original.locator('pre')).toContainText(fixture.cve)
  await page.screenshot({ path: root + '/original-declaration.png', fullPage: true, animations: 'disabled' })
  await original.locator('.el-dialog__headerbtn').click()
  async function decision(label, title, note) {
    await ruleDialog.getByRole('button', { name: label, exact: true }).first().click()
    const prompt = page.getByRole('dialog', { name: title, exact: true })
    await prompt.getByRole('textbox').fill(note); await prompt.getByRole('button', { name: '确认', exact: true }).click()
    await expect(prompt).toBeHidden()
  }
  await decision('撤销本地声明', '撤销公告声明', 'Browser fixture withdrawal')
  await expect(page.getByText('治理操作暂时失败', { exact: true })).toBeVisible()
  assert.equal(stage, 'active'); scenarios.push('failed-decision-keeps-active-state')
  rejectDecision = false
  await decision('撤销本地声明', '撤销公告声明', 'Browser fixture withdrawal')
  await expect(ruleDialog).toContainText('当前来源依据暂停采用、已撤销或已退役')
  await expect(ruleDialog.getByRole('button', { name: '恢复本地声明', exact: true })).toHaveCount(1)
  await page.screenshot({ path: root + '/withdrawn-declaration.png', fullPage: true, animations: 'disabled' })
  scenarios.push('withdrawal-keeps-original-declaration-and-priority')
  await decision('恢复本地声明', '恢复公告声明', 'Browser fixture independent reinstatement')
  await expect(ruleDialog.getByRole('button', { name: '恢复本地声明', exact: true })).toHaveCount(0)
  await ruleDialog.locator('.el-dialog__headerbtn').click(); scenarios.push('explicit-current-digest-reinstatement')
  const sourceRow = page.getByRole('row').filter({ has: page.getByRole('cell', { name: fixture.source, exact: true }) }).filter({ has: page.getByRole('button', { name: '退役来源', exact: true }) })
  await sourceRow.getByRole('button', { name: '退役来源', exact: true }).click()
  const retirePrompt = page.getByRole('dialog', { name: '退役安全来源', exact: true })
  await expect(retirePrompt).toContainText('该标识不能恢复同步')
  await retirePrompt.getByRole('textbox').fill('Browser fixture retired provider')
  await retirePrompt.getByRole('button', { name: '确认退役', exact: true }).click()
  const retiredRow = page.getByRole('row').filter({ has: page.getByRole('cell', { name: fixture.source, exact: true }) }).filter({ has: page.getByRole('button', { name: '治理记录', exact: true }) })
  await expect(retiredRow).toContainText('已退役'); await expect(retiredRow.getByRole('button', { name: '退役来源', exact: true })).toHaveCount(0)
  await page.screenshot({ path: root + '/retired-source.png', fullPage: true, animations: 'disabled' })
  await retiredRow.getByRole('button', { name: '治理记录', exact: true }).click()
  const history = page.getByRole('dialog', { name: `${fixture.source} · 治理记录`, exact: true })
  await expect(history.getByText('本地撤销', { exact: true })).toBeVisible(); await expect(history.getByText('来源退役', { exact: true })).toBeVisible()
  await history.getByRole('row').filter({ hasText: '本地撤销' }).getByRole('button', { name: '查看', exact: true }).click()
  const event = page.getByRole('dialog', { name: '治理时原始依据', exact: true })
  await expect(event).toContainText('Browser fixture withdrawal'); await expect(event).toContainText(fixture.source)
  await expect(event).toContainText('Browser governance declaration')
  await page.screenshot({ path: root + '/immutable-audit.png', fullPage: true, animations: 'disabled' })
  await event.locator('.el-dialog__headerbtn').click(); await history.locator('.el-dialog__headerbtn').click()
  scenarios.push('removed-source-retirement-and-original-audit')
  await page.setViewportSize({ width: 390, height: 844 })
  await page.getByRole('row').filter({ hasText: fixture.cve }).getByRole('button', { name: '查看依据', exact: true }).click()
  await expect(ruleDialog).toContainText('来源已退役')
  const mobileRuleBounds = await ruleDialog.locator('.el-dialog').boundingBox(); assert.ok(mobileRuleBounds.x >= 0 && mobileRuleBounds.x + mobileRuleBounds.width <= 390)
  await page.screenshot({ path: root + '/governance-mobile.png', fullPage: true, animations: 'disabled' })
  await ruleDialog.locator('.el-dialog__headerbtn').click()
  for (const role of ['operator', 'viewer']) {
    await page.evaluate(role => localStorage.setItem('alinksec_user', JSON.stringify({ username: role, role })), role); await page.reload()
    await expect(page.getByRole('heading', { name: '来源治理', exact: true })).toBeVisible()
    await expect(page.getByRole('button', { name: '退役来源', exact: true })).toHaveCount(0)
    await page.getByRole('button', { name: '查看漏洞规则依据', exact: true }).click()
    await page.getByRole('row').filter({ hasText: fixture.cve }).getByRole('button', { name: '查看依据', exact: true }).click()
    await expect(ruleDialog.getByRole('button', { name: '撤销本地声明', exact: true })).toHaveCount(0)
    await expect(ruleDialog.getByRole('button', { name: '恢复本地声明', exact: true })).toHaveCount(0)
    await expect(ruleDialog.getByRole('button', { name: '治理记录', exact: true })).toHaveCount(2)
    await ruleDialog.locator('.el-dialog__headerbtn').click()
  }
  scenarios.push('mobile-dialog-and-reader-roles')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
  writeFileSync(root + '/validation.json', JSON.stringify({ passed: true, mode: `${preview ? 'page preview' : 'production web bundle'} with captured ${fixture.database} lifecycle responses`, scenarios, writes, mobileRuleBounds, errors, unexpected }, null, 2))
  console.log('Passed source governance display: ' + scenarios.join(', '))
} finally { await browser?.close(); await new Promise(done => server.close(done)) }
