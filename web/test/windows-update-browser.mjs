import assert from 'node:assert/strict'
import { readFileSync, writeFileSync, mkdirSync, existsSync, statSync, createReadStream } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, resolve, extname, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(process.env.ALINKSEC_WINDOWS_UPDATE_PREVIEW_DIST || resolve(web, 'dist'))
const root = resolve(web, '../.tmp/windows-update-browser')
const fixture = JSON.parse(readFileSync(resolve(process.env.ALINKSEC_WINDOWS_UPDATE_BROWSER_FIXTURES || resolve(web, '../.tmp/windows-update-fixtures'), 'workflow.json')))
const stages = fixture.stages
assert.ok(existsSync(resolve(dist, 'index.html'))); mkdirSync(root, { recursive: true })
const server = createServer((req, res) => {
 let file
 try { file = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) } catch { res.writeHead(400); res.end(); return }
 if (file !== dist && !file.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
 if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html')
 res.setHeader('Content-Type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.png': 'image/png', '.woff2': 'font/woff2' }[extname(file)] || 'application/octet-stream')
 createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
let stage = 'discovered', fail = false, failCreate = false, browser, activePage
const errors = [], unexpected = [], checks = [], writes = []
try {
 async function session(role, id) {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote', '--disable-gpu', '--js-flags=--max-old-space-size=128'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1050 } }); context.setDefaultTimeout(10000)
  await context.addInitScript(({ role, id }) => { if (location.protocol !== 'http:') return; localStorage.setItem('alinksec_token', 'fixture'); localStorage.setItem('alinksec_user', JSON.stringify({ username: role, role, id })) }, { role, id })
  await context.route('**/api/**', async route => {
   const req = route.request(), url = new URL(req.url()), path = url.pathname; let data
   if (req.method() !== 'GET') {
    if (role === 'viewer') { unexpected.push('viewer write ' + path); return route.fulfill({ status: 403, json: { code: 403, msg: '只读' } }) }
    if (path === '/api/fix/windows/tasks') {
     writes.push(req.postDataJSON())
     if (failCreate) return route.fulfill({ status: 503, json: { code: 503, msg: '更新任务暂不可用' } })
     stage = 'pending_approval'; data = { taskId: stages[stage].tasks.list[0].id }
    } else if (path.match(/^\/api\/fix\/tasks\/\d+\/approve$/) && id === fixture.reviewer) { stage = 'pending_reboot'; data = { state: 'dispatched' } }
    else { unexpected.push(req.method() + ' ' + path); return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected write' } }) }
   } else if (path === '/api/fix/windows/hosts') {
    if (fail) return route.fulfill({ status: 503, json: { code: 503, msg: '更新状态暂不可用' } })
    data = stages[stage].hosts
   } else if (path === '/api/fix/windows/candidates') data = url.searchParams.get('agentId') === fixture.agent ? stages[stage].candidates : []
   else if (path === '/api/fix/tasks') data = stages[stage].tasks
   else if (path.match(/^\/api\/fix\/tasks\/\d+\/records$/)) data = stages[stage].records[path.split('/')[4]]
   else if (path === '/api/fix/approvers') data = [{ id: fixture.reviewer, username: fixture.reviewerName }]
   else if (['/api/vuln/findings', '/api/vuln/weakpwds', '/api/vuln/ports', '/api/vuln/coverage'].includes(path)) data = { list: [], total: 0, items: [] }
   else if (path === '/api/vuln/stats') data = { total: 0, pending: 0, fixed: 0, bySeverity: [] }
   else { unexpected.push(path); return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected request' } }) }
   return route.fulfill({ json: { code: 0, data } })
  })
  const page = await context.newPage(); activePage = page; page.on('pageerror', e => errors.push(e.message)); await page.goto(`http://127.0.0.1:${server.address().port}/vuln`)
  await page.getByRole('tab', { name: 'Windows 更新', exact: true }).click()
  return { page, context, section: page.getByTestId('windows-updates') }
 }
 let { page, context, section } = await session('viewer', fixture.viewer)
 await expect(section.getByText('发现完成', { exact: true })).toBeVisible()
 await expect(section.locator('.el-tag__content').filter({ hasText: /^尚未发现$/ })).toBeVisible()
 await section.getByRole('button', { name: 'Windows 更新验收', exact: true }).click()
 await expect(section.getByText('12345678-1234-1234-1234-123456789abc · 修订 7')).toBeVisible()
 await expect(section.getByRole('button', { name: '提交安装审批' })).toHaveCount(0)
 await expect(section.getByRole('button', { name: '发现更新' })).toHaveCount(0)
 await page.screenshot({ path: root + '/discovery-viewer-desktop.png', fullPage: true, animations: 'disabled' }); checks.push('captured-host-coverage-exact-identity-viewer-readonly')
 fail = true; await section.getByRole('button', { name: '刷新状态', exact: true }).click(); await expect(section.getByText('更新状态暂不可用', { exact: true })).toBeVisible()
 fail = false; await section.getByRole('button', { name: '重试', exact: true }).click(); await expect(section.getByText('发现完成', { exact: true })).toBeVisible(); checks.push('failed-refresh-clears-stale-targets-and-retries')
 await context.close(); await browser.close()
 ;({ page, context, section } = await session('operator', fixture.creator))
 await section.getByRole('button', { name: 'Windows 更新验收', exact: true }).click(); await section.getByRole('button', { name: '提交安装审批', exact: true }).click()
 const dialog = page.getByRole('dialog', { name: 'Windows 更新安装审批', exact: true })
 await dialog.getByRole('combobox').first().click(); await page.getByRole('option', { name: fixture.reviewerName, exact: true }).click()
 failCreate = true; await dialog.getByRole('button', { name: '提交审批', exact: true }).click(); await expect(dialog.getByRole('alert').filter({ hasText: '更新任务暂不可用' })).toBeVisible()
 failCreate = false; await dialog.getByRole('button', { name: '提交审批', exact: true }).click(); await expect(dialog).toBeHidden()
 assert.equal(writes.length, 2); assert.deepEqual(writes[1].items, [{ agentId: fixture.agent, candidateId: stages.discovered.candidates[0].id }]); assert.equal(writes[1].approver, fixture.reviewerName)
 await expect(section.getByText('待指定账号审批', { exact: true })).toBeVisible(); await expect(section.getByRole('button', { name: '审批安装', exact: true })).toHaveCount(0); checks.push('fixed-target-submission-retries-and-designated-approver-boundary')
 await context.close(); await browser.close()
 ;({ page, context, section } = await session('operator', fixture.reviewer))
 await section.getByRole('button', { name: '审批安装', exact: true }).click(); await page.getByRole('dialog').filter({ hasText: '审批 Windows 更新' }).getByRole('button', { name: '批准安装', exact: true }).click()
 await expect(section.getByText('待重启或复核', { exact: true })).toBeVisible(); await section.getByRole('button', { name: '详情', exact: true }).click()
 const record = page.getByRole('dialog', { name: 'Windows 更新执行记录', exact: true })
 await expect(record.getByText('Windows 更新验收 · 等待重启复核', { exact: true })).toBeVisible(); await expect(record.getByText('需要人工安排系统重启；Agent 将继续复核。', { exact: true })).toBeVisible()
 await page.setViewportSize({ width: 390, height: 844 }); await page.screenshot({ path: root + '/pending-reboot-mobile.png', animations: 'disabled' })
 const content = record.locator('.el-dialog'), bounds = await content.boundingBox(); assert.ok(bounds.x >= 0 && bounds.y >= 0 && bounds.x + bounds.width <= 391 && bounds.y + bounds.height <= 845)
 assert.ok(await content.evaluate(el => el.scrollWidth <= el.clientWidth))
 await record.getByRole('button', { name: 'Close this dialog', exact: true }).click()
 stage = 'verified'; await section.getByRole('button', { name: '刷新任务', exact: true }).click(); await expect(section.getByText('复核完成', { exact: true })).toBeVisible(); await section.getByRole('button', { name: '详情', exact: true }).click()
 await expect(record.getByText('Windows 更新验收 · 复核成功', { exact: true })).toBeVisible(); await page.screenshot({ path: root + '/verified-mobile.png', animations: 'disabled' }); checks.push('approval-pending-reboot-and-later-verification-mobile')
 assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
 writeFileSync(root + '/result.json', JSON.stringify({ passed: true, checks, errors, unexpected, mobileDialog: bounds }, null, 2) + '\n'); console.log('Passed Windows update browser checks:', checks)
} catch (error) {
 const body = await activePage?.locator('body').innerText().catch(() => '')
 await activePage?.screenshot({ path: root + '/failure.png', fullPage: true, animations: 'disabled' }).catch(() => {})
 writeFileSync(root + '/failure.json', JSON.stringify({ message: error.message, stage, body, errors, unexpected }, null, 2) + '\n')
 throw error
} finally { await browser?.close(); await new Promise(done => server.close(done)) }
