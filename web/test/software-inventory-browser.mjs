import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(process.env.SOFTWARE_INVENTORY_DIST || resolve(web, 'dist'))
const artifacts = resolve(process.env.SOFTWARE_INVENTORY_ARTIFACTS || resolve(web, '../.tmp/software-inventory-browser'))
assert.ok(existsSync(resolve(dist, 'index.html')), 'Build the production web bundle first')
mkdirSync(artifacts, { recursive: true })
const mime = { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' }
const server = createServer((req, res) => {
  let file
  try { file = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) } catch { res.writeHead(400); res.end(); return }
  if (file !== dist && !file.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
  if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html')
  res.setHeader('Content-Type', mime[extname(file)] || 'application/octet-stream')
  createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(resolve => server.listen(0, '127.0.0.1', resolve))
let browser
const errors = [], unexpected = [], scenarios = []
const host = { agent_id: 'inventory-host', hostname: 'inventory-host', os_type: 1, os_version: 'Ubuntu 24.04', arch: 'arm64', status: 1 }
let inventory, software, findings = []
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } })
  context.setDefaultTimeout(10000)
  await context.addInitScript(() => {
    localStorage.setItem('alinksec_token', 'browser-fixture')
    localStorage.setItem('alinksec_user', JSON.stringify({ username: 'admin', role: 'admin' }))
  })
  await context.route('**/api/**', route => {
    const path = new URL(route.request().url()).pathname
    let data
    if (path === '/api/hosts') data = { list: [host], total: 1 }
    else if (path === '/api/hosts/groups') data = []
    else if (path === '/api/hosts/inventory-host') data = { ...host, ...inventory }
    else if (path === '/api/hosts/inventory-host/software') data = software
    else if (/^\/api\/hosts\/inventory-host\/(ports|processes|accounts|containers)$/.test(path)) data = []
    else if (path === '/api/metrics/query_range') data = []
    else if (path === '/api/vuln/findings') data = { list: findings, total: findings.length }
    else if (path === '/api/vuln/stats') data = { bySeverity: [], total: findings.length, pending: findings.length, fixed: 0 }
    else if (path === '/api/vuln/weakpwds' || path === '/api/vuln/ports') data = { list: [], total: 0 }
    else { unexpected.push(path); return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected request' } }) }
    return route.fulfill({ json: { code: 0, data } })
  })
  const page = await context.newPage()
  page.on('pageerror', error => errors.push(error.message))
  const known = { distro_id: 'ubuntu', distro_version: '24.04', software_inventory_source: 'dpkg', software_succeeded_at: '2026-10-12 01:00:00', software_identity_error: '' }
  for (const [status, label] of [
    ['complete', '软件清单已完整采集'],
    ['failed', '最近软件采集失败；当前显示上次保留的清单，自动修复已阻断'],
    ['legacy', '软件清单完整性未知，请重新采集后进行自动修复'],
    ['unsupported', '当前系统的软件采集尚不支持；自动修复已阻断'],
    ['missing', '软件清单已采集，发行版身份信息不完整'],
    ['empty', '软件清单已完整采集'],
  ]) {
    inventory = { ...known, software_collection_status: ['missing', 'empty'].includes(status) ? 'complete' : status }
    software = [{ name: 'inventory-fixture', version: '2:1.0-1', source: 'dpkg', architecture: 'amd64' },
      { name: 'inventory-fixture', version: '2:1.0-1', source: 'dpkg', architecture: 'i386' }]
    if (status === 'legacy') { inventory = { software_collection_status: 'legacy' }; software = [ { ...software[0], architecture: '' } ] }
    if (status === 'missing') Object.assign(inventory, { distro_version: '', software_identity_error: 'distribution_identity_incomplete' })
    if (status === 'empty') software = []
    await page.goto(`http://127.0.0.1:${server.address().port}/hosts`)
    await page.getByRole('button', { name: '详情', exact: true }).click()
    const drawer = page.locator('.el-drawer')
    await expect(drawer.getByText(label, { exact: true })).toBeVisible()
    if (['complete', 'failed'].includes(status)) {
      await expect(drawer.getByRole('cell', { name: 'amd64', exact: true })).toBeVisible()
      await expect(drawer.getByRole('cell', { name: 'i386', exact: true })).toBeVisible()
    }
    if (status === 'legacy') {
      await expect(drawer.getByRole('cell', { name: '未知', exact: true })).toBeVisible()
      await expect(drawer.getByRole('cell', { name: 'arm64', exact: true })).toHaveCount(0)
    }
    if (status === 'empty') await expect(drawer.getByText('完整采集结果为空', { exact: true })).toBeVisible()
    if (['complete', 'failed', 'legacy'].includes(status)) await page.screenshot({ path: `${artifacts}/${status}-desktop.png`, fullPage: true, animations: 'disabled' })
    scenarios.push(status)
  }
  await page.setViewportSize({ width: 390, height: 844 })
  await expect.poll(() => page.evaluate(() => document.querySelector('.el-drawer').getBoundingClientRect().width - innerWidth),
    { message: 'Drawer exceeds mobile width after layout settles' }).toBeLessThanOrEqual(0)
  const mobileBounds = await page.evaluate(() => ({ drawerWidth: document.querySelector('.el-drawer').getBoundingClientRect().width, viewportWidth: innerWidth }))
  await page.screenshot({ path: artifacts + '/empty-mobile.png', fullPage: true, animations: 'disabled' })
  await page.setViewportSize({ width: 1440, height: 1000 })
  const base = { id: 1, agent_id: 'scope-a', hostname: 'scope-a', cve_id: 'CVE-2026-45678', software: 'scope-fixture',
    installed_version: '1.0', fixed_version: '2.0', severity: 3, status: 0, source: 'dpkg', architecture: 'amd64',
    distro_id: 'ubuntu', distro_version: '24.04', os_type: 1, os_version: 'Ubuntu 24.04', identity_status: 'complete', identity_current: 1, execution_supported: 1,
    rule_source_id: 'manual', rule_digest: 'a'.repeat(64), evidence_status: 'declared', rule_current: 1 }
  findings = [base, { ...base, id: 2 }, { ...base, id: 3, agent_id: 'scope-b', hostname: 'scope-b' },
    { ...base, id: 4, architecture: 'i386', identity_current: 0 }, { ...base, id: 5, distro_id: 'debian' },
    { ...base, id: 6, distro_version: '22.04' }, { ...base, id: 7, installed_version: '1.1' },
    { ...base, id: 8, identity_status: 'legacy', identity_current: 0, source: '', architecture: '', distro_id: '', distro_version: '' },
    { ...base, id: 9, agent_id: 'scope-stale', hostname: 'scope-stale', identity_current: 0 }]
  await page.goto(`http://127.0.0.1:${server.address().port}/vuln`)
  const rows = page.locator('.el-table__body tr')
  await expect(rows).toHaveCount(6)
  const current = rows.filter({ hasText: 'ubuntu 24.04' }).filter({ hasText: 'dpkg · amd64' }).filter({ hasText: '1.0 → 2.0' })
  await expect(current).toHaveCount(1)
  await expect(current).toContainText('3 台')
  await expect(current).toContainText('1 项需重新采集/扫描或人工处理')
  const legacy = rows.filter({ hasText: '历史结果，请重新扫描' })
  await expect(legacy).toHaveCount(1)
  await expect(legacy.getByRole('button', { name: '一键修复', exact: true })).toHaveCount(0)
  const multiarch = rows.filter({ hasText: 'dpkg · i386' })
  await expect(multiarch.getByRole('button', { name: '一键修复', exact: true })).toHaveCount(0)
  await current.getByRole('button', { name: '一键修复', exact: true }).click()
  const dialog = page.locator('.el-dialog').filter({ hasText: '一键修复' })
  await expect(dialog).toContainText('ubuntu 24.04 · dpkg · amd64')
  await expect(dialog).toContainText('仅提交符合条件的检测项')
  await page.screenshot({ path: artifacts + '/vulnerability-scope-desktop.png', fullPage: true, animations: 'disabled' })
  await dialog.getByRole('button', { name: '取消', exact: true }).click()
  await legacy.getByRole('button', { name: '详情', exact: true }).click()
  const legacyDialog = page.locator('.el-dialog:visible').filter({ hasText: '匹配时身份' })
  await expect(legacyDialog).toContainText('请重新采集、扫描或人工处理')
  await expect(legacyDialog).toContainText('影响主机（1 台）')
  const hostTag = legacyDialog.locator('.el-tag')
  await expect(hostTag).toHaveText(['scope-a'])
  await expect(hostTag).toBeVisible()
  await expect(hostTag).toHaveCSS('opacity', '1')
  await expect(hostTag).toHaveCSS('transform', 'none')
  const detailHostTag = await hostTag.evaluate(tag => {
    const style = getComputedStyle(tag), bounds = tag.getBoundingClientRect()
    return { text: tag.textContent, opacity: style.opacity, transform: style.transform, width: bounds.width, height: bounds.height }
  })
  assert.ok(detailHostTag.width > 0 && detailHostTag.height > 0)
  await expect(legacyDialog).not.toContainText('{{')
  await page.screenshot({ path: artifacts + '/vulnerability-legacy-detail.png', fullPage: true, animations: 'disabled' })
  const scopeScenarios = ['distribution-release-architecture-version-separated', 'agents-counted-once', 'stale-excluded', 'legacy-blocked', 'multiarch-blocked', 'dialog-identity', 'detail-host-count-and-list']
  assert.deepEqual(errors, [])
  assert.deepEqual(unexpected, [])
  writeFileSync(artifacts + '/validation.json', JSON.stringify({ mode: 'production web bundle with synthetic API fixtures', scenarios, scopeScenarios, mobileBounds, detailHostTag, errors, unexpected }, null, 2) + '\n')
  console.log(`Passed software inventory display: ${scenarios.join(', ')} and mobile drawer bounds`)
  console.log(`Passed vulnerability scope display: ${scopeScenarios.join(', ')}`)
} finally { await browser?.close(); await new Promise(resolve => server.close(resolve)) }
