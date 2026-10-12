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
let inventory, software
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
  assert.deepEqual(errors, [])
  assert.deepEqual(unexpected, [])
  writeFileSync(artifacts + '/validation.json', JSON.stringify({ mode: 'production web bundle with synthetic API fixtures', scenarios, mobileBounds, errors, unexpected }, null, 2) + '\n')
  console.log(`Passed software inventory display: ${scenarios.join(', ')} and mobile drawer bounds`)
} finally { await browser?.close(); await new Promise(resolve => server.close(resolve)) }
