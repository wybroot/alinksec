import assert from 'node:assert/strict'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect } from '@playwright/test'

const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const preview = process.env.ALINKSEC_YARA_PREVIEW_DIST
const fullDist = process.env.ALINKSEC_YARA_UPDATE_DIST
assert.ok(!(preview && fullDist), 'Select either a page preview or a full frontend bundle')
const dist = resolve(preview || fullDist || resolve(web, 'dist'))
const fixturePath = resolve(process.env.ALINKSEC_YARA_UPDATE_FIXTURE || resolve(web, '../.tmp/library-auto-update/browser-fixtures.json'))
const fixture = JSON.parse(readFileSync(fixturePath))
const output = resolve(process.env.ALINKSEC_YARA_UPDATE_OUTPUT || resolve(web, '../.tmp/yara-update-browser'))
const original = fixture.responses['/api/virus/yara-status']
const ready = original.items.find(row => row.state === 'ready' && row.coverage?.update?.enabled && row.coverage.update.success_at)
assert.ok(ready, 'Capture a successful enabled updater before running this check')
assert.ok(existsSync(resolve(dist, 'index.html')), 'Build the selected frontend first')
mkdirSync(output, { recursive: true })

const server = createServer((req, res) => {
  let file
  try { file = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) }
  catch { res.writeHead(400); res.end(); return }
  if (file !== dist && !file.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
  if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.woff2': 'font/woff2' }[extname(file)] || 'application/octet-stream')
  createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
let browser, page, response = structuredClone(original), failedRequest = false
const checks = [], errors = [], unexpected = [], requests = []
const mode = `${preview ? 'current page preview' : 'production frontend'}; captured API responses and simulated update failures`

try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote', '--disable-gpu', '--js-flags=--max-old-space-size=128'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 }, locale: 'zh-CN', timezoneId: 'Asia/Shanghai' })
  context.setDefaultTimeout(6000)
  await context.addInitScript(() => {
    localStorage.setItem('alinksec_token', 'captured-api-replay')
    localStorage.setItem('alinksec_user', JSON.stringify({ username: 'viewer', role: 'viewer' }))
  })
  await context.route('**/api/**', async route => {
    const request = route.request(), path = new URL(request.url()).pathname
    requests.push(`${request.method()} ${path}`)
    if (request.method() !== 'GET' || !Object.hasOwn(fixture.responses, path)) {
      unexpected.push(`${request.method()} ${path}`)
      return route.fulfill({ status: 500, json: { code: 500, msg: 'Unexpected request' } })
    }
    if (path === '/api/virus/yara-status' && failedRequest) return route.fulfill({ status: 503, json: { code: 503, msg: 'YARA 状态暂不可用' } })
    return route.fulfill({ json: { code: 0, data: path === '/api/virus/yara-status' ? response : fixture.responses[path] } })
  })
  page = await context.newPage()
  page.on('pageerror', error => errors.push(error.message))
  await page.goto(`http://127.0.0.1:${server.address().port}/virus`)
  const section = page.getByTestId('yara-status')
  const host = section.locator('.host').filter({ has: page.getByText(ready.hostname, { exact: true }) })
  const timeText = seconds => page.evaluate(value => value ? new Date(value * 1000).toLocaleString() : '尚未记录', seconds)
  const assertTimes = async update => {
    for (const [label, key] of [['最近检查', 'checked_at'], ['最近成功检查', 'success_at'], ['规则内容变更', 'changed_at'], ['下次检查', 'next_check_at']]) {
      await expect(host).toContainText(`${label}：${await timeText(update[key])}`)
    }
  }
  const refresh = async (coverage = {}) => {
    response = structuredClone(original)
    Object.assign(response.items.find(row => row.agent_id === ready.agent_id).coverage, coverage)
    await section.getByRole('button', { name: '刷新状态', exact: true }).click()
    await expect(section.getByRole('button', { name: '刷新状态', exact: true })).toBeEnabled()
  }
  await expect(host.getByText('就绪', { exact: true })).toBeVisible()
  await expect(host).toContainText(ready.coverage.version)
  await expect(host).toContainText('已校验上游规则')
  await assertTimes(ready.coverage.update)
  await section.screenshot({ path: resolve(output, 'live-update-desktop.png'), animations: 'disabled' })
  const clamav = fixture.responses['/api/virus/clamav-status']
  if (clamav.items.some(row => row.state === 'disabled')) await expect(page.getByTestId('clamav-status').getByText('未配置启用', { exact: true })).toBeVisible()
  checks.push('captured-live-rule-digest-and-four-update-times')

  const scanFailures = { last_at: ready.coverage.observed_at - 10, last_issue: 'yara_timeout', counts: { yara_timeout: 3, yara_read_failed_or_changed: 2 } }
  await refresh({ last_issue: '', scans: 10, failures: 5, scan_failures: scanFailures })
  await expect(host.getByText('就绪', { exact: true })).toBeVisible()
  await expect(host).toContainText('最近失败：' + await timeText(scanFailures.last_at))
  await expect(host).toContainText('等待、编译或扫描超时：3')
  await expect(host).toContainText('文件读取失败或读取期间已变化：2')
  await section.screenshot({ path: resolve(output, 'scan-failures-desktop.png'), animations: 'disabled' })
  await refresh({ scans: 10, failures: 5, scan_failures: undefined })
  await expect(host).toContainText('当前 Agent 尚未报告失败分类与最近失败时间。')
  await expect(host).not.toContainText('最近失败：')
  await refresh()
  checks.push('scan-failure-history-visible-after-recovery-and-legacy-history-remains-unknown')

  const unchanged = { ...ready.coverage.update, checked_at: ready.coverage.update.checked_at + 60, success_at: ready.coverage.update.success_at + 60 }
  await refresh({ update: unchanged })
  await expect(host).toContainText('已校验上游规则')
  await assertTimes(unchanged)
  await expect(host).toContainText(ready.coverage.version)
  checks.push('unchanged-check-preserves-rule-change-time-and-version')

  for (const [code, label] of [['yara_update_download', '规则下载失败，保留上次可用规则'], ['yara_compile_error', '规则编译失败'], ['yara_update_storage', '规则保存或校验失败'], ['yara_timeout', '等待、编译或扫描超时']]) {
    const update = { ...ready.coverage.update, checked_at: ready.coverage.update.checked_at + 120, last_issue: code }
    await refresh({ update })
    await expect(host).toContainText(`自动更新失败：${label}`)
    await expect(host.getByText('就绪', { exact: true })).toBeVisible()
    await expect(host).toContainText(ready.coverage.version)
    await assertTimes(update)
  }
  await section.screenshot({ path: resolve(output, 'failed-update-desktop.png'), animations: 'disabled' })
  checks.push('failed-update-visible-with-usable-prior-rules-and-last-attempt-time')

  const waiting = { enabled: true, checked_at: 0, success_at: 0, changed_at: 0, next_check_at: 0, last_issue: '' }
  await refresh({ update: waiting })
  await expect(host).toContainText('等待首次成功更新')
  await assertTimes(waiting)
  await refresh({ update: { ...waiting, checked_at: ready.coverage.update.checked_at, last_issue: 'yara_update_download' } })
  await expect(host).toContainText('自动更新失败：规则下载失败')
  await expect(host).not.toContainText('保留上次可用规则')
  await expect(host).toContainText('最近成功检查：尚未记录')
  checks.push('first-success-pending-and-first-failure-do-not-invent-success-times')

  await refresh({ update: { ...waiting, enabled: false } })
  await expect(host).toContainText('未启用自动更新')
  await expect(host).not.toContainText('下次检查：')
  await refresh({ update: undefined })
  await expect(host).toContainText('尚未报告自动更新状态')
  await expect(host).not.toContainText('最近成功检查：')
  checks.push('disabled-and-legacy-agents-do-not-claim-updates')

  failedRequest = true
  await section.getByRole('button', { name: '刷新状态', exact: true }).click()
  await expect(section.getByText('YARA 状态暂不可用', { exact: true })).toBeVisible()
  await expect(section.locator('.host')).toHaveCount(0)
  failedRequest = false; response = structuredClone(original)
  await section.getByRole('button', { name: '重试', exact: true }).click()
  await expect(host).toContainText('已校验上游规则')
  checks.push('request-failure-clears-old-state-and-retry-restores-captured-data')

  await page.setViewportSize({ width: 390, height: 844 })
  await section.scrollIntoViewIfNeeded()
  const bounds = await section.boundingBox()
  assert.ok(bounds.x >= 0 && bounds.x + bounds.width <= 391, 'Mobile status fits the viewport')
  assert.ok(await section.evaluate(element => element.scrollWidth <= element.clientWidth), 'Rule digest and update times wrap')
  await assertTimes(ready.coverage.update)
  await section.screenshot({ path: resolve(output, 'live-update-mobile.png'), animations: 'disabled' })
  await refresh({ update: { ...ready.coverage.update, last_issue: 'yara_update_download' }, scans: 10, failures: 5, scan_failures: scanFailures })
  await expect(host).toContainText('自动更新失败：规则下载失败')
  await expect(host).toContainText('文件读取失败或读取期间已变化：2')
  assert.ok(await section.evaluate(element => element.scrollWidth <= element.clientWidth), 'Mobile failure history wraps')
  await section.screenshot({ path: resolve(output, 'failed-update-mobile.png'), animations: 'disabled' })
  await expect(page.getByRole('button', { name: '快速扫描', exact: true })).toHaveCount(0)
  checks.push('desktop-and-mobile-status-wrap-and-viewer-has-no-scan-controls')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
  writeFileSync(resolve(output, 'result.json'), JSON.stringify({ passed: true, mode, capturedAt: fixture.capturedAt, checks, errors, unexpected, requests, mobileSection: bounds }, null, 2) + '\n')
  console.log(JSON.stringify({ passed: true, mode, checks, errors, unexpected }))
} catch (error) {
  await page?.screenshot({ path: resolve(output, 'failure.png'), fullPage: true }).catch(() => {})
  writeFileSync(resolve(output, 'failure.json'), JSON.stringify({ error: String(error), mode, checks, errors, unexpected }, null, 2) + '\n')
  throw error
} finally {
  await browser?.close()
  await new Promise(done => server.close(done))
}
