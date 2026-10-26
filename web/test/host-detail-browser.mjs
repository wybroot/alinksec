import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect as baseExpect } from '@playwright/test'
const expect = baseExpect.configure({ timeout: 15000 })
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..'), dist = resolve(web, 'dist')
const output = resolve(process.env.ALINKSEC_HOST_DETAIL_OUTPUT || resolve(web, '../.tmp/host-detail-browser'))
const capture = process.env.ALINKSEC_HOST_DETAIL_CAPTURE ? JSON.parse(readFileSync(process.env.ALINKSEC_HOST_DETAIL_CAPTURE)) : null
const sampledAt = Date.now(), bucket = Math.floor(sampledAt / 60000) * 60000
const host = capture?.host || { agent_id: 'detail-host', hostname: '验收主机', ip: '192.0.2.10', os_type: 1, os_version: 'Ubuntu 24.04', kernel: '6.8.0-fixture', arch: 'amd64', status: 1, isolation_status: 0, isolation_contract: 1, agent_version: '0.0.4', software_collection_status: 'complete', policy_version: 'actual-policy-version', disks: [{ mount: '/', fs_type: 'ext4', total_bytes: 40 * 1024 ** 3, used_bytes: 30 * 1024 ** 3, updated_at: new Date().toISOString() }] }
const measured = capture?.runtime || { latest: { sampled_at: sampledAt, cpu_percent: 0, memory_percent: 37.5, uptime_sec: 90061, host_info_at: sampledAt, host: { cpu_model: 'Actual fixture CPU', logical_cpus: 4, physical_cores: 2, memory_total_bytes: 8 * 1024 ** 3, boot_time_sec: Math.floor(sampledAt / 1000) - 90061, timezone: 'UTC', ip_list: ['192.0.2.10'], mac_list: ['02:00:00:00:00:01'] } }, samples: [{ bucket, sampled_at: sampledAt, cpu_percent: 0, memory_percent: 37.5 }], serverTime: sampledAt, source: 'heartbeat' }
const health = capture?.health || { checkedAt: new Date().toISOString(), status: 'healthy', components: ['api', 'database', 'grpc', 'storage', 'tls', 'metrics', 'redis', 'rabbitmq', 'cluster'].map(id => ({ id, name: { metrics: 'VictoriaMetrics', database: '关系数据库' }[id] || id, status: ['redis', 'rabbitmq'].includes(id) ? 'disabled' : 'healthy', message: '组件检测结果', details: {}, durationMs: 1 })) }
assert.ok(measured.latest.host.cpu_model); assert.ok(host.kernel); assert.ok(host.disks.length)
mkdirSync(output, { recursive: true })
const server = createServer((req, res) => {
  let file
  try { file = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) } catch { res.writeHead(400); res.end(); return }
  if (!file.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
  if (!existsSync(file) || !statSync(file).isFile()) file = resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.js': 'text/javascript', '.css': 'text/css', '.html': 'text/html', '.svg': 'image/svg+xml', '.woff2': 'font/woff2' }[extname(file)] || 'application/octet-stream')
  createReadStream(file).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
const base = `http://127.0.0.1:${server.address().port}`, checks = [], screenshots = [], errors = [], unexpected = []
let browser, runtime = structuredClone(measured), runtimeFailure = false, healthFailure = false
try {
  browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote', '--disable-gpu', '--js-flags=--max-old-space-size=128'] })
  const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } })
  await context.addInitScript(() => {
    localStorage.setItem('alinksec_token', 'host-detail-capture')
    localStorage.setItem('alinksec_user', JSON.stringify({ username: 'capture', role: sessionStorage.getItem('role') || 'admin' }))
  })
  await context.route('**/api/**', route => {
    const request = route.request(), path = new URL(request.url()).pathname
    const ok = data => route.fulfill({ json: { code: 0, data } })
    assert.equal(request.method(), 'GET', 'This browser scenario must not change real host state')
    if (path === '/api/hosts') return ok({ list: [host], total: 1 })
    if (path === '/api/hosts/groups') return ok([])
    if (path === `/api/hosts/${host.agent_id}`) return ok(host)
    if (path === `/api/hosts/${host.agent_id}/runtime`) return runtimeFailure ? route.fulfill({ status: 503, json: { code: 50300, msg: '性能读取暂不可用' } }) : ok(runtime)
    if (new RegExp(`^/api/hosts/${host.agent_id}/(software|ports|processes|accounts|containers)$`).test(path)) return ok(capture?.assets?.[path.split('/').at(-1)] || [])
    if (['/api/upgrade/packages', '/api/upgrade/versions', '/api/notify/channels'].includes(path)) return ok([])
    if (path === '/api/audit/logs') return ok({ list: [], total: 0 })
    if (path === '/api/system/health') return healthFailure ? route.fulfill({ status: 503, json: { code: 50300, msg: '健康检测暂不可用' } }) : ok(health)
    unexpected.push(path); return route.fulfill({ status: 500, json: { code: 50000, msg: 'Unexpected request' } })
  })
  const page = await context.newPage(); page.on('pageerror', error => errors.push(error.message))
  const drawer = page.locator('.el-drawer')
  const shot = async name => { await page.screenshot({ path: resolve(output, name), animations: 'disabled' }); screenshots.push(name) }
  await page.goto(base + '/hosts'); await page.getByRole('button', { name: '详情', exact: true }).click()
  await expect(drawer).toContainText(measured.latest.host.cpu_model)
  await expect(drawer).toContainText(host.kernel)
  await expect(drawer).toContainText('开机时间')
  await expect(drawer).toContainText('磁盘与文件系统')
  await expect(drawer.locator('.host-stat').first()).toContainText(Number(measured.latest.cpu_percent).toFixed(1) + '%')
  await expect(drawer.locator('canvas')).toHaveCount(1)
  assert.ok((await drawer.boundingBox()).width >= 1000, 'Desktop detail is still too narrow')
  await shot('host-detail-desktop.png'); checks.push('hardware_boot_disks_and_actual_measured_cpu_visible_in_wide_detail')
  for (const tab of ['软件清单', '容器与工作负载', '进程', '监听端口', '风险账户', '主机概览']) await drawer.getByRole('tab', { name: tab, exact: true }).click()
  checks.push('all_existing_asset_tabs_remain_accessible')
  await page.setViewportSize({ width: 390, height: 844 })
  await expect.poll(async () => (await drawer.boundingBox()).width).toBeLessThanOrEqual(390)
  assert.ok(await drawer.evaluate(el => el.scrollWidth <= el.clientWidth + 1), 'Mobile drawer overflows')
  await shot('host-detail-mobile.png'); checks.push('mobile_drawer_fits_viewport')
  runtime = { ...structuredClone(measured), latest: {}, samples: [], serverTime: Date.now() }
  await drawer.getByRole('button', { name: '刷新详情', exact: true }).click()
  await expect(drawer.locator('.host-stat').first()).toContainText('—')
  await expect(drawer).toContainText('暂无有效性能采样')
  await shot('host-detail-missing-mobile.png'); checks.push('missing_cpu_is_unknown_and_not_fabricated_idle')
  runtime = structuredClone(measured)
  await drawer.getByRole('button', { name: '刷新详情', exact: true }).click()
  await expect(drawer.locator('.host-stat').first()).toContainText(Number(measured.latest.cpu_percent).toFixed(1) + '%')
  runtimeFailure = true
  await drawer.getByRole('button', { name: '刷新详情', exact: true }).click()
  await expect(drawer).toContainText('性能读取暂不可用')
  await expect(drawer).toContainText('性能采样暂缺或已过期')
  await expect(drawer.locator('.host-stat').first()).toContainText(Number(measured.latest.cpu_percent).toFixed(1) + '%')
  checks.push('runtime_read_failure_is_visible')
  await page.goto(base + '/system'); await page.getByRole('tab', { name: '组件健康', exact: true }).click()
  const panel = page.locator('.component-health')
  await expect(panel.locator('[data-component]')).toHaveCount(9)
  await expect(panel.locator('[data-component="metrics"]')).toContainText('VictoriaMetrics')
  await expect(panel.locator('[data-component="redis"]')).toContainText('未启用')
  await shot('component-health-mobile.png'); checks.push('all_components_and_disabled_dependencies_visible')
  await page.setViewportSize({ width: 1440, height: 1000 }); await shot('component-health-desktop.png')
  healthFailure = true
  await panel.getByRole('button', { name: '刷新状态', exact: true }).click()
  await expect(panel).toContainText('健康检测暂不可用'); await expect(panel).toContainText('检测结果已过期')
  await shot('component-health-error.png'); checks.push('failed_health_refresh_marks_cached_results_stale')
  for (const role of ['operator', 'viewer']) {
    await page.evaluate(role => sessionStorage.setItem('role', role), role); await page.goto(base + '/system')
    await expect(page.getByRole('tab', { name: '组件健康', exact: true })).toHaveCount(0)
  }
  checks.push('health_management_is_hidden_from_non_admin_roles')
  assert.deepEqual(unexpected, []); assert.deepEqual(errors, [])
  writeFileSync(resolve(output, 'result.json'), JSON.stringify({ passed: true, input: capture ? 'actual_private_preview_readonly_rest_capture' : 'explicit_boundary_fixture', checks, screenshots, errors, unexpected }, null, 2) + '\n')
} finally { if (browser) await browser.close(); await new Promise(done => server.close(done)) }
