import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { createReadStream, existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs'
import { dirname, extname, resolve, sep } from 'node:path'
import { fileURLToPath } from 'node:url'
import { chromium, expect as baseExpect } from '@playwright/test'

const expect = baseExpect.configure({ timeout: 12000 })
const web = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const dist = resolve(process.env.ALINKSEC_SCREEN_DIST || resolve(web, 'dist'))
const output = resolve(process.env.ALINKSEC_SCREEN_OUTPUT || resolve(web, '../.tmp/screen-browser'))
const capture = process.env.ALINKSEC_SCREEN_CAPTURE ? JSON.parse(readFileSync(process.env.ALINKSEC_SCREEN_CAPTURE)) : null
async function runScenario(capture, output, context) {
const alerts = Array.from({ length: 20 }, (_, index) => ({ id: 100 - index, severity: index % 5,
  severity_source: 'agent_proto_v1', event_type: index === 4 ? 'sql_injection' : index === 7 ? 'web_attack' : ['file_tamper', 'login_crack', 'virus'][index % 3],
  title: index === 0 ? '<img src=x onerror=alert(1)>安全事件' : `受控动画验收事件 ${index + 1}`,
  detail: { source_ip: [1,4,7].includes(index) ? '118.28.8.8' : '10.0.0.5', trigger: index === 1 ? 'ssh_bruteforce' : '' }, host_ip: '10.20.30.40',
  count: 1, hostname: 'acceptance-host', agent_id: 'screen-fixture', action_taken: index % 2 ? 'alert_only' : 'blocked',
  last_time: '2026-10-26T12:30:00Z' }))
const responses = capture || {
  '/api/dashboard/summary': { hosts: { online: 8, total: 10, protectOn: 6 }, alerts: { open: 12, bySeverity: [{ severity: 4, count: 4 }, { severity: 3, count: 8 }] }, virus: { findings30d: 9 }, baseline: { avgScore: 87, hostsChecked: 8 } },
  '/api/dashboard/screen-trend': [{ date: '10-26', virus: 4, blocked: 9 }],
  '/api/dashboard/event-distribution': [], '/api/dashboard/baseline-categories': [{ category: '身份鉴别', pass_rate: 87 }],
  '/api/dashboard/top-hosts': [{ hostname: 'acceptance-host', agent_id: 'screen-fixture', alert_count: 12 }],
  '/api/alerts': { list: alerts, total: alerts.length }, '/api/protect/engines': [{ key: 'file', name: '文件防护', desc: '按实际规则检测文件变更', builtin: true }],
  '/api/protect/status': [{ agent_id: 'screen-fixture', protect_enabled: true }],
  '/api/dashboard/screen-situation': { providerStatus: 'configured', events: alerts.map((alert, index) => ({ id: alert.id,
    source: { ip: ['login_crack','sql_injection','web_attack'].includes(alert.event_type) ? alert.detail.source_ip : '', location: [1,4,7].includes(index)
      ? { status: 'located', provider: 'ipip', latitude: 39.125032, longitude: 117.295532, label: '文档坐标测试数据' }
      : { status: 'non_public_ip' } },
    target: { agentId: alert.agent_id, ip: alert.host_ip, location: [1,4,7].includes(index)
      ? { status: 'located', provider: 'asset_inventory', latitude: 31.23, longitude: 121.47, label: '明确标注的测试资产' }
      : { status: 'non_public_ip' } },
  })) },
}
mkdirSync(output, { recursive: true })
const server = createServer((req, res) => {
  let path
  try { path = resolve(dist, '.' + decodeURIComponent(new URL(req.url, 'http://localhost').pathname)) }
  catch { res.writeHead(400); res.end(); return }
  if (!path.startsWith(dist + sep)) { res.writeHead(403); res.end(); return }
  if (!existsSync(path) || !statSync(path).isFile()) path = resolve(dist, 'index.html')
  res.setHeader('Content-Type', { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json' }[extname(path)] || 'application/octet-stream')
  createReadStream(path).on('error', () => res.destroy()).pipe(res)
})
await new Promise(done => server.listen(0, '127.0.0.1', done))
const origin = (process.env.ALINKSEC_SCREEN_BASE || `http://127.0.0.1:${server.address().port}`).replace(/\/$/, '')
const checks = [], errors = [], unexpected = []
let page, empty = false, failed = false, geoFailed = false, noBaseline = false
try {
  await context.route('**/api/**', route => {
    const request = route.request(), path = new URL(request.url()).pathname
    if (!path.startsWith('/api/')) return route.continue()
    assert.equal(request.method(), 'GET', 'Dashboard browser checks must not write to a real host')
    if (path === '/api/dashboard/alert-trend') return route.fulfill({ json: { code: 0, data: [] } })
    if (path === '/api/metrics/query_range') return route.fulfill({ json: { code: 0, data: { result: [] } } })
    if (geoFailed && path === '/api/dashboard/screen-situation') return route.fulfill({ status: 503, json: { code: 50300 } })
    if (!(path in responses)) { unexpected.push(path); return route.fulfill({ status: 500, json: { code: 50000 } }) }
    if (failed) return route.fulfill({ status: 503, json: { code: 50300, msg: '暂不可用' } })
    if (noBaseline && path === '/api/dashboard/summary') return route.fulfill({ json: { code: 0, data: { ...responses[path], baseline: {} } } })
    if (noBaseline && path === '/api/dashboard/baseline-categories') return route.fulfill({ json: { code: 0, data: [] } })
    const data = empty && path === '/api/alerts' ? { list: [], total: 0 } : empty && path === '/api/dashboard/screen-situation' ? { providerStatus: 'configured', events: [] } : responses[path]
    return route.fulfill({ json: { code: 0, data } })
  })
  page = await context.newPage()
  await page.setViewportSize({ width: 1920, height: 1080 })
  page.on('pageerror', error => errors.push(error.message))
  page.on('request', request => { if (!request.url().startsWith(origin) && !request.url().startsWith('data:')) unexpected.push(request.url()) })
  await page.goto(origin + '/screen')
  const globe = page.locator('.security-globe canvas'), ticker = page.locator('.ticker-viewport'), track = page.locator('.ticker-track')
  const count = responses['/api/alerts'].list.length
  const routeCount = capture ? 0 : 3
  await expect(globe).toHaveAttribute('aria-label', new RegExp(`${routeCount} 条可定位网络链路`))
  await expect(page.getByRole('complementary', { name: '真实事件归属与证据' })).toBeVisible()
  await expect(page.locator('.engines')).not.toContainText('运行中')
  await expect(page.locator('.engines .track')).toHaveCount(0)
  await expect(page.getByText('各主机实际状态请查看防护与覆盖页面', { exact: true })).toBeVisible()
  await expect(page.locator('.kpis')).not.toContainText('自动处置')
  await expect(page.getByRole('heading', { name: /告警级别分布/ })).toContainText('全部待处置告警')
  checks.push('capabilities_and_response_records_do_not_claim_engine_runtime_or_automatic_blocking')
  if (capture) {
    await expect(page.getByText('暂无带来源 IP 的网络告警', { exact: true })).toBeVisible()
    if (responses['/api/dashboard/screen-situation'].providerInfo?.providers?.some(p => p.id === 'offline' && p.status === 'configured')) {
      await expect(page.locator('.situation-footer')).toContainText('离线城市库')
      await expect(page.locator('.situation-footer a')).toHaveAttribute('href', 'https://db-ip.com')
      checks.push('actual_offline_database_version_and_manufacturer_attribution_are_visible')
    }
  }
  else {
    await page.locator('.event-relation').nth(1).click()
    await expect(page.locator('.evidence-detail')).toContainText('118.28.8.8')
    await expect(page.locator('.evidence-detail')).toContainText('IPIP 城市近似')
    await expect(page.locator('.evidence-detail')).toContainText('资产登记')
    await expect(page.locator('.event-relations')).toContainText('SSH 暴力破解')
    await expect(page.locator('.event-relations')).toContainText('SQL 注入')
    await expect(page.locator('.event-relations')).toContainText('Web 攻击')
    await expect.poll(() => page.evaluate(() => window.__globeFrames.at(-1)?.markers.length || 0)).toBeGreaterThanOrEqual(2)
    const markers = await page.evaluate(() => window.__globeFrames.at(-1).markers)
    await expect.poll(() => page.evaluate(() => window.__globeFrames.at(-1)?.markers)).not.toEqual(markers)
    assert.equal(await page.evaluate(() => window.__globeFrames.every(frame => frame.pulses === 0)), true)
    checks.push('evidence_links_observed_ip_to_real_asset_and_geographic_endpoints_rotate_with_earth_without_historical_attack_replay')
    alerts[1].count++
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
    await expect.poll(() => page.evaluate(() => window.__globeFrames.at(-1)?.pulses || 0)).toBeGreaterThan(0)
    await expect.poll(() => page.evaluate(() => window.__globeFrames.every(frame => frame.pulses === 0)), { timeout: 6000 }).toBe(true)
    checks.push('new_observed_event_update_emits_one_directional_pulse_then_stops')
    const metadata = responses['/api/dashboard/screen-situation'].events[4]
    const location = metadata.source.location
    metadata.source.location = { status: 'pending' }; alerts[4].count++
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
    await expect(globe).toHaveAttribute('aria-label', /2 条可定位网络链路/)
    metadata.source.location = location
    await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
    await expect.poll(() => page.evaluate(() => window.__globeFrames.at(-1)?.pulses || 0)).toBeGreaterThan(0)
    await expect.poll(() => page.evaluate(() => window.__globeFrames.every(frame => frame.pulses === 0)), { timeout: 6000 }).toBe(true)
    checks.push('new_attack_waits_briefly_for_geolocation_then_pulses_once_without_replaying_history')
  }
  const frame = await globe.evaluate(canvas => canvas.toDataURL())
  await expect.poll(() => globe.evaluate(canvas => canvas.toDataURL())).not.toBe(frame)
  assert.ok(await globe.evaluate(canvas => canvas.width <= canvas.clientWidth * 1.5 + 1))
  checks.push('globe_rotates_with_bounded_resolution_and_only_located_network_events_generate_paths')
  if (capture && count > 1) {
    await expect(track).toHaveClass(/scrolling/)
    const initial = await track.evaluate(el => getComputedStyle(el).transform)
    await expect.poll(() => track.evaluate(el => getComputedStyle(el).transform)).not.toBe(initial)
    checks.push('actual_preview_events_scroll_even_when_fewer_rows_than_viewport')
  }
  if (!capture) {
    await expect(track.locator('tbody').first().locator('tr')).toHaveCount(20)
    await expect(track).toContainText('<img src=x onerror=alert(1)>安全事件')
    await expect(track.locator('img')).toHaveCount(0)
    await expect(track).toHaveClass(/scrolling/)
    const transform = () => track.evaluate(el => getComputedStyle(el).transform)
    const first = await transform()
    await expect.poll(transform).not.toBe(first)
    const header = await page.locator('.table-head').boundingBox()
    await page.waitForTimeout(200)
    assert.deepEqual(await page.locator('.table-head').boundingBox(), header)
    checks.push('overflow_events_scroll_continuously_below_fixed_header_and_escape_untrusted_text')
    await ticker.hover(); await page.waitForTimeout(100)
    const hovered = await transform(); await page.waitForTimeout(250); assert.equal(await transform(), hovered)
    await page.mouse.move(0, 0)
    await expect.poll(transform).not.toBe(hovered)
    await page.getByRole('button', { name: '暂停滚动', exact: true }).click(); await page.mouse.move(0, 0)
    const paused = await transform(); await page.waitForTimeout(250); assert.equal(await transform(), paused)
    await page.getByRole('button', { name: '继续滚动', exact: true }).click(); await page.mouse.move(0, 0)
    await ticker.focus(); await page.waitForTimeout(100)
    const focused = await transform(); await page.waitForTimeout(250); assert.equal(await transform(), focused)
    await ticker.evaluate(el => el.blur()); await page.mouse.move(0, 0)
    checks.push('hover_button_and_keyboard_focus_pause_then_resume_event_scroll')
    await track.evaluate(el => { const a = el.getAnimations()[0]; a.currentTime = a.effect.getTiming().duration * .92 })
    const viewBox = await ticker.boundingBox(), last = await track.locator('tbody').first().locator('tr').last().boundingBox()
    assert.ok(last.y < viewBox.y + viewBox.height && last.y + last.height > viewBox.y, 'Last event cannot be reached by scrolling')
    await track.evaluate(el => { const a = el.getAnimations()[0]; a.currentTime = a.effect.getTiming().duration - 30 })
    await page.waitForTimeout(100)
    const top = await track.locator('tbody').first().locator('tr').first().boundingBox()
    assert.ok(top.y > viewBox.y - 15 && top.y <= viewBox.y + 1, 'Ticker did not loop back without an empty gap')
    checks.push('last_event_is_visible_and_loop_returns_to_first_event_without_empty_gap')
  }
  await page.screenshot({ path: resolve(output, 'screen-desktop.png') })
  await page.setViewportSize({ width: 1366, height: 768 })
  await expect.poll(() => page.locator('#stage').evaluate(el => el.getBoundingClientRect().right)).toBeLessThanOrEqual(1367)
  await page.screenshot({ path: resolve(output, 'screen-laptop.png') })
  checks.push('dashboard_and_globe_fit_laptop_viewport')
  await page.emulateMedia({ reducedMotion: 'reduce' }); await page.waitForTimeout(150)
  const still = await globe.evaluate(canvas => canvas.toDataURL()); await page.waitForTimeout(300)
  assert.equal(await globe.evaluate(canvas => canvas.toDataURL()), still)
  if (!capture) {
    assert.equal(await track.evaluate(el => getComputedStyle(el).animationName), 'none')
    assert.equal(await ticker.evaluate(el => getComputedStyle(el).overflowY), 'auto')
  }
  checks.push('reduced_motion_freezes_globe_and_preserves_manual_event_scrolling')
  noBaseline = true; await page.reload()
  await expect(page.locator('.clock')).toContainText('数据已同步')
  await expect(page.getByRole('img', { name: '暂无基线评分', exact: true })).toBeVisible()
  await expect(page.getByRole('img', { name: '暂无已完成任务的分类结果', exact: true })).toBeVisible()
  checks.push('missing_baseline_results_stay_unknown_without_zero_scores_or_invented_categories')
  noBaseline = false
  empty = true; await page.reload()
  await expect(page.locator('.clock')).toContainText('数据已同步')
  await expect(page.getByText('暂无安全事件，正在持续监测', { exact: true })).toBeVisible()
  await expect(globe).toHaveAttribute('aria-label', /0 条可定位网络链路/)
  await expect(page.locator('.ticker-copy')).toHaveCount(0)
  await expect(page.getByRole('button', { name: '暂停滚动', exact: true })).toHaveCount(0)
  await page.screenshot({ path: resolve(output, 'screen-empty.png') })
  checks.push('empty_data_has_no_fabricated_attacks_or_duplicate_events')
  empty = false
  geoFailed = true; await page.reload()
  await expect(page.locator('.clock')).toContainText('数据已同步')
  await expect(page.locator('.situation-footer')).toContainText('IP 定位数据暂不可用')
  await expect(globe).toHaveAttribute('aria-label', /0 条可定位网络链路/)
  await expect(track.locator('tbody').first().locator('tr')).toHaveCount(count)
  checks.push('geolocation_failure_retains_real_alerts_without_fabricating_paths')
  geoFailed = false; await page.emulateMedia({ reducedMotion: 'no-preference' }); await page.reload()
  await expect(page.locator('.clock')).toContainText('数据已同步')
  await expect(globe).toHaveAttribute('aria-label', new RegExp(`${routeCount} 条可定位网络链路`))
  failed = true
  await page.evaluate(() => document.dispatchEvent(new Event('visibilitychange')))
  await expect(page.locator('.clock')).toContainText('数据更新暂不可用')
  await expect(globe).toHaveAttribute('aria-label', new RegExp(`${routeCount} 条可定位网络链路`))
  checks.push('failed_refresh_preserves_last_events_and_marks_data_unavailable')
  failed = false
  await page.getByRole('button', { name: '返回控制台', exact: true }).click()
  await expect(page.locator('.security-globe')).toHaveCount(0)
  await page.waitForLoadState('networkidle')
  checks.push('leaving_dashboard_removes_globe_and_ticker')
  assert.deepEqual(errors, []); assert.deepEqual(unexpected, [])
  writeFileSync(resolve(output, 'result.json'), JSON.stringify({ passed: true, input: capture ? 'actual_private_preview_rest_capture' : 'explicit_visual_boundary_fixture', checks, errors, unexpected }, null, 2) + '\n')
  console.log(JSON.stringify({ passed: true, checks: checks.length }))
} catch (error) {
  writeFileSync(resolve(output, 'failure.json'), JSON.stringify({ checks, errors, unexpected, message: error.message, body: page ? await page.locator('body').innerText().catch(() => '') : '' }, null, 2)+'\n')
  if (page) await page.screenshot({ path: resolve(output, 'failure.png') }).catch(() => {})
  throw error
} finally { if (page) await page.close(); await new Promise(done => server.close(done)) }
}

const browser = await chromium.launch({ headless: true, args: ['--no-sandbox', '--disable-dev-shm-usage', '--single-process', '--no-zygote', '--disable-gpu', '--js-flags=--max-old-space-size=128'] })
try {
  const context = await browser.newContext({ viewport: { width: 1920, height: 1080 } })
  await context.addInitScript(() => {
    const proto = CanvasRenderingContext2D.prototype, clear = proto.clearRect, arc = proto.arc
    window.__globeFrames = []
    proto.clearRect = function(...args) {
      if (this.canvas.closest('.globe-visual')) {
        if (this.__frame) { window.__globeFrames.push(this.__frame); if (window.__globeFrames.length > 6) window.__globeFrames.shift() }
        this.__frame = { markers: [], pulses: 0 }
      }
      return clear.apply(this, args)
    }
    proto.arc = function(x, y, radius, ...args) {
      if (this.__frame) {
        if (radius === 2.7 || radius === 3.8) this.__frame.markers.push([x, y])
        if (radius === 1.5) this.__frame.pulses++
      }
      return arc.call(this, x, y, radius, ...args)
    }
    localStorage.setItem('alinksec_token', 'screen-visual-acceptance')
    localStorage.setItem('alinksec_user', JSON.stringify({ username: 'capture', role: 'admin' }))
  })
  await runScenario(capture, output, context)
} finally { await browser.close() }
