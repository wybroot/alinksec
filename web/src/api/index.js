/* =====================================================================
 * 数据接口层（M2 · 真实 REST）
 * ---------------------------------------------------------------------
 * 所有数据来自服务端 8080 /api/**（JWT 鉴权），页面零 mock。
 * 登录态：localStorage 持久化 token，401 自动跳转登录页。
 * 适配层把服务端字段映射为页面组件所需结构（页面无需感知后端模型）。
 * ===================================================================== */

import { readRuleEvidence } from '../utils/vulnerabilityEvidence.js'
import { eventEvidence } from '../utils/securitySituation.js'

const TOKEN_KEY = 'alinksec_token'
const USER_KEY = 'alinksec_user'

export function getToken() { return localStorage.getItem(TOKEN_KEY) || '' }
export function getUser() {
  try { return JSON.parse(localStorage.getItem(USER_KEY) || 'null') } catch { return null }
}
export function setSession(token, user) {
  localStorage.setItem(TOKEN_KEY, token)
  localStorage.setItem(USER_KEY, JSON.stringify(user))
}
export function clearSession() {
  localStorage.removeItem(TOKEN_KEY)
  localStorage.removeItem(USER_KEY)
}

async function request(path, options = {}) {
  const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) }
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(path, { ...options, headers })
  if (res.status === 401) {
    clearSession()
    location.href = '/login'
    throw new Error('登录已过期')
  }
  const body = await res.json().catch(() => ({}))
  if (!res.ok || body.code !== 0) {
    throw new Error(body.msg || `请求失败(${res.status})`)
  }
  return body.data
}

const get = (path) => request(path)
const post = (path, data) => request(path, { method: 'POST', body: JSON.stringify(data) })

export const fetchRawLogs = query => get(`/api/logs?${new URLSearchParams(query)}`)
export const fetchRawLog = id => get(`/api/logs/${encodeURIComponent(id)}`)
export async function downloadRawLogs(ids, format) {
  const response = await fetch('/api/logs/export', { method: 'POST', headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${getToken()}` }, body: JSON.stringify({ ids, format }) })
  if (response.status === 401) { clearSession(); location.href = '/login'; throw new Error('登录已过期') }
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).msg || '日志导出失败')
  const reader = response.body.getReader(), chunks = []; let size = 0
  try { for (;;) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > 8388608) { await reader.cancel(); throw new Error('日志导出超过 8 MiB') }; chunks.push(value) } } finally { reader.releaseLock() }
  const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length }
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), n => n.toString(16).padStart(2, '0')).join('')
  if (digest !== response.headers.get('X-Content-SHA256')) throw new Error('日志导出摘要不匹配')
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }))
  const link = document.createElement('a'); link.href = url; link.download = `alinksec-logs.${format === 'csv' ? 'csv' : 'ndjson'}`; link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const fetchClusterStatus = () => get('/api/cluster')
export const retryClusterReport = (id, body) => post(`/api/cluster/reports/${encodeURIComponent(id)}/retry`, body)

export const fetchEvidence = () => get('/api/evidence')
export const fetchEvidenceTargets = () => get('/api/evidence/targets')
export const fetchEvidenceSamples = agent => get(`/api/evidence/targets/${encodeURIComponent(agent)}/samples`)
export const collectEvidence = data => post('/api/evidence', data)
export const removeEvidence = id => request(`/api/evidence/${encodeURIComponent(id)}`, { method: 'DELETE' })
export async function downloadEvidence(row) {
  if (!/^[0-9a-f-]{36}$/.test(row.id) || !/^[0-9a-f]{64}$/.test(row.content_sha256)) throw new Error('取证文件标识无效')
  const response = await fetch(`/api/evidence/${row.id}/download`, { headers: { Authorization: `Bearer ${getToken()}` } })
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).msg || '文件下载失败')
  const bytes = await response.arrayBuffer()
  if (bytes.byteLength > 1048576 || bytes.byteLength !== Number(row.size_bytes)) throw new Error('文件大小不匹配')
  const hash = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), n => n.toString(16).padStart(2, '0')).join('')
  if (hash !== row.content_sha256 || hash !== response.headers.get('X-Content-SHA256')) throw new Error('文件完整性校验失败')
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }))
  const link = document.createElement('a'); link.href = url
  link.download = `alinksec-${row.id}-${row.kind === 'diagnostic' ? 'diagnostic.zip' : 'quarantine.sample.bin'}`
  link.click(); setTimeout(() => URL.revokeObjectURL(url), 1000)
}

export const fetchScapPackages = () => get('/api/baseline/scap/packages')
export const fetchScapPackage = id => get(`/api/baseline/scap/packages/${encodeURIComponent(id)}`)
export const importScapPackage = file => upload('/api/baseline/scap/packages/import', file)
export const decideScapPackage = (id, data) => post(`/api/baseline/scap/packages/${encodeURIComponent(id)}/decision`, data)
export const fetchScapTargets = () => get('/api/baseline/scap/targets')
export const fetchScapTasks = (page = 1) => get(`/api/baseline/scap/tasks?page=${page}&size=20`)
export const fetchScapTask = id => get(`/api/baseline/scap/tasks/${encodeURIComponent(id)}`)
export const createScapTask = data => post('/api/baseline/scap/tasks', data)
export async function downloadScap(path, filename) {
  if (!/^\/api\/baseline\/scap\/(packages|tasks)\/[A-Za-z0-9-]+\/(source|content|agents\/[A-Za-z0-9_.:-]+\/evidence)$/.test(path)) throw new Error('导出路径无效')
  const response = await fetch(path, { headers: { Authorization: `Bearer ${getToken()}` } })
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).msg || '导出失败')
  const bytes = await response.arrayBuffer()
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), n => n.toString(16).padStart(2, '0')).join('')
  if (digest !== response.headers.get('X-Content-SHA256')) throw new Error('导出内容摘要不匹配')
  const url = URL.createObjectURL(new Blob([bytes], { type: response.headers.get('Content-Type') }))
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click(); URL.revokeObjectURL(url)
}

export const fetchBaselineUpstreams = () => get('/api/baseline/upstreams')
export const fetchBaselineUpstream = id => get(`/api/baseline/upstreams/${encodeURIComponent(id)}`)
export const updateBaselineUpstream = (id, plan) => put(`/api/baseline/upstreams/${encodeURIComponent(id)}/schedule`, plan)
export const syncBaselineUpstream = id => post(`/api/baseline/upstreams/${encodeURIComponent(id)}/sync`, {})
export const retryBaselineUpstream = (id, release) => post(`/api/baseline/upstreams/${encodeURIComponent(id)}/releases/${encodeURIComponent(release)}/retry`, {})
export async function downloadBaselineUpstream(path, filename) {
  if (!/^\/api\/baseline\/upstreams\/[A-Za-z0-9_.-]+\/(receipts\/[A-Za-z0-9-]+|releases\/[A-Za-z0-9-]+\/artifact)$/.test(path)) throw new Error('导出路径无效')
  const response = await fetch(path, { headers: { Authorization: `Bearer ${getToken()}` } })
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).msg || '导出失败')
  const bytes = await response.arrayBuffer()
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), n => n.toString(16).padStart(2, '0')).join('')
  if (digest !== response.headers.get('X-Content-SHA256')) throw new Error('导出内容摘要不匹配')
  const url = URL.createObjectURL(new Blob([bytes], { type: response.headers.get('Content-Type') }))
  const link = document.createElement('a'); link.href = url; link.download = filename; link.click(); URL.revokeObjectURL(url)
}

export const fetchWindowsUpdateHosts = (page = 1) => get(`/api/fix/windows/hosts?page=${page}&size=20`)
export const fetchWindowsUpdateCandidates = agentId => get(`/api/fix/windows/candidates?agentId=${encodeURIComponent(agentId)}`)
export const scanWindowsUpdates = agentIds => post('/api/fix/windows/scans', { agentIds })
export const createWindowsUpdateTask = data => post('/api/fix/windows/tasks', data)
export const endWindowsUpdateReview = (id, reason) => post(`/api/fix/windows/tasks/${id}/end-review`, { reason, acknowledged: true })
const put = (path, data) => request(path, { method: 'PUT', body: JSON.stringify(data) })
const del = (path) => request(path, { method: 'DELETE' })

export const fetchLibraries = () => get('/api/libraries')
export const fetchLibraryCves = ({ keyword = '', page = 1, size = 20 } = {}) => get(`/api/libraries/cves?${new URLSearchParams({ keyword, page, size })}`)
export const fetchLibraryDeclarations = (cveId) => get(`/api/libraries/cves/${encodeURIComponent(cveId)}/declarations`)
export const decideLibraryCve = (sourceId, cveId, body) => post(`/api/libraries/sources/${encodeURIComponent(sourceId)}/cves/${encodeURIComponent(cveId)}/decision`, body)
export const retireLibrarySource = (id, note) => post(`/api/libraries/sources/${encodeURIComponent(id)}/retire`, { note })
export const fetchSourcePolicy = id => get(`/api/libraries/sources/${encodeURIComponent(id)}/policy`)
export const updateSourcePolicy = (id, body) => put(`/api/libraries/sources/${encodeURIComponent(id)}/policy`, body)
export const fetchSourceSelections = params => get(`/api/libraries/selections?${new URLSearchParams(params)}`)
export const fetchSourceSelection = (kind, key) => get(`/api/libraries/selection?${new URLSearchParams({ kind, key })}`)
export const fetchSelectionCandidate = (kind, key, source) => get(`/api/libraries/selection/candidate?${new URLSearchParams({ kind, key, source })}`)
export const fetchSelectionHistory = (kind, key, page = 1) => get(`/api/libraries/selection/history?${new URLSearchParams({ kind, key, page, size: 20 })}`)
export const decideSourceSelection = body => post('/api/libraries/selection/decision', body)
export const fetchLibraryGovernance = (id, page = 1) => get(`/api/libraries/sources/${encodeURIComponent(id)}/governance?${new URLSearchParams({ page, size: 20 })}`)
export const synchronizeLibrary = (id) => post(`/api/libraries/sources/${encodeURIComponent(id)}/sync`, {})
export const updateLibrarySchedule = (id, plan) => put(`/api/libraries/sources/${encodeURIComponent(id)}/schedule`, plan)
export const resetLibrarySchedule = (id) => del(`/api/libraries/sources/${encodeURIComponent(id)}/schedule`)
export const fetchVendorAdvisories = (id, page = 1) => get(`/api/libraries/sources/${encodeURIComponent(id)}/advisories?page=${page}&size=20`)
export const fetchOpenCtiIndicators = (id, page = 1) => get(`/api/libraries/sources/${encodeURIComponent(id)}/indicators?${new URLSearchParams({ page, size: 20 })}`)
export const fetchOpenCtiIndicator = (id, indicatorId) => get(`/api/libraries/sources/${encodeURIComponent(id)}/indicators/${encodeURIComponent(indicatorId)}`)
export const fetchVendorAdvisory = (id, documentId) => get(`/api/libraries/sources/${encodeURIComponent(id)}/advisories/${encodeURIComponent(documentId)}`)
export async function downloadVendorAdvisory(source, document) {
  if (!/^[A-Za-z0-9-]{1,64}$/.test(source) || !/^[a-f0-9-]{36}$/.test(document.id) || !/^[a-f0-9]{64}$/.test(document.sha256)) throw new Error('公告下载标识无效')
  const response = await fetch(`/api/libraries/sources/${source}/advisories/${document.id}/raw`, { headers: { Authorization: `Bearer ${getToken()}` } })
  if (response.status === 401) { clearSession(); location.href = '/login'; throw new Error('登录已过期') }
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).msg || '原件下载失败')
  const bytes = await response.arrayBuffer()
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), n => n.toString(16).padStart(2, '0')).join('')
  if (digest !== document.sha256 || digest !== response.headers.get('X-Content-SHA256')) throw new Error('公告原件摘要不匹配')
  const gzip = new Uint8Array(bytes)[0] === 0x1f && new Uint8Array(bytes)[1] === 0x8b
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }))
  const link = window.document.createElement('a'); link.href = url; link.download = `advisory-${document.id}.json${gzip ? '.gz' : ''}`; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
export const fetchLibraryRuns = (id) => get(`/api/libraries/sources/${encodeURIComponent(id)}/runs`)
export const importCveLibrary = (file) => upload('/api/libraries/cves/import', file)

/** multipart 上传（浏览器自动生成 boundary，勿手工设 Content-Type） */
async function upload(path, file, field = 'file') {
  const form = new FormData()
  form.append(field, file)
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(path, { method: 'POST', headers, body: form })
  if (res.status === 401) {
    clearSession()
    location.href = '/login'
    throw new Error('登录已过期')
  }
  const body = await res.json().catch(() => ({}))
  if (!res.ok || body.code !== 0) {
    throw new Error(body.msg || `请求失败(${res.status})`)
  }
  return body.data
}

/* ---------------- 登录 ---------------- */

export async function login(username, password) {
  const data = await post('/api/auth/login', { username, password })
  setSession(data.token, data.user)
  return data.user
}

export async function logout() {
  try { await post('/api/auth/logout', {}) } catch { /* 忽略 */ }
  clearSession()
}

/* ---------------- 适配工具 ---------------- */

const SEV = { 5: 'critical', 4: 'critical', 3: 'high', 2: 'medium', 1: 'low' }
const sev = (n) => SEV[Number(n)] || 'unknown'
const alertSev = a => a.severity_level == null ? sev(a.severity) : ({ '-1': 'unknown', 0: 'info', 1: 'low', 2: 'medium', 3: 'high', 4: 'critical' }[Number(a.severity_level)] || 'unknown')
const OS = { 1: (v) => v || 'Linux', 2: (v) => v || 'Windows' }

function fmtTime(iso) {
  if (!iso) return '—'
  const d = new Date(iso)
  const p = (x) => String(x).padStart(2, '0')
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

function fmtAgo(iso) {
  if (!iso) return '—'
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return `${Math.max(s, 0)}s 前`
  if (s < 3600) return `${Math.floor(s / 60)}m 前`
  if (s < 86400) return `${Math.floor(s / 3600)}h 前`
  return `${Math.floor(s / 86400)}d 前`
}

const HOST_STATUS = { 0: 'pending', 1: 'online', 2: 'offline', 3: 'offline' }
const ISOLATION_STATUS = {
  0: 'normal',
  1: 'isolating',
  2: 'isolated',
  3: 'restoring',
  4: 'isolate_failed',
  5: 'restore_failed',
  6: 'isolation_unknown',
}

/* ---------------- 总览 ---------------- */

export async function fetchDashboard() {
  const [summary, trend, events, topHosts] = await Promise.all([
    get('/api/dashboard/summary'),
    get('/api/dashboard/alert-trend?days=7'),
    get('/api/alerts?page=1&size=6'),
    get('/api/dashboard/top-hosts?limit=5'),
  ])
  const s = summary || {}
  const sevMap = {}
  for (const row of s.alerts?.bySeverity || []) sevMap[Number(row.severity)] = Number(row.count)
  const critical = (sevMap[4] ?? 0) + (sevMap[5] ?? 0)
  const top = (topHosts || [])[0]
  return {
    stats: {
      hosts: s.hosts?.online ?? 0,
      hostsTotal: s.hosts?.total ?? 0,
      weekNew: s.hosts?.weekNew ?? 0,
      pending: s.alerts?.open ?? 0,
      crit: critical,
      high: sevMap[3] ?? 0,
      virusWeek: s.virus?.findings30d ?? 0,
      quarantined: s.virus?.quarantined ?? 0,
      virusTodo: s.virus?.todo ?? 0,
      riskHosts: (topHosts || []).length,
      topRisk: top ? `${top.hostname}（${top.alert_count}）` : '—',
    },
    // The backend groups source-aware display levels; old APIs may also return5.
    sevDist: [
      { value: critical, name: '严重' },
      { value: sevMap[3] ?? 0, name: '高危' },
      { value: sevMap[2] ?? 0, name: '中危' },
      { value: sevMap[1] ?? 0, name: '低危' },
      { value: sevMap[0] ?? 0, name: '信息' },
      { value: sevMap[-1] ?? 0, name: '未知' },
    ].filter((x) => x.value > 0),
    trend: (trend || []).map((t) => ({
      date: t.date,
      count: Number(t.count || 0),
      handled: Number(t.handled || 0),
    })),
    events: (events?.list || []).map((a) => ({
      id: a.id,
      time: fmtTime(a.last_time),
      sev: alertSev(a),
      legacySeverity: a.severity_source === 'legacy_unclassified',
      text: a.title,
      host: a.hostname || a.agent_id,
      action: a.action_taken || 'alert_only',
    })),
  }
}

/* ---------------- 指标查询（VictoriaMetrics 透传） ---------------- */

/** VM 即时查询 */
export async function fetchMetricsQuery(query, time) {
  const qs = time ? `&time=${encodeURIComponent(time)}` : ''
  return get(`/api/metrics/query?query=${encodeURIComponent(query)}${qs}`)
}

/**
 * VM 区间查询（矩阵）：返回 [{metric, values:[[tsSec, "val"], ...]}]
 * query 例 avg(alinksec_cpu_usage)；step 例 1h
 */
export async function fetchMetricsRange(query, step = '1h', rangeHours = 24) {
  const end = Math.floor(Date.now() / 1000)
  const start = end - rangeHours * 3600
  return fetchMetricsQueryRange(query, String(start), String(end), step)
}

async function fetchMetricsQueryRange(query, start, end, step) {
  const data = await get(
    `/api/metrics/query_range?query=${encodeURIComponent(query)}&start=${start}&end=${end}&step=${encodeURIComponent(step)}`,
  )
  return data?.data?.result || data?.result || []
}

export async function fetchHostMetrics(agentId) {
  return get(`/api/hosts/${encodeURIComponent(agentId)}/runtime`)
}

export const fetchSystemHealth = () => get('/api/system/health')

/* ---------------- 安全大屏 ---------------- */

export async function fetchScreen() {
  const [summary, trend, sevDist, categories, topHosts, alerts, engines, status, situation] = await Promise.all([
    get('/api/dashboard/summary'),
    get('/api/dashboard/screen-trend?days=7'),
    get('/api/dashboard/event-distribution'),
    get('/api/dashboard/baseline-categories'),
    get('/api/dashboard/top-hosts?limit=5'),
    get('/api/alerts?page=1&size=20'),
    get('/api/protect/engines'),
    get('/api/protect/status'),
    get('/api/dashboard/screen-situation').catch(() => ({ providerStatus: 'unavailable', events: [] })),
  ])
  const s = summary || {}
  const sevMap = {}
  for (const row of s.alerts?.bySeverity || []) sevMap[Number(row.severity)] = Number(row.count)
  const critical = (sevMap[4] ?? 0) + (sevMap[5] ?? 0)

  // 趋势（date/virus/blocked）
  const trendData = (trend || []).map((d) => ({ date: d.date, virus: Number(d.virus), blocked: Number(d.blocked) }))

  // 告警等级分布（饼图）
  const sevPie = [
    { name: '严重', value: critical },
    { name: '高危', value: sevMap[3] ?? 0 },
    { name: '中危', value: sevMap[2] ?? 0 },
    { name: '低危', value: sevMap[1] ?? 0 },
    { name: '信息', value: sevMap[0] ?? 0 },
    { name: '未知', value: sevMap[-1] ?? 0 },
  ]

  // 基线维度雷达（pass_rate 0~100）
  const radar = (categories || []).map((c) => ({ category: c.category, rate: Number(c.pass_rate) }))

  // 风险主机 TOP（alert_count 归一化为 0~100 风险分）
  const maxAlert = Math.max(1, ...(topHosts || []).map((h) => Number(h.alert_count || 0)))
  const riskHosts = (topHosts || []).map((h) => ({
    hostname: h.hostname || h.agent_id,
    alerts: Number(h.alert_count || 0),
    risk: Math.round((Number(h.alert_count || 0) / maxAlert) * 100),
  }))

  // 实时事件流
  const locations = new Map((situation?.events || []).map(event => [event.id, event]))
  const events = (alerts?.list || []).map((a) => ({
    ...eventEvidence(a, locations.get(a.id)),
    id: a.id,
    sev: alertSev(a),
    legacySeverity: a.severity_source === 'legacy_unclassified',
    type: a.event_type,
    text: alertText(a),
    host: a.hostname || a.agent_id || '—',
    action: a.action_taken || '',
    time: fmtTime(a.last_time),
  }))

  const protectOn = (status || []).filter((a) => a.protect_enabled).length
  const total = Number(s.hosts?.total ?? 0)
  return {
    kpi: {
      hosts: Number(s.hosts?.online ?? 0),
      total,
      coverage: total ? Math.round((Number(s.hosts?.online ?? 0) / total) * 100) : 0,
      protectOn,
      pending: Number(s.alerts?.open ?? 0),
      crit: critical,
      high: sevMap[3] ?? 0,
      virus: Number(s.virus?.findings30d ?? 0),
      rtHit: (alerts?.list || []).filter((a) => a.action_taken).length,
      compliance: s.baseline?.avgScore != null ? Math.round(Number(s.baseline.avgScore)) : null,
      hostsChecked: Number(s.baseline?.hostsChecked ?? 0),
    },
    sevDist: (sevDist || []).map((d) => ({ type: d.type, count: Number(d.count) })),
    trend: trendData,
    sevPie,
    radar,
    riskHosts,
    events,
    providerStatus: situation?.providerStatus || 'unavailable',
    providerInfo: situation?.providerInfo || null,
    engines: (engines || []).map((e) => ({ key: e.key, name: e.name, desc: e.desc })),
  }
}

/* ---------------- 主机 ---------------- */

/** 布防一次性卸载口令（docs/01 §6.1 防恶意卸载；15min 有效，Agent 端 uninstall 子命令消费） */
export async function armUninstallToken(agentId) {
  return post(`/api/hosts/${agentId}/uninstall-token`, {})
}

/** 生成 Agent 安装注册码（默认 10 次/7 天） */
export async function createEnrollToken(maxUses = 10, validDays = 7) {
  return post(`/api/hosts/enroll-token?maxUses=${maxUses}&validDays=${validDays}`, {})
}

/** 立即采集（CmdCollectNow） */
export async function collectNow(agentId) {
  return post(`/api/hosts/${agentId}/collect`, {})
}

/** 隔离 / 解除隔离（CmdProtectAction.ISOLATE_HOST / RESTORE_ISOLATION） */
export async function isolateHost(agentId, isolated) {
  return post(`/api/hosts/${agentId}/${isolated ? 'isolate' : 'unisolate'}`, {})
}

export async function fetchHosts({ keyword = '', status = '', page = 1, size = 20 } = {}) {
  const params = new URLSearchParams({ page: String(page), size: String(size) })
  if (keyword.trim()) params.set('keyword', keyword.trim())
  const connectionFilter = { pending: 0, online: 1, offline: 2 }[status]
  const isolationFilter = {
    normal: 0, isolating: 1, isolated: 2, restoring: 3, isolate_failed: 4, restore_failed: 5, isolation_unknown: 6,
  }[status]
  if (connectionFilter !== undefined) params.set('status', String(connectionFilter))
  if (isolationFilter !== undefined) params.set('isolationStatus', String(isolationFilter))
  const data = await get(`/api/hosts?${params}`)
  const list = (data?.list || []).map((h) => {
    const state = hostConnectionAndIsolation(h)
    return {
      agentId: h.agent_id,
      virusExecutionContract: Number(h.virus_execution_contract || 0),
      host: h.hostname,
      ip: h.ip || '—',
      os: OS[h.os_type]?.(h.os_version) || h.os_version || '—',
      arch: h.arch || '—',
      group: '—',
      ver: h.agent_version || '—',
      ...state,
      protect: !!h.protect_enabled,
      hb: fmtAgo(h.last_heartbeat),
      risk: Number(h.alert_count || 0),
      alertCount: Number(h.alert_count || 0),
      lastEvt: h.last_event || '',
      softwareCount: h.software_count,
      portCount: h.port_count,
      processCount: Number(h.process_count || 0),
      accountCount: h.account_count,
      riskyAccountCount: Number(h.risky_account_count || 0),
      containerCount: Number(h.container_count || 0),
    }
  })
  return { list, total: Number(data?.total || 0), page, size }
}

function hostConnectionAndIsolation(h) {
  const connectionStatus = HOST_STATUS[h.status] || 'offline'
  const isolationStatus = ISOLATION_STATUS[Number(h.isolation_status)] || 'normal'
  return { connectionStatus, isolationStatus, isolationError: h.isolation_error || '',
    isolationContract: Number(h.isolation_contract || 0),
    isolationAutomatic: h.isolation_automatic === true || Number(h.isolation_automatic) === 1,
    status: isolationStatus === 'normal' ? connectionStatus : isolationStatus }
}
export async function fetchHostState(agentId) {
  return hostConnectionAndIsolation(await get(`/api/hosts/${agentId}`))
}

export async function fetchAllHosts() {
  const size = 100
  const first = await fetchHosts({ page: 1, size })
  const list = [...first.list]
  for (let page = 2; list.length < first.total; page += 1) {
    const next = await fetchHosts({ page, size })
    if (!next.list.length) break
    list.push(...next.list)
  }
  return list
}

function alertText(alert) {
  if (alert.event_type !== 'process') return alert.title
  const process = alert.detail?.process
  if (!process) return alert.title
  const exe = process.exe || process.cmdline || 'unknown'
  return `${alert.title} · ${exe}${process.pid ? ` (PID ${process.pid})` : ''}`
}

export async function fetchGroups() {
  const list = await get('/api/hosts/groups')
  return (list || []).map((g) => g.name)
}

export async function fetchHostDetail(agentId) {
  const [detail, software, ports, processes, accounts, containers] = await Promise.all([
    get(`/api/hosts/${agentId}`),
    get(`/api/hosts/${agentId}/software?page=1&size=500`),
    get(`/api/hosts/${agentId}/ports`),
    get(`/api/hosts/${agentId}/processes`),
    get(`/api/hosts/${agentId}/accounts`),
    get(`/api/hosts/${agentId}/containers`),
  ])
  return { detail, software, ports, processes, accounts, containers }
}

/* ---------------- 基线 ---------------- */

export async function fetchBaseline() {
  const data = await get('/api/baseline/latest')
  return (data?.list || []).map((r) => ({
    taskId: data.taskId,
    agentId: r.agent_id,
    host: r.hostname,
    tpl: r.tpl || '等保 2.0 基线',
    rate: Math.round(Number(r.score) || 0),
    errors: Number(r.error_count || 0),
    legacy: Number(r.legacy_count || 0),
    c: Number(r.c || 0),
    h: Number(r.h || 0),
    m: Number(r.m || 0),
    l: Number(r.l || 0),
    time: fmtTime(r.checked_at),
  }))
}

export const fetchBaselinePackages = () => get('/api/baseline/packages')
export const fetchBaselinePackage = (id) => get(`/api/baseline/packages/${encodeURIComponent(id)}`)
export const importBaselinePackage = (file) => upload('/api/baseline/packages/import', file)
export const reviewBaselinePackage = (id, approved, note) => post(`/api/baseline/packages/${encodeURIComponent(id)}/review`, { approved, note })
export const testBaselinePackage = (id, agentIds) => post(`/api/baseline/packages/${encodeURIComponent(id)}/test`, { agentIds })
export const publishBaselinePackage = (id, note) => post(`/api/baseline/packages/${encodeURIComponent(id)}/publish`, { note })
export const withdrawBaselinePackage = (id, note) => post(`/api/baseline/packages/${encodeURIComponent(id)}/withdraw`, { note })
export const fetchBaselineCompliance = (taskId, agentId) => get(`/api/baseline/tasks/${encodeURIComponent(taskId)}/agents/${encodeURIComponent(agentId)}/compliance`)
export const reviewBaselineCompliance = (taskId, agentId, decision) => post(`/api/baseline/tasks/${encodeURIComponent(taskId)}/agents/${encodeURIComponent(agentId)}/compliance/review`, decision)
export const fetchBaselineCoverage = (agentIds, templateIds = []) => post('/api/baseline/coverage', { agentIds, templateIds })

export async function fetchBaselineTemplates() {
  return get('/api/baseline/templates')
}

/** 核查明细：passed 传 false 只拉失败项（一键修复入口） */
export async function fetchBaselineTaskDetail(taskId, agentId, passed) {
  const qs = passed === undefined || passed === null ? '' : `?passed=${passed}`
  return get(`/api/baseline/tasks/${taskId}/agents/${agentId}/items${qs}`)
}

export async function createBaselineTask(agentIds, templateIds, name) {
  return post('/api/baseline/tasks', { agentIds, templateIds, name })
}

export async function fetchBaselineCategoryStats(taskId) {
  return get(`/api/baseline/tasks/${taskId}/category-stats`)
}

/* ---------------- 配置修复 ---------------- */

/** 创建修复任务：items = [{agentId, itemId}]（基线失败项，fixable=true 才允许） */
export async function createFixTask(items, name) {
  return post('/api/fix/tasks', { items, name })
}

export async function fetchFixTasks() {
  return get('/api/fix/tasks?page=1&size=50')
}

export async function fetchFixTaskRecords(taskId) {
  return get(`/api/fix/tasks/${taskId}/records`)
}

/** 创建软件包类修复任务（提交审批）：items = [{agentId, findingId}] */
export async function createPackageFixTask(items, opts) {
  return post('/api/fix/tasks/package', {
    items,
    name: opts?.name,
    approver: opts?.approver,
    windowStart: opts?.windowStart,
    windowEnd: opts?.windowEnd,
  })
}

/** 审批软件包类修复任务 */
export async function approveFixTask(taskId) {
  return post(`/api/fix/tasks/${taskId}/approve`, {})
}
export const fetchFixApprovers = () => get('/api/fix/approvers')
export const cancelFixTask = (taskId, reason) => post(`/api/fix/tasks/${taskId}/cancel`, { reason })

/* ---------------- 补丁仓库 ---------------- */

export async function fetchPatches(params = {}) {
  const q = new URLSearchParams({ page: params.page || 1, size: params.size || 50 })
  if (params.osType) q.set('osType', params.osType)
  if (params.keyword) q.set('keyword', params.keyword)
  return get(`/api/fix/patches?${q}`)
}

/** 导入补丁包：file + 元数据（osType/osVersion/pkgName/targetVersion/repoType） */
export async function importPatch(formData) {
  const token = getToken()
  return fetch('/api/fix/patches', {
    method: 'POST',
    body: formData,
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  }).then(async r => {
    const j = await r.json().catch(() => ({}))
    if (!r.ok || j.code !== 0) throw new Error(j.message || `导入失败（${r.status}）`)
    return j.data
  })
}

/* ---------------- 漏洞 ---------------- */

export async function fetchVulns() {
  const size = 200
  const first = await get(`/api/vuln/findings?page=1&size=${size}`)
  const list = [...(first?.list || [])]
  for (let page = 2; list.length < Number(first?.total || 0); page += 1) {
    const next = await get(`/api/vuln/findings?page=${page}&size=${size}`)
    if (!next?.list?.length) break
    list.push(...next.list)
  }
  const grouped = new Map()
  const agentsByGroup = new Map()
  const seen = new Set()
  for (const f of list) {
    const id = `${f.agent_id}\0${f.id}`
    if (seen.has(id)) continue
    seen.add(id)
    const key = JSON.stringify([f.cve_id, f.software, f.installed_version || '', f.fixed_version || '',
      f.source || '', f.architecture || '', f.distro_id || '', f.distro_version || '', f.os_type || 0,
      f.os_version || '', f.identity_status || 'legacy', f.rule_source_id || '', f.rule_digest || '', f.evidence_status || 'legacy'])
    if (!grouped.has(key)) {
      grouped.set(key, {
        cve: f.cve_id,
        desc: f.title || f.cve_id,
        pkg: f.software,
        cur: f.installed_version || '—',
        target: f.fixed_version || '—',
        sev: sev(f.severity),
        cvss: f.cvss ?? '-',
        fixType: 'pkg',
        source: f.source || '',
        architecture: f.architecture || '',
        distroId: f.distro_id || '',
        distroVersion: f.distro_version || '',
        osVersion: f.os_version || '',
        identityStatus: f.identity_status || 'legacy',
        ruleSourceId: f.rule_source_id || '',
        ruleDigest: f.rule_digest || '',
        evidenceStatus: f.evidence_status || 'legacy',
        ruleEvidence: readRuleEvidence(f.rule_evidence),
        blocked: 0,
        executionUnsupported: 0,
        repairUnreviewed: 0,
        hosts: 0,
        hostList: [],
        findings: [],
        status: f.status >= 3 ? 'fixed' : 'todo',
      })
      agentsByGroup.set(key, new Set())
    }
    const g = grouped.get(key)
    const agents = agentsByGroup.get(key)
    if (!agents.has(f.agent_id)) {
      agents.add(f.agent_id)
      g.hosts = agents.size
      const label = f.hostname || f.agent_id
      g.hostList.push(g.hostList.includes(label) ? `${label} (${f.agent_id})` : label)
    }
    if (Number(f.status) <= 1 && f.id && f.agent_id && f.fixed_version
        && f.identity_status === 'complete' && (f.identity_current === true || Number(f.identity_current) === 1)
        && f.evidence_status === 'declared' && (f.rule_current === true || Number(f.rule_current) === 1)
        && (f.execution_supported === true || Number(f.execution_supported) === 1)
        && (f.repair_reviewed === true || Number(f.repair_reviewed) === 1)) {
      g.findings.push({ agentId: f.agent_id, findingId: Number(f.id) })
      g.status = 'todo'
    } else if (Number(f.status) <= 1) g.blocked += 1
    if (Number(f.status) <= 1 && !(f.repair_reviewed === true || Number(f.repair_reviewed) === 1)) g.repairUnreviewed += 1
    if (Number(f.status) <= 1 && !(f.execution_supported === true || Number(f.execution_supported) === 1)) g.executionUnsupported += 1
  }
  return [...grouped.values()]
}

export function fetchVulnStats() {
  return get('/api/vuln/stats')
}
export const fetchVulnerabilityHistory = (status = 3, page = 1) => get(`/api/vuln/findings?${new URLSearchParams({ status, page, size: 20 })}`)
export const fetchVulnerabilityCoverage = (page = 1, size = 20) => get(`/api/vuln/coverage?${new URLSearchParams({ page, size })}`)
export const fetchPackageAssessments = (agentId, page = 1, keyword = '') => get(`/api/vuln/coverage/${encodeURIComponent(agentId)}/packages?${new URLSearchParams({ page, size: 20, keyword })}`)

export async function fetchWeakpwds() {
  return get('/api/vuln/weakpwds?page=1&size=100')
}

export async function fetchVulnTasks() {
  return get('/api/vuln/tasks?page=1&size=50')
}

export async function createScanTask(agentIds, opts) {
  return post('/api/vuln/tasks', {
    agentIds,
    name: opts?.name,
    includeVuln: opts?.includeVuln !== false,
    includeWeakPassword: !!opts?.includeWeakPassword,
    includePortService: !!opts?.includePortService,
  })
}

export async function fetchPortFindings(riskyOnly) {
  return get(`/api/vuln/ports?page=1&size=200${riskyOnly ? '&risky=true' : ''}`)
}

export async function fetchAgentsForSelect() {
  const hosts = await fetchAllHosts()
  return hosts.map((h) => ({ id: h.agentId, name: h.host || h.agentId, ip: h.ip, virusExecutionContract: h.virusExecutionContract }))
}

/* ---------------- 病毒 ---------------- */

const VIRUS_STATUS = { 0: 'todo', 1: 'quarantined', 2: 'deleted', 3: 'restored', 4: 'whitelisted' }

export async function fetchVirus(status) {
  const qs = status !== '' && status != null ? `?status=${status}&page=1&size=100` : '?page=1&size=100'
  const [stats, findings, dbVersions] = await Promise.all([
    get('/api/virus/stats'),
    get('/api/virus/findings' + qs),
    get('/api/virus/db'),
  ])
  const db = (dbVersions || [])[0]
  return {
    db: {
      version: db?.db_version || '未导入',
      updated: fmtTime(db?.imported_at),
      hashCount: Number(db?.hash_count || 0).toLocaleString(),
      ruleCount: Number(db?.rule_count || 0).toLocaleString(),
    },
    stats: {
      findings30d: Number(stats?.findings30d || 0),
      quarantined: Number(stats?.quarantined || 0),
      todo: Number(stats?.todo || 0),
      realtime: stats?.realtime || {},
    },
    findings: (findings?.list || []).map((f) => ({
      id: f.id,
      path: f.path,
      name: f.name,
      engine: f.engine,
      sev: sev(f.severity),
      host: f.hostname || f.agent_id,
      agentId: f.agent_id,
      status: VIRUS_STATUS[Number(f.status)] || 'todo',
      sha256: f.sha256,
      size: f.size,
      time: fmtTime(f.created_at),
      quarantineId: f.quarantine_id || '',
      actionError: f.action_error || '',
      pending: Number(f.pending_actions || 0) > 0,
      lastActionState: f.last_action_state || '',
      lastActionError: f.last_action_error || '',
      whitelisted: Number(f.hash_whitelisted || 0) > 0,
      executionSupported: Number(f.virus_execution_contract || 0) === 2,
    })),
  }
}

/** 创建病毒扫描任务：mode 1快速 2全盘 3自定义（paths 必填） */
export async function createVirusTask(agentIds, mode, paths, name, engine = 'builtin') {
  return post('/api/virus/tasks', { agentIds, mode, paths: paths || [], name, engine })
}

/** 检出处置：action = quarantine / delete / restore / whitelist */
export async function virusAct(findingIds, action) {
  return post('/api/virus/findings/actions', { findingIds, action })
}

/** 导入特征库包（zip：manifest.json + hashes.txt），成功后自动推送全部 Agent */
export async function importVirusDb(file) {
  return upload('/api/virus/db/import', file)
}

/** 手动触发特征库推送（新装 Agent 补拉） */
export async function pushVirusDb() {
  return post('/api/virus/db/push', {})
}

export async function fetchVirusTasks() {
  return get('/api/virus/tasks?page=1&size=50')
}

export const fetchVirusTaskEvidence = id => get(`/api/virus/tasks/${id}/evidence`)
export const fetchVirusActionHistory = id => get(`/api/virus/findings/${id}/history`)
export const updateVirusRealtime = (enabled, action) => post('/api/virus/realtime', { enabled, action })

export async function fetchVirusWhitelist() {
  return get('/api/virus/whitelist')
}

export async function addVirusWhitelist(type, value, remark) {
  return post('/api/virus/whitelist', { type, value, remark })
}

export async function removeVirusWhitelist(id) {
  return del(`/api/virus/whitelist/${id}`)
}

/* ---------------- Agent 升级（M4 灰度） ---------------- */

export async function fetchUpgradePackages() {
  return get('/api/upgrade/packages')
}

export async function uploadUpgradePackage(file, version, platform, notes) {
  // multipart 追加表单字段（upload() 只挂文件，这里手工构造）
  const form = new FormData()
  form.append('file', file)
  form.append('version', version)
  form.append('platform', platform)
  form.append('notes', notes || '')
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch('/api/upgrade/packages', { method: 'POST', headers, body: form })
  if (res.status === 401) { clearSession(); location.href = '/login'; throw new Error('登录已过期') }
  const body = await res.json().catch(() => ({}))
  if (!res.ok || body.code !== 0) throw new Error(body.msg || `请求失败(${res.status})`)
  return body.data
}

export async function dispatchUpgrade(packageId, agentIds) {
  return post('/api/upgrade/dispatch', { packageId, agentIds })
}

export async function fetchAgentVersions() {
  return get('/api/upgrade/versions')
}

/* ---------------- 审计与报表（M4） ---------------- */

export async function fetchAuditLogs(page = 1, size = 20) {
  return get(`/api/audit/logs?page=${page}&size=${size}`)
}

/* ---------------- 告警通知通道 ---------------- */

export function fetchNotifyChannels() {
  return get('/api/notify/channels')
}

export function createNotifyChannel(channel) {
  return post('/api/notify/channels', channel)
}

export function updateNotifyChannel(id, channel) {
  return put(`/api/notify/channels/${id}`, channel)
}

export function removeNotifyChannel(id) {
  return del(`/api/notify/channels/${id}`)
}

/* ---------------- 报表预览、历史与定时生成 ---------------- */
const reportParams = query => new URLSearchParams(Object.entries(query || {}).filter(([, value]) => value !== null && value !== undefined && value !== '')).toString()
export const fetchReportGroups = () => get('/api/hosts/groups')
export const previewReport = query => get('/api/reports/preview?' + reportParams(query))
export const saveReportSnapshot = body => post('/api/reports/snapshots', body)
export const fetchReportHistory = (page = 1) => get(`/api/reports/snapshots?page=${page}&size=20`)
export const fetchReportSnapshot = id => get('/api/reports/snapshots/' + encodeURIComponent(id))
export const removeReportSnapshot = id => del('/api/reports/snapshots/' + encodeURIComponent(id))
export const fetchReportSchedules = () => get('/api/reports/schedules')
export const saveReportSchedule = (id, body) => id ? put('/api/reports/schedules/' + encodeURIComponent(id), body) : post('/api/reports/schedules', body)
export const removeReportSchedule = (id, revision) => del(`/api/reports/schedules/${encodeURIComponent(id)}?revision=${revision}`)
export async function downloadReport(format, query = {}, snapshotId = null) {
  if (!['csv', 'xlsx', 'html', 'json'].includes(format)) throw new Error('报表格式无效')
  const path = snapshotId ? `/api/reports/snapshots/${encodeURIComponent(snapshotId)}/export.${format}` : `/api/reports/compliance.${format}?${reportParams(query)}`
  const response = await fetch(path, { headers: { Authorization: `Bearer ${getToken()}` } })
  if (response.status === 401) { clearSession(); location.href = '/login'; throw new Error('登录已过期') }
  if (!response.ok) throw new Error((await response.json().catch(() => ({}))).msg || `报表导出失败(${response.status})`)
  const bytes = await response.arrayBuffer()
  if (bytes.byteLength > 8 * 1024 * 1024) throw new Error('报表文件超过 8 MiB 上限')
  const digest = Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', bytes)), n => n.toString(16).padStart(2, '0')).join('')
  if (digest !== response.headers.get('X-Content-SHA256')) throw new Error('报表文件摘要不匹配')
  const url = URL.createObjectURL(new Blob([bytes], { type: response.headers.get('Content-Type') }))
  const link = document.createElement('a'); link.href = url; link.download = `alinksec-report.${format}`; link.click()
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}
export const downloadComplianceReport = (from, to) => downloadReport('csv', { from, to })

/* ---------------- 实时防护 ---------------- */

export async function fetchProtect() {
  const [engines, blocks] = await Promise.all([
    get('/api/protect/engines'),
    get('/api/protect/blocks?limit=6'),
  ])
  const keyMap = { process: '进程防护', file_tamper: '文件完整性', login: '登录防护', decoy: '勒索诱饵' }
  const descMap = {
    process: '高危进程名/路径/命令行特征阻断，挖矿、反弹 Shell 特征内置',
    file_tamper: 'Linux 关键文件内容与权限监控，可按规则自动恢复',
    login: 'Linux SSH 爆破与异常时段登录检测，可按规则限时封禁来源',
    decoy: '诱饵文件触碰即阻断加密进程（本地响应）',
  }
  const cards = (engines || []).map((e) => ({
    title: keyMap[e.key] || e.name,
    desc: e.desc || descMap[e.key] || '',
  }))
  return { cards, blocks: (blocks || []).map((b) => ({ ...b, severity: alertSev(b), legacySeverity: b.severity_source === 'legacy_unclassified', time: fmtTime(b.last_time) })) }
}

/** 防护规则清单（PR-0010 诱饵 / PR-0011 加密行为） */
export function fetchProtectRules() {
  return get('/api/protect/rules')
}

/** 编辑防护规则（match/actions/enabled） */
export function updateProtectRule(ruleId, body) {
  return put(`/api/protect/rules/${ruleId}`, body)
}

/** 安全处置下发：action = kill / isolate / restore */
export function protectAction(agentId, action, target, reason) {
  return post('/api/protect/actions', { agentId, action, target, reason })
}

/* ---------------- 告警 ---------------- */

function parseAlertDetail(detail) {
  if (detail && typeof detail === 'object') return detail
  try { const value=JSON.parse(detail || '{}'); return value && typeof value==='object' ? value : {} } catch { return {} }
}

export async function fetchAlerts() {
  const data = await get('/api/alerts?page=1&size=100')
  return (data?.list || []).map((a) => ({
    id: a.id,
    sev: alertSev(a),
    legacySeverity: a.severity_source === 'legacy_unclassified',
    type: a.event_type,
    text: a.title,
    host: a.hostname || a.agent_id || '—',
    time: fmtTime(a.last_time),
    done: Number(a.status) === 2,
    handler: a.handle_remark || '',
    action: a.action_taken || '',
    detail: parseAlertDetail(a.detail),
  }))
}

export async function handleAlert(id, remark) {
  return post(`/api/alerts/${id}/handle`, { remark })
}

export const fetchPatchReviewContext = (id, cveId) => get(`/api/fix/patches/${id}/review-context?cveId=${encodeURIComponent(cveId)}`)
export const reviewPatch = (id, body) => post(`/api/fix/patches/${id}/reviews`, body)
export const revokePatchReview = (id, reviewId, note) => post(`/api/fix/patches/${id}/reviews/${encodeURIComponent(reviewId)}/revoke`, { note })

export async function fetchScanCoverage(page = 1) { return get(`/api/vuln/scan-coverage?page=${page}&size=20`) }
export async function fetchFileWatchStatus(page = 1) { return get(`/api/protect/file-watch-status?page=${page}&pageSize=20`) }

export const fetchWindowsLoginStatus = (page = 1) => get(`/api/protect/windows-login-status?page=${page}&pageSize=20`)

export async function fetchClamavStatus(page = 1, size = 20) { return get(`/api/virus/clamav-status?page=${page}&size=${size}`) }

export async function fetchYaraStatus(page = 1, size = 20) { return get(`/api/virus/yara-status?page=${page}&size=${size}`) }
