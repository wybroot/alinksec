/* =====================================================================
 * 数据接口层（M2 · 真实 REST）
 * ---------------------------------------------------------------------
 * 所有数据来自服务端 8080 /api/**（JWT 鉴权），页面零 mock。
 * 登录态：localStorage 持久化 token，401 自动跳转登录页。
 * 适配层把服务端字段映射为页面组件所需结构（页面无需感知后端模型）。
 * ===================================================================== */

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
const put = (path, data) => request(path, { method: 'PUT', body: JSON.stringify(data) })
const del = (path) => request(path, { method: 'DELETE' })

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

const SEV = { 4: 'critical', 3: 'high', 2: 'medium', 1: 'low' }
const sev = (n) => SEV[Number(n)] || 'low'
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
  const top = (topHosts || [])[0]
  return {
    stats: {
      hosts: s.hosts?.online ?? 0,
      hostsTotal: s.hosts?.total ?? 0,
      weekNew: s.hosts?.weekNew ?? 0,
      pending: s.alerts?.open ?? 0,
      crit: sevMap[4] ?? 0,
      high: sevMap[3] ?? 0,
      virusWeek: s.virus?.findings30d ?? 0,
      quarantined: s.virus?.quarantined ?? 0,
      virusTodo: s.virus?.todo ?? 0,
      riskHosts: (topHosts || []).length,
      topRisk: top ? `${top.hostname}（${top.alert_count}）` : '—',
    },
    // 告警级别分布（饼图）：severity 4严重/3高危/2中危/1低危
    sevDist: [
      { value: sevMap[4] ?? 0, name: '严重' },
      { value: sevMap[3] ?? 0, name: '高危' },
      { value: sevMap[2] ?? 0, name: '中危' },
      { value: sevMap[1] ?? 0, name: '低危' },
    ].filter((x) => x.value > 0),
    trend: (trend || []).map((t) => ({
      date: t.date,
      count: Number(t.count || 0),
      handled: Number(t.handled || 0),
    })),
    events: (events?.list || []).map((a) => ({
      id: a.id,
      time: fmtTime(a.last_time),
      sev: sev(a.severity),
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
  return data?.result || []
}

/* ---------------- 安全大屏 ---------------- */

export async function fetchScreen() {
  const [summary, trend, sevDist, categories, topHosts, alerts, engines, status] = await Promise.all([
    get('/api/dashboard/summary'),
    get('/api/dashboard/screen-trend?days=7'),
    get('/api/dashboard/event-distribution'),
    get('/api/dashboard/baseline-categories'),
    get('/api/dashboard/top-hosts?limit=5'),
    get('/api/alerts?page=1&size=20'),
    get('/api/protect/engines'),
    get('/api/protect/status'),
  ])
  const s = summary || {}
  const sevMap = {}
  for (const row of s.alerts?.bySeverity || []) sevMap[Number(row.severity)] = Number(row.count)

  // 趋势（date/virus/blocked）
  const trendData = (trend || []).map((d) => ({ date: d.date, virus: Number(d.virus), blocked: Number(d.blocked) }))

  // 告警等级分布（饼图）
  const sevPie = [
    { name: '严重', value: sevMap[4] ?? 0 },
    { name: '高危', value: sevMap[3] ?? 0 },
    { name: '中危', value: sevMap[2] ?? 0 },
    { name: '低危', value: sevMap[1] ?? 0 },
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
  const events = (alerts?.list || []).map((a) => ({
    id: a.id,
    sev: sev(a.severity),
    type: a.event_type,
    text: a.title,
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
      crit: sevMap[4] ?? 0,
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

export async function fetchHosts() {
  const data = await get('/api/hosts?page=1&size=100')
  return (data?.list || []).map((h) => ({
    agentId: h.agent_id,
    host: h.hostname,
    ip: h.ip || '—',
    os: OS[h.os_type]?.(h.os_version) || h.os_version || '—',
    group: '—',
    ver: h.agent_version || '—',
    status: HOST_STATUS[h.status] || 'offline',
    protect: !!h.protect_enabled,
    hb: fmtAgo(h.last_heartbeat),
    risk: Number(h.alert_count || 0),
    lastEvt: h.last_event || '',
    softwareCount: h.software_count,
    portCount: h.port_count,
    accountCount: h.account_count,
    containerCount: Number(h.container_count || 0),
  }))
}

export async function fetchGroups() {
  const list = await get('/api/hosts/groups')
  return (list || []).map((g) => g.name)
}

export async function fetchHostDetail(agentId) {
  const [detail, software, ports, accounts, containers] = await Promise.all([
    get(`/api/hosts/${agentId}`),
    get(`/api/hosts/${agentId}/software?page=1&size=500`),
    get(`/api/hosts/${agentId}/ports`),
    get(`/api/hosts/${agentId}/accounts`),
    get(`/api/hosts/${agentId}/containers`),
  ])
  return { detail, software, ports, accounts, containers }
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
    c: Number(r.c || 0),
    h: Number(r.h || 0),
    m: Number(r.m || 0),
    l: Number(r.l || 0),
    time: fmtTime(r.checked_at),
  }))
}

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
export async function approveFixTask(taskId, operator) {
  return post(`/api/fix/tasks/${taskId}/approve`, { operator })
}

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
  const data = await get('/api/vuln/findings?page=1&size=200')
  const grouped = new Map()
  for (const f of data?.list || []) {
    if (!grouped.has(f.cve_id)) {
      grouped.set(f.cve_id, {
        cve: f.cve_id,
        desc: f.title || f.cve_id,
        pkg: f.software,
        cur: f.installed_version || '—',
        target: f.cve_fixed || '—',
        sev: sev(f.severity),
        cvss: f.cvss ?? '-',
        fixType: 'pkg',
        hosts: 0,
        hostList: [],
        status: f.status >= 3 ? 'fixed' : 'todo',
      })
    }
    const g = grouped.get(f.cve_id)
    g.hosts += 1
    if (!g.hostList.includes(f.hostname || f.agent_id)) g.hostList.push(f.hostname || f.agent_id)
    if (f.status < 3 && g.status === 'fixed') g.status = 'todo'
    if (f.status >= 3 && g.status === 'todo') g.status = 'fixing'
  }
  return [...grouped.values()]
}

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
  const data = await get('/api/hosts?page=1&size=100')
  return (data?.list || []).map((h) => ({ id: h.agent_id, name: h.hostname || h.agent_id, ip: h.ip }))
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
      yaraCount: Number(db?.rule_count || 0).toLocaleString(),
    },
    stats: {
      findings30d: Number(stats?.findings30d || 0),
      quarantined: Number(stats?.quarantined || 0),
      todo: Number((findings?.list || []).filter((f) => Number(f.status) === 0).length),
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
    })),
  }
}

/** 创建病毒扫描任务：mode 1快速 2全盘 3自定义（paths 必填） */
export async function createVirusTask(agentIds, mode, paths, name) {
  return post('/api/virus/tasks', { agentIds, mode, paths: paths || [], name })
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

/** 合规报表下载（浏览器直接拉 CSV，带 JWT header） */
export async function downloadComplianceReport(from, to) {
  const headers = {}
  const token = getToken()
  if (token) headers.Authorization = `Bearer ${token}`
  const res = await fetch(`/api/reports/compliance.csv?from=${from}&to=${to}`, { headers })
  if (!res.ok) throw new Error(`报表导出失败(${res.status})`)
  const blob = await res.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `alinksec-report-${from}_${to}.csv`
  a.click()
  URL.revokeObjectURL(url)
}


/* ---------------- 实时防护 ---------------- */

export async function fetchProtect() {
  const [engines, status, blocksRaw] = await Promise.all([
    get('/api/protect/engines'),
    get('/api/protect/status'),
    get('/api/protect/blocks?limit=6'),
  ])
  const protectOn = (status || []).filter((a) => a.protect_enabled).length
  const keyMap = { process: '进程防护', file_tamper: '文件完整性', login: '登录防护', decoy: '勒索诱饵' }
  const descMap = {
    process: '高危进程名/路径/命令行特征阻断，挖矿、反弹 Shell 特征内置',
    file_tamper: '关键文件（passwd、sudoers、启动项）防篡改，篡改自动还原',
    login: 'SSH/RDP 暴力破解识别，阈值触发自动封禁来源 IP',
    decoy: '诱饵文件触碰即阻断加密进程（本地响应）',
  }
  const cards = (engines || []).map((e) => ({
    title: keyMap[e.key] || e.name,
    on: true,
    desc: e.desc || descMap[e.key] || '',
    stats: `已防护主机 ${protectOn} 台`,
  }))
  return { cards, blocks: blocks || [] }
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

export async function fetchAlerts() {
  const data = await get('/api/alerts?page=1&size=100')
  return (data?.list || []).map((a) => ({
    id: a.id,
    sev: sev(a.severity),
    type: a.event_type,
    text: a.title,
    host: a.hostname || a.agent_id || '—',
    time: fmtTime(a.last_time),
    done: Number(a.status) === 2,
    handler: a.handle_remark || '',
  }))
}

export async function handleAlert(id, remark) {
  return post(`/api/alerts/${id}/handle`, { remark })
}
