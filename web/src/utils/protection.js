const tokens = (value) => [...new Set(String(value || '').split(/[,，\n]/).map(x => x.trim()).filter(Boolean))]
const integer = (value, min, max, label) => {
  if (!Number.isInteger(value) || value < min || value > max) throw new Error(`${label}超出允许范围`)
  return value
}

export function fileProtectionPayload(rule, form) {
  const paths = [...new Set(String(form.paths || '').split(/\r?\n/).map(x => x.trim()).filter(Boolean))]
  if (!paths.length || paths.length > 64 || paths.some(x => x.length > 4096 || x.includes('\0') || !(/^(\/|[A-Za-z]:[\\/])/.test(x)))) throw new Error('请输入最多 64 个绝对文件路径')
  return { enabled: Boolean(form.enabled), actions: form.restore ? ['alert', 'restore'] : ['alert'], match: { ...rule.match, paths } }
}

function loginPayload(rule, form, windows = false) {
  const portLabel = windows ? 'Windows 登录 TCP 端口' : 'SSH 端口'
  const ports = tokens(form.ports).map(x => /^\d+$/.test(x) ? Number(x) : NaN)
  if (!ports.length || ports.length > 16) throw new Error(`请输入 1 至 16 个${portLabel}`)
  ports.forEach(x => integer(x, 1, 65535, portLabel))
  const trusted = tokens(form.trusted), users = tokens(form.users)
  if (trusted.length > 128 || users.length > 64) throw new Error('信任来源或排除账户超过上限')
  if (!String(form.timezone || '').trim()) throw new Error('请选择时区')
  return { enabled: Boolean(form.enabled), actions: form.block ? ['alert', 'block_ip'] : ['alert'], match: {
    ...rule.match, failure_threshold: integer(form.threshold, 2, 100, '失败次数'), window_sec: integer(form.window, 1, 3600, '检测窗口'),
    cooldown_sec: integer(form.cooldown, 1, 86400, '告警间隔'), block_duration_sec: integer(form.duration, 5, 3600, '封禁时长'),
    ssh_ports: ports, trusted_ips: trusted, user_exclude: users, off_hours_enabled: Boolean(form.offHours),
    allowed_start_hour: integer(form.start, 0, 23, '起始小时'), allowed_end_hour: integer(form.end, 0, 24, '结束小时'), timezone: form.timezone.trim(),
  } }
}

export function loginProtectionPayload(rule, form) { return loginPayload(rule, form) }

export function windowsLoginProtectionPayload(rule, form) {
  if (rule?.match?.windows_contract !== 1 || JSON.stringify(rule.match.platforms) !== '["windows"]') throw new Error('Windows 登录规则范围无效')
  const types = [...new Set(form.types || [])]
  if (!types.length || types.length > 2 || types.some(x => ![3, 10].includes(x))) throw new Error('请选择网络登录或远程交互登录')
  const result = loginPayload(rule, form, true)
  result.match.windows_ports = result.match.ssh_ports
  delete result.match.ssh_ports
  result.match.windows_logon_types = types
  return result
}

export const windowsLoginStateLabel = state => ({ starting: '启动中', disabled: '规则已停用', polling: '正在监测', behind: '正在追赶日志', degraded: '覆盖不完整', failed: '监测失败', unsupported: 'Agent 不支持', offline: '主机离线或禁用', stale: '心跳已过期', stalled: '日志采集停滞', unknown: '状态未知' }[state] || '状态未知')
export const windowsLoginIssueLabel = issue => ({ journal_invalid: '本地状态损坏或无法访问', persist_failed: '本地状态保存失败', audit_query_failed: '无法查询登录审计策略', security_read_failed: '无法读取 Security 日志', event_query_failed: '登录事件查询或解析失败', event_order_invalid: '事件顺序异常', log_gap: '日志已清空或覆盖，检测计数已重置', block_failed: '来源封禁失败', firewall_cleanup_failed: '过滤器清理失败，需要重启 Agent', audit_disabled: '成功或失败登录审计未启用', backlog: '日志尚未追平', event_buffer_full: '未确认告警缓冲区已满，等待平台回执', event_retention_exceeded: '本地事件保留已超限' }[issue] || issue || '—')
