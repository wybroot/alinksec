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

export function loginProtectionPayload(rule, form) {
  const ports = tokens(form.ports).map(x => /^\d+$/.test(x) ? Number(x) : NaN)
  if (!ports.length || ports.length > 16) throw new Error('请输入 1 至 16 个 SSH 端口')
  ports.forEach(x => integer(x, 1, 65535, 'SSH 端口'))
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
