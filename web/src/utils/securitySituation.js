export const NETWORK_EVENT_LABELS = {
  login_crack: '登录暴力破解', login_anomaly: '异常登录', ssh_bruteforce: 'SSH 暴力破解', rdp_bruteforce: 'RDP 暴力破解',
  credential_stuffing: '撞库攻击', web_attack: 'Web 攻击', waf_attack: 'WAF 攻击告警', sql_injection: 'SQL 注入',
  xss: '跨站脚本攻击', path_traversal: '路径穿越', command_injection: '命令注入', file_inclusion: '文件包含',
  webshell_attack: 'WebShell 攻击', ssrf: '服务端请求伪造', rce: '远程代码执行', port_scan: '端口扫描', network_attack: '网络攻击',
}
export const NETWORK_EVENT_TYPES = new Set(Object.keys(NETWORK_EVENT_LABELS))
export const LOCATION_REASONS = {
  no_network_source: '本机事件，未记录远端来源', invalid_ip: 'IP 缺失或格式无效', non_public_ip: '内网或保留地址',
  disabled: 'IP 定位未启用', credentials_missing: '定位服务凭据未配置', pending: '正在查询定位', rate_limited: '等待定位配额',
  busy: '定位查询繁忙', lookup_failed: '定位查询失败', coordinates_missing: '定位结果缺少经纬度', unavailable: '定位数据暂不可用',
  database_missing: '离线定位库未安装', database_invalid: '离线定位库无效', not_found: '定位库未覆盖该 IP', source_missing: '未采集到攻击来源 IP',
}
export function located(value) {
  return value?.status === 'located' && ['ipip', 'dbip', 'maxmind', 'asset_inventory'].includes(value.provider)
    && typeof value.latitude === 'number' && typeof value.longitude === 'number'
    && Number.isFinite(value.latitude) && Number.isFinite(value.longitude)
    && Math.abs(value.latitude) <= 90 && Math.abs(value.longitude) <= 180
}
export function eventEvidence(alert, metadata) {
  let detail = alert.detail
  if (typeof detail === 'string') { try { detail = JSON.parse(detail) } catch { detail = {} } }
  const network = NETWORK_EVENT_TYPES.has(alert.event_type)
  const sourceIp = network && typeof detail?.source_ip === 'string' ? detail.source_ip : ''
  const sourceMatches = sourceIp && metadata?.source?.ip === sourceIp
  const targetMatches = alert.agent_id && metadata?.target?.agentId === alert.agent_id
    && (!alert.host_ip || metadata.target.ip === alert.host_ip)
  return {
    agentId: alert.agent_id || '', sourceIp, targetIp: alert.host_ip || metadata?.target?.ip || '',
    sourceLocation: sourceMatches ? metadata.source.location : { status: network ? 'unavailable' : 'no_network_source' },
    targetLocation: targetMatches ? metadata.target.location : { status: 'unavailable' },
    network, attackLabel: detail?.trigger === 'ssh_bruteforce' ? 'SSH 暴力破解' : detail?.trigger === 'windows_bruteforce' ? 'Windows 登录暴力破解' : NETWORK_EVENT_LABELS[alert.event_type] || '',
    observedAt: alert.last_time || '', count: Math.max(1, Number(alert.count) || 1),
  }
}
export function situationStats(events) {
  return { attacks: events.filter(e => e.network).length, network: events.filter(e => e.network && e.sourceIp).length,
    routes: events.filter(e => e.network && e.sourceIp && located(e.sourceLocation) && located(e.targetLocation)).length,
    located: events.filter(e => (e.sourceIp && located(e.sourceLocation)) || located(e.targetLocation)).length,
    local: events.filter(e => !e.network).length }
}
