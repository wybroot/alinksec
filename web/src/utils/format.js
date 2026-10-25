// 级别/状态映射工具（控制台与大屏共用）
export const sevType = s => ({ critical: 'danger', high: 'warning', medium: 'primary', low: 'info' }[s] || 'info')
export const sevLabel = s => ({ critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息', unknown: '未知' }[s] || s)
export const actionLabel = action => ({ alert_only: '仅告警', restored: '已恢复文件', restore_failed: '恢复失败', blocked_ip: '已执行限时封禁', block_expired: '封禁意图已失效', block_failed: '封禁失败', killed: '已结束进程', isolated: '已隔离主机', killed_and_isolated: '已结束进程并隔离主机' }[action] || action || '仅告警')
export const hostTagType = s => ({
  online: 'success', offline: 'info', pending: 'warning', isolating: 'warning', isolated: 'danger',
  restoring: 'warning', isolate_failed: 'danger', restore_failed: 'danger', isolation_unknown: 'warning',
}[s] || 'info')
export const hostStatusLabel = s => ({
  normal: '未隔离', online: '在线', offline: '离线', pending: '待激活', isolating: '隔离中', isolated: '已隔离',
  restoring: '解除中', isolate_failed: '隔离失败', restore_failed: '解除失败', isolation_unknown: '隔离状态待确认',
}[s] || s)

// ECharts 控制台浅色主题通用轴样式
export const AX = {
  axisLabel: { color: '#64748b', fontSize: 11 },
  axisLine: { lineStyle: { color: '#e2e8f0' } },
  splitLine: { lineStyle: { color: '#eef2f7' } }
}
export const PAL = ['#2563eb', '#06b6d4', '#f59e0b', '#dc2626', '#16a34a', '#94a3b8']
