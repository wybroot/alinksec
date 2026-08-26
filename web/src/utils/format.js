// 级别/状态映射工具（控制台与大屏共用）
export const sevType = s => ({ critical: 'danger', high: 'warning', medium: 'primary', low: 'info' }[s] || 'info')
export const sevLabel = s => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[s] || s)
export const hostTagType = s => ({ online: 'success', offline: 'info', isolated: 'danger', pending: 'warning' }[s] || 'info')
export const hostStatusLabel = s => ({ online: '在线', offline: '离线', isolated: '已隔离', pending: '待激活' }[s] || s)

// ECharts 控制台浅色主题通用轴样式
export const AX = {
  axisLabel: { color: '#64748b', fontSize: 11 },
  axisLine: { lineStyle: { color: '#e2e8f0' } },
  splitLine: { lineStyle: { color: '#eef2f7' } }
}
export const PAL = ['#2563eb', '#06b6d4', '#f59e0b', '#dc2626', '#16a34a', '#94a3b8']
