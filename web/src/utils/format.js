// 级别/状态映射工具（控制台与大屏共用）
export const sevType = s => ({ critical: 'danger', high: 'warning', medium: 'primary', low: 'info' }[s] || 'info')
export const sevLabel = s => ({ critical: '严重', high: '高危', medium: '中危', low: '低危' }[s] || s)
export const hostTagType = s => ({
  online: 'success', offline: 'info', pending: 'warning', isolating: 'warning', isolated: 'danger',
  restoring: 'warning', isolate_failed: 'danger', restore_failed: 'danger',
}[s] || 'info')
export const hostStatusLabel = s => ({
  normal: '未隔离', online: '在线', offline: '离线', pending: '待激活', isolating: '隔离中', isolated: '已隔离',
  restoring: '解除中', isolate_failed: '隔离失败', restore_failed: '解除失败',
}[s] || s)

// ECharts 控制台浅色主题通用轴样式
export const AX = {
  axisLabel: { color: '#64748b', fontSize: 11 },
  axisLine: { lineStyle: { color: '#e2e8f0' } },
  splitLine: { lineStyle: { color: '#eef2f7' } }
}
export const PAL = ['#2563eb', '#06b6d4', '#f59e0b', '#dc2626', '#16a34a', '#94a3b8']
