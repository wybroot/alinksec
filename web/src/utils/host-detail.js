export const measuredPercent = value => typeof value === 'number' && Number.isFinite(value) && value >= 0 && value <= 100 ? value : null
export const percentText = value => measuredPercent(value) === null ? '—' : `${Number(value).toFixed(1)}%`
export function bytesText(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value)) || Number(value) < 0) return '—'
  const bytes = Number(value)
  const unit = Math.min(4, Math.floor(Math.log(Math.max(1, bytes)) / Math.log(1024)))
  return `${(bytes / 1024 ** unit).toFixed(unit ? 1 : 0)} ${['B', 'KiB', 'MiB', 'GiB', 'TiB'][unit]}`
}
export function durationText(value) {
  if (value === null || value === undefined || !Number.isFinite(Number(value)) || Number(value) < 0) return '—'
  const seconds = Number(value)
  const days = Math.floor(seconds / 86400), hours = Math.floor(seconds % 86400 / 3600), minutes = Math.floor(seconds % 3600 / 60)
  return `${days ? days + ' 天 ' : ''}${days || hours ? hours + ' 小时 ' : ''}${minutes} 分钟`
}
export function formatDate(value) {
  if (value === null || value === undefined || value === '') return '未上报'
  let input = value
  if (typeof input === 'string' && /^\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d(?:\.\d+)?$/.test(input)) input = input.replace(' ', 'T') + 'Z'
  const date = new Date(input)
  return Number.isFinite(date.getTime()) ? date.toLocaleString('zh-CN', { hour12: false }) : '未上报'
}
export function metricPoints(runtime = {}) {
  const end = Math.floor((runtime.serverTime || Date.now()) / 60000) * 60000
  const samples = new Map((runtime.samples || []).map(sample => [Number(sample.bucket), sample]))
  const points = Array.from({ length: 60 }, (_, index) => {
    const ts = end - (59 - index) * 60000
    const sample = samples.get(ts)
    return { ts, cpu: measuredPercent(sample?.cpu_percent), mem: measuredPercent(sample?.memory_percent) }
  })
  return { labels: points.map(p => new Date(p.ts).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit', hour12: false })),
    cpu: points.map(p => p.cpu), mem: points.map(p => p.mem) }
}
