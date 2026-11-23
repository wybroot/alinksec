export const assetCategories = [
  ['software', '软件'], ['ports', '监听端口'], ['processes', '进程'],
  ['accounts', '账户'], ['disks', '磁盘'], ['containers', '容器'],
]

export const collectionLabel = state => ({
  complete: '最近采集完成', failed: '采集失败，保留上次记录',
  partial: '采集不完整，保留上次记录', unsupported: '当前系统不支持',
  legacy: '采集版本或覆盖未知',
}[state?.status] || '尚无可确认的采集状态')

export const collectionTime = value => {
  const time = Number(value)
  if (!Number.isFinite(time) || time <= 0 || time > 8640000000000000) return '未知'
  return new Date(time).toISOString().replace('T', ' ').replace('.000Z', ' UTC').replace('Z', ' UTC')
}

export const collectionEmptyLabel = (state, completeLabel) => state?.status === 'complete'
  ? completeLabel : '暂无可用记录；不能据此判断资产为空'

export const formatAssetBytes = value => {
  const bytes = Number(value)
  if (!Number.isFinite(bytes) || bytes < 0) return '未知'
  for (const [unit, size] of [['TiB', 2 ** 40], ['GiB', 2 ** 30], ['MiB', 2 ** 20], ['KiB', 2 ** 10]]) {
    if (bytes >= size) return `${(bytes / size).toFixed(1)} ${unit}`
  }
  return `${bytes} B`
}
