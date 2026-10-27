export const readScanScope = value => {
  try { const scope = typeof value === 'string' ? JSON.parse(value) : value; return scope && typeof scope === 'object' && !Array.isArray(scope) ? scope : {} }
  catch { return {} }
}

export const retryPaths = evidence => [...new Set((evidence?.issues || [])
  .map(issue => issue.path).filter(path => typeof path === 'string' && path.length <= 512
    && !/[\x00-\x1f\x7f]/.test(path) && (path.startsWith('/') || /^[A-Za-z]:[\\/]/.test(path))
    && !path.replaceAll('\\', '/').split('/').includes('..')))].slice(0, 64)

export const scanBudget = form => {
  const budget = { timeLimitSec: form.timeLimitSec, maxFiles: form.maxFiles, maxTotalBytes: Math.round(form.maxMiB * 1048576) }
  if (![budget.timeLimitSec, budget.maxFiles, budget.maxTotalBytes].every(Number.isSafeInteger)
    || budget.timeLimitSec < 1 || budget.timeLimitSec > 7200 || budget.maxFiles < 1 || budget.maxFiles > 100000
    || budget.maxTotalBytes < 1 || budget.maxTotalBytes > 20 * 1073741824) throw new Error('请填写有效的扫描预算')
  return budget
}

export const canDispose = (row, action) => {
  if (!row || row.pending) return false
  if (action === 'whitelist') return true
  if (!row.executionSupported) return false
  if (action === 'restore') return ['todo', 'quarantined'].includes(row.status) && /^[0-9a-f]{32}$/.test(row.quarantineId || '')
  if (action === 'quarantine') return ['todo', 'restored'].includes(row.status) && !row.quarantineId
  if (action === 'delete') return ['todo', 'quarantined', 'restored'].includes(row.status) && (row.status !== 'quarantined' || /^[0-9a-f]{32}$/.test(row.quarantineId || ''))
  return false
}

export const dispositionSummary = (ids, rows) => {
  const counts = { pending: 0, succeeded: 0, failed: 0, timeout: 0, committed: 0, unknown: 0 }
  const byId = new Map(rows.map(row => [row.id, row]))
  for (const id of ids) {
    const state = byId.get(id)?.state
    counts[Object.hasOwn(counts, state) ? state : 'unknown']++
  }
  return counts
}
