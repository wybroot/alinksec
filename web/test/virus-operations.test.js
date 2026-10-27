import test from 'node:test'
import assert from 'node:assert/strict'
import { retryPaths, scanBudget, readScanScope, canDispose, dispositionSummary } from '../src/utils/virus.js'

test('retry proposes bounded absolute paths and preserves order without traversal or report-only placeholders', () => {
  const paths = ['/tmp/a', '/tmp/a', 'C:\\Data\\a', '任务范围', '/tmp/../etc/passwd', '/tmp/a\nb', '/'+ 'a'.repeat(512)]
  assert.deepEqual(retryPaths({ issues: paths.map(path => ({ path })) }), ['/tmp/a', 'C:\\Data\\a'])
  assert.equal(retryPaths({ issues: Array.from({ length: 70 }, (_, i) => ({ path: `/tmp/${i}` })) }).length, 64)
  assert.deepEqual(retryPaths(null), [])
})
test('budget conversion rejects missing, fractional and out of range counts', () => {
  assert.deepEqual(scanBudget({ timeLimitSec: 60, maxFiles: 100, maxMiB: 256 }), { timeLimitSec: 60, maxFiles: 100, maxTotalBytes: 268435456 })
  for (const patch of [{ timeLimitSec: 0 }, { timeLimitSec: 7201 }, { maxFiles: 1.5 }, { maxFiles: 100001 }, { maxMiB: 20481 }, { maxMiB: null }])
    assert.throws(() => scanBudget({ timeLimitSec: 60, maxFiles: 100, maxMiB: 256, ...patch }))
})
test('legacy or malformed scopes remain visibly unknown', () => {
  assert.deepEqual(readScanScope('bad'), {})
  assert.deepEqual(readScanScope('[]'), {})
  assert.deepEqual(readScanScope(null), {})
  assert.equal(readScanScope('{"retry_of":12}').retry_of, 12)
})
test('disposition choices respect pending operations and retained quarantine objects, including restored and legacy files', () => {
  const row = { status: 'todo', pending: false, executionSupported: true, quarantineId: '' }
  assert.equal(canDispose(row, 'quarantine'), true)
  assert.equal(canDispose({ ...row, quarantineId: 'c'.repeat(32) }, 'quarantine'), false)
  assert.equal(canDispose({ ...row, quarantineId: 'c'.repeat(32) }, 'restore'), true)
  assert.equal(canDispose({ ...row, status: 'quarantined', quarantineId: '' }, 'delete'), false)
  assert.equal(canDispose({ ...row, status: 'restored' }, 'quarantine'), true)
  assert.equal(canDispose({ ...row, executionSupported: false }, 'delete'), false)
  assert.equal(canDispose({ ...row, executionSupported: false }, 'whitelist'), true)
  for (const action of ['quarantine', 'delete', 'restore', 'whitelist']) assert.equal(canDispose({ ...row, pending: true }, action), false)
})
test('batch counts only the exact submitted actions and keeps missing or unknown receipts unconfirmed', () => {
  assert.deepEqual(dispositionSummary(['a', 'b', 'c', 'd', 'e'], [
    { id: 'a', state: 'succeeded' }, { id: 'b', state: 'failed' }, { id: 'c', state: 'pending' }, { id: 'd', state: 'new-state' }, { id: 'other', state: 'succeeded' },
  ]), { succeeded: 1, failed: 1, pending: 1, timeout: 0, committed: 0, unknown: 2 })
})
