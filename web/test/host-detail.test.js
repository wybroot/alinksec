import test from 'node:test'
import assert from 'node:assert/strict'
import { metricPoints, percentText, bytesText, durationText } from '../src/utils/host-detail.js'

test('real idle measurements stay zero while absent or invalid measurements stay unknown', () => {
  assert.equal(percentText(0), '0.0%')
  for (const value of [null, undefined, NaN, Infinity, -1, 101, '', false, '0']) assert.equal(percentText(value), '—')
  assert.equal(bytesText(0), '0 B')
  assert.equal(bytesText(null), '—')
  assert.equal(bytesText(8 * 1024 ** 3), '8.0 GiB')
  assert.equal(durationText(90061), '1 天 1 小时 1 分钟')
})
test('the one-hour chart preserves offline gaps and isolates CPU and memory availability', () => {
  const end = 1800000000000
  const points = metricPoints({ serverTime: end, samples: [
    { bucket: end - 120000, cpu_percent: 12.5, memory_percent: 40 },
    { bucket: end, cpu_percent: 0, memory_percent: null },
  ] })
  assert.equal(points.labels.length, 60)
  assert.equal(points.cpu[57], 12.5)
  assert.equal(points.cpu[58], null)
  assert.equal(points.cpu[59], 0)
  assert.equal(points.mem[59], null)
  assert.ok(points.cpu.slice(0, 57).every(value => value === null))
})
