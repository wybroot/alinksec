import assert from 'node:assert/strict'
import test from 'node:test'
import { yaraUpdateSummary } from '../src/utils/yara.js'

test('YARA readiness does not imply a configured or successful automatic update', () => {
  assert.equal(yaraUpdateSummary(undefined), '尚未报告自动更新状态')
  assert.equal(yaraUpdateSummary({ enabled: false }), '未启用自动更新')
  assert.equal(yaraUpdateSummary({ enabled: true, success_at: 0 }), '等待首次成功更新')
  assert.equal(yaraUpdateSummary({ enabled: true, success_at: 0, last_issue: 'yara_update_download' }), '自动更新失败：规则下载失败')
  assert.equal(yaraUpdateSummary({ enabled: true, success_at: 1, last_issue: 'yara_update_download' }), '自动更新失败：规则下载失败，保留上次可用规则')
  assert.equal(yaraUpdateSummary({ enabled: true, success_at: 1, last_issue: 'yara_compile_error' }), '自动更新失败：规则编译失败，请检查语法、模块和规则元数据，保留上次可用规则')
  assert.equal(yaraUpdateSummary({ enabled: true, success_at: 1, last_issue: '' }), '已校验上游规则')
})
