import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

// Only invoked by the explicitly disposable API smoke harness. The reports are
// protocol fixtures; native execution evidence is captured in separate jobs.
export async function captureCompliance({ mode, sql, ok, request, tokens, baselinePackages, baselineTaskIds }) {
  const fixtures = { mode, evidenceKind: 'disposable REST API with protocol report fixtures', profiles: [] }
  for (const level of [2, 3]) for (const platform of ['linux', 'windows']) {
    const document = JSON.parse(readFileSync(new URL(`../baseline/packages/compliance/level${level}/${platform}-baseline.json`, import.meta.url)))
    const agent = platform === 'linux' ? 'ci-smoke-001' : 'ci-smoke-windows'
    const options = { token: tokens.admin, method: 'POST' }
    const boundary = 'compliance-pack-boundary'
    const upload = value => ({ ...options, rawBody: Buffer.from(`--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="compliance.json"\r\nContent-Type: application/json\r\n\r\n${JSON.stringify(value)}\r\n--${boundary}--\r\n`), extraHeaders: { 'Content-Type': `multipart/form-data; boundary=${boundary}` } })
    const incomplete = structuredClone(document)
    delete incomplete.compliance.controlChecks[Object.keys(incomplete.compliance.controlChecks)[0]]
    assert.equal((await request('/api/baseline/packages/import', upload(incomplete))).status, 400)
    const candidate = await ok('/api/baseline/packages/import', upload(document))
    const record = { id: candidate.id, code: document.code }; baselinePackages.push(record)
    const prefix = `/api/baseline/packages/${candidate.id}`
    const approved = await ok(`${prefix}/review`, { ...options, body: { approved: true, note: 'Review entire clause inventory and native probe scope; protocol fixture' } })
    record.template = Number(approved.template_id)
    const row = { level, platform, agent, candidate, approved }
    for (const outcome of ['error', 'pass']) {
      const testing = await ok(`${prefix}/test`, { ...options, body: { agentIds: [agent] } })
      const taskId = Number(testing.test_task_id); baselineTaskIds.push(taskId)
      const path = `/api/baseline/tasks/${taskId}/agents/${agent}/compliance`
      row.path = path; row.taskId = taskId
      row.pending = await ok(path, { token: tokens.viewer })
      assert.equal(row.pending[0].counts.pending, level === 2 ? 23 : 34)
      const controlId = `${level === 2 ? 7 : 8}.1.4.1.a`
      const decision = { templateId: record.template, controlId, revision: 0, decision: 'pass', note: '已核验现场账户清单与口令策略的协议测试证据', evidenceRef: 'fixture:identity;sha256=' + 'a'.repeat(64) }
      assert.equal((await request(`${path}/review`, { ...options, body: decision })).status, 400)
      const n = document.items.length, pass = outcome === 'pass'
      sql(`BEGIN;
        INSERT INTO t_baseline_result(task_id,agent_id,item_id,passed,actual,message,execution_status)
        SELECT e.task_id,e.agent_id,e.item_id,${pass},'Protocol report fixture, not native compliance evidence','${pass ? '' : 'Probe unavailable fixture'}','${outcome}'
        FROM t_baseline_task_expected e WHERE e.task_id=${taskId};
        INSERT INTO t_baseline_summary(task_id,agent_id,total,passed_count,failed_count,score,error_count)
        VALUES (${taskId},'${agent}',${n},${pass ? n : 0},${pass ? 0 : n},${pass ? 100 : 0},${pass ? 0 : n});
        UPDATE t_baseline_task SET status=2,progress=100,finished_at=CURRENT_TIMESTAMP WHERE id=${taskId}; COMMIT;`)
      row[outcome] = await ok(path, { token: tokens.viewer })
      if (!pass) {
        assert.ok(row.error[0].counts.error > 0)
        assert.equal((await request(`${path}/review`, { ...options, body: decision })).status, 400)
        assert.equal((await request(`${prefix}/publish`, { ...options, body: { note: 'Errors cannot be published' } })).status, 400)
      } else {
        assert.equal(row.pass[0].counts.pass, 0)
        for (const role of ['operator', 'viewer']) assert.equal((await request(`${path}/review`, { ...options, token: tokens[role], body: decision })).status, 403)
        const raced = await Promise.all([request(`${path}/review`, { ...options, body: decision }), request(`${path}/review`, { ...options, body: decision })])
        assert.deepEqual(raced.map(r => r.status).sort(), [200, 400])
        row.reviewed = await ok(path, { token: tokens.viewer })
        assert.equal(row.reviewed[0].counts.pass, 1)
        assert.equal(row.reviewed[0].controls.find(c => c.id === controlId).history.length, 1)
        const reopened = await ok(`${path}/review`, { ...options, body: { ...decision, revision: 1, decision: 'pending', note: '账户范围变化后撤回结论并重新收集现场证据', evidenceRef: '' } })
        assert.equal(reopened[0].counts.pass, 0)
        assert.equal(reopened[0].controls.find(c => c.id === controlId).history.length, 2)
        row.reopened = reopened
        row.latest = await ok('/api/baseline/latest', { token: tokens.viewer })
        row.items = await ok(`/api/baseline/tasks/${taskId}/agents/${agent}/items`, { token: tokens.viewer })
        row.categories = await ok(`/api/baseline/tasks/${taskId}/category-stats`, { token: tokens.viewer })
      }
    }
    row.published = await ok(`${prefix}/publish`, { ...options, body: { note: 'Complete automatic report fixture reviewed; manual clause evidence still required' } })
    row.withdrawn = await ok(`${prefix}/withdraw`, { ...options, body: { note: 'Disposable fixture cleanup' } })
    assert.equal((await ok(row.path, { token: tokens.viewer }))[0].controls.length, level === 2 ? 23 : 34)
    fixtures.profiles.push(row)
  }
  return fixtures
}
