import assert from 'node:assert/strict'
import { createHash } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const digest = bytes => createHash('sha256').update(bytes).digest('hex')
const quote = value => "'" + String(value).replaceAll("'", "''") + "'"
const outcomes = ['pass', 'fail', 'error', 'unknown', 'notapplicable', 'notchecked', 'notselected', 'informational', 'fixed']

export async function captureScap({ mode, sql, ok, request, tokens }) {
  assert.equal(process.env.ALINKSEC_SMOKE_ALLOW_FIXTURES, 'true')
  const root = fileURLToPath(new URL(`../../.tmp/scap-api-${mode}/`, import.meta.url))
  execFileSync('python3', [fileURLToPath(new URL('scap-api-fixture.py', import.meta.url)), root], { timeout: 10_000 })
  const source = readFileSync(root + '/content.zip'), pin = 'a'.repeat(64)
  const captured = { evidenceKind: 'disposable REST lifecycle and protocol report fixtures; separate native interpreter acceptance required', mode, checks: [] }
  const options = { method: 'POST', token: tokens.admin }
  const upload = token => ({ ...options, token, timeout: 40_000, rawBody: Buffer.concat([
    Buffer.from('--scap-api-boundary\r\nContent-Disposition: form-data; name="file"; filename="standards.zip"\r\nContent-Type: application/zip\r\n\r\n'), source, Buffer.from('\r\n--scap-api-boundary--\r\n'),
  ]), extraHeaders: { 'Content-Type': 'multipart/form-data; boundary=scap-api-boundary' } })
  const base = '/api/baseline/scap'
  for (const role of ['operator', 'viewer']) assert.equal((await request(base + '/packages/import', upload(tokens[role]))).status, 403)
  captured.candidate = await ok(base + '/packages/import', upload(tokens.admin))
  const id = captured.candidate.id, prefix = base + '/packages/' + id
  assert.equal(captured.candidate.status, 'candidate')
  assert.equal(captured.candidate.source_sha256, digest(source))
  assert.notEqual(captured.candidate.source_sha256, captured.candidate.content_sha256)
  assert.match(captured.candidate.resolution.resolver, /^OpenSCAP command line tool/)
  assert.equal(captured.candidate.metadata.rules.length, 9)
  assert.equal((await ok(base + '/packages/import', upload(tokens.admin))).id, id)
  assert.equal(captured.candidate.reviews.length, 1)
  const attachment = async (path, expected) => {
    const response = await request(path, { token: tokens.viewer, binary: true })
    assert.equal(response.status, 200)
    assert.equal(response.headers['x-content-sha256'], digest(response.bytes))
    if (expected) assert.equal(digest(response.bytes), expected)
    assert.equal(response.headers['cache-control'], 'no-store')
    return response.bytes
  }
  assert.deepEqual(await attachment(prefix + '/source', digest(source)), source)
  const content = await attachment(prefix + '/content', captured.candidate.content_sha256)
  captured.sourceBase64 = source.toString('base64'); captured.contentBase64 = content.toString('base64')
  const decide = (row, action, token = tokens.admin, agentIds = []) => ({ ...options, token, body: { revision: row.revision, action, note: 'Reviewed offline standard content; disposable REST protocol fixture', agentIds } })
  for (const role of ['operator', 'viewer']) assert.equal((await request(prefix + '/decision', decide(captured.candidate, 'approve', tokens[role]))).status, 403)
  const raced = await Promise.all([request(prefix + '/decision', decide(captured.candidate, 'approve')), request(prefix + '/decision', decide(captured.candidate, 'approve'))])
  assert.deepEqual(raced.map(r => r.status).sort(), [200, 400])
  captured.approved = await ok(prefix, { token: tokens.viewer })
  assert.equal(captured.approved.testReady, false)
  assert.equal((await request(prefix + '/decision', decide(captured.approved, 'publish'))).status, 400)
  captured.checks.push('JWT-admin-review-and-optimistic-revision-race; original-derived-byte-digests; idempotent-source-import')
  const hosts = [['ready', 1, 'ready'], ['windows', 2, 'ready'], ['stale', 1, 'ready'], ['unavailable', 1, 'unavailable']]
  for (const [suffix, os, state] of hosts) {
    const agent = 'ci-smoke-scap-' + suffix
    const coverage = JSON.stringify({ state, version: '5.15', runtime_sha256: pin, observed_at: Math.floor(Date.now() / 1000), last_issue: state === 'unavailable' ? 'scap_runtime_unavailable' : '' })
    sql(`BEGIN; INSERT INTO t_agent(agent_id,hostname,os_type,os_version,status) VALUES(${quote(agent)},${quote('SCAP ' + suffix)},${os},${quote(os === 1 ? 'ubuntu 24.04' : 'Windows Server 2025')},1);
      INSERT INTO t_scap_status(agent_id,contract,coverage,observed_at) VALUES(${quote(agent)},1,${quote(coverage)},${Date.now() - (suffix === 'stale' ? 100_000 : 0)}); COMMIT;`)
  }
  const agent = 'ci-smoke-scap-ready'
  captured.targets = await ok(base + '/targets', { token: tokens.viewer })
  assert.equal(captured.targets.find(t => t.agent_id === 'ci-smoke-scap-stale').state, 'stale')
  for (const suffix of ['windows', 'stale', 'unavailable']) assert.equal((await request(prefix + '/decision', decide(captured.approved, 'test', tokens.admin, ['ci-smoke-scap-' + suffix]))).status, 400)
  assert.equal((await request(prefix + '/decision', decide(captured.approved, 'test', tokens.admin, [agent, agent]))).status, 400)
  captured.testing = await ok(prefix + '/decision', decide(captured.approved, 'test', tokens.admin, [agent]))
  captured.pending = await ok(base + '/tasks/' + captured.testing.last_test_task, { token: tokens.viewer })
  assert.equal((await request(base + '/tasks/' + captured.pending.id + '/agents/' + agent + '/evidence', { token: tokens.viewer })).status, 400)
  function reportFixture(task, statuses) {
    const host = task.hosts[0], manifest = task.snapshot.content.manifest
    const evidence = { schemaVersion: 1, taskId: task.id, commandId: host.command_id, agentId: agent, contentSha256: task.content_sha256, benchmarkId: manifest.benchmarkId, profileId: manifest.profileId, engine: 'SCC', engineVersion: '5.15', runtimeSha256: pin, state: 'complete', issue: '', durationMs: 42, sourceResultSha256: 'b'.repeat(64), rules: task.snapshot.content.rules.map((r, i) => ({ ruleId: r.id, result: statuses[i], weight: 1 })), scores: [{ system: 'urn:xccdf:scoring:default', value: 12.5, maximum: 100 }], counts: Object.fromEntries(outcomes.map(s => [s, statuses.filter(t => t === s).length])) }
    const bytes = JSON.stringify(evidence), sha = digest(bytes)
    sql(`BEGIN; UPDATE t_scap_task_agent SET state='complete',evidence=${quote(bytes)},evidence_sha256='${sha}',finished_at=CURRENT_TIMESTAMP WHERE task_id=${quote(task.id)};
      UPDATE t_scap_task SET state='complete',finished_at=CURRENT_TIMESTAMP WHERE id=${quote(task.id)}; COMMIT;`)
    return bytes
  }
  const nineBytes = reportFixture(captured.pending, outcomes)
  captured.nineOutcomes = await ok(base + '/tasks/' + captured.pending.id, { token: tokens.viewer })
  captured.nineEvidence = nineBytes
  for (const outcome of outcomes) assert.equal(captured.nineOutcomes.hosts[0].evidence.counts[outcome], 1)
  captured.errorTest = await ok(prefix, { token: tokens.viewer })
  assert.equal(captured.errorTest.testReady, false)
  assert.equal((await request(prefix + '/decision', decide(captured.errorTest, 'publish'))).status, 400)
  assert.equal((await attachment(base + '/tasks/' + captured.pending.id + '/agents/' + agent + '/evidence')).toString(), nineBytes)
  captured.checks.push('wrong-OS-stale-unavailable-duplicate-targets-rejected; no-evidence-from-command-status; all-nine-outcomes-preserved; error-unknown-block-publication')
  captured.retesting = await ok(prefix + '/decision', decide(captured.errorTest, 'test', tokens.admin, [agent]))
  const pending = await ok(base + '/tasks/' + captured.retesting.last_test_task, { token: tokens.viewer })
  reportFixture(pending, ['pass', 'fail', 'notapplicable', 'notchecked', 'notselected', 'informational', 'fixed', 'pass', 'pass'])
  captured.ready = await ok(prefix, { token: tokens.viewer })
  assert.equal(captured.ready.testReady, true)
  captured.published = await ok(prefix + '/decision', decide(captured.ready, 'publish'))
  const selection = { packageId: id, agentIds: [agent], name: '标准核查任务' }
  assert.equal((await request(base + '/tasks', { ...options, token: tokens.viewer, body: selection })).status, 403)
  const taskId = (await ok(base + '/tasks', { ...options, token: tokens.operator, body: selection })).taskId
  captured.regular = await ok(base + '/tasks/' + taskId, { token: tokens.viewer })
  assert.equal(captured.regular.snapshot.resolution.resolver, captured.published.resolution.resolver)
  assert.equal(captured.regular.snapshot.sourceSha256, digest(source))
  assert.equal(captured.regular.snapshot.runtimePins[agent], pin)
  captured.tasks = await ok(base + '/tasks', { token: tokens.viewer })
  captured.withdrawn = await ok(prefix + '/decision', decide(captured.published, 'withdraw'))
  assert.equal((await request(base + '/tasks', { ...options, token: tokens.operator, body: selection })).status, 400)
  assert.deepEqual(await attachment(base + '/tasks/' + taskId + '/content', captured.published.content_sha256), content)
  assert.equal((await attachment(base + '/tasks/' + captured.pending.id + '/agents/' + agent + '/evidence')).toString(), nineBytes)
  captured.checks.push('complete-no-error-native-contract-fixture-publish; operator-task-viewer-read; withdrawal-freezes-task-and-evidence-snapshots')
  captured.list = await ok(base + '/packages', { token: tokens.viewer })
  return captured
}
