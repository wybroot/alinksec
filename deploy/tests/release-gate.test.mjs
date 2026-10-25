import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import test from 'node:test'
import { findValidatedRun, passesReleaseGate } from '../release/ci-gate.mjs'

const sha = 'a'.repeat(40)
const run = { id: 123, head_sha: sha, head_branch: 'main', event: 'push', status: 'completed', conclusion: 'success' }
const fixture = JSON.parse(readFileSync(new URL('./fixtures/release-ci-jobs.json', import.meta.url)))
const jobs = fixture.jobs
test('release requires all jobs on the exact main commit', () => {
  assert.equal(passesReleaseGate(run, jobs, sha), true)
  for (const changes of [{ head_sha: 'b'.repeat(40) }, { head_branch: 'other' }, { event: 'pull_request' },
    { conclusion: 'cancelled' }, { status: 'in_progress' }]) {
    assert.equal(passesReleaseGate({ ...run, ...changes }, jobs, sha), false)
  }
  for (let i = 0; i < jobs.length; i++) {
    assert.equal(passesReleaseGate(run, jobs.filter((_, j) => i !== j), sha), false)
    for (const conclusion of ['skipped', 'failure', 'cancelled', null]) {
      assert.equal(passesReleaseGate(run, jobs.map((job, j) => j === i ? { ...job, conclusion } : job), sha), false)
    }
    for (const status of ['queued', 'in_progress', undefined]) {
      assert.equal(passesReleaseGate(run, jobs.map((job, j) => j === i ? { ...job, status } : job), sha), false)
    }
  }
})
test('the accepted 27-job main layout includes both Windows versions and every module', () => {
  assert.equal(jobs.length, 27)
  assert.equal(fixture.sourceRun, 40161433310)
  assert.equal(passesReleaseGate({ ...run, head_sha: fixture.sourceCommit }, jobs, fixture.sourceCommit), true)
  assert.equal(passesReleaseGate({ ...run, event: 'workflow_dispatch' }, jobs, sha), true)
})
test('duplicate, unknown or additional jobs require a reviewed gate update', () => {
  assert.equal(passesReleaseGate(run, [...jobs, jobs[0]], sha), false)
  assert.equal(passesReleaseGate(run, [...jobs, { name: 'new-job', status: 'completed', conclusion: 'success' }], sha), false)
  assert.equal(passesReleaseGate(run, jobs.map((job, i) => i === 0 ? jobs[1] : job), sha), false)
  assert.equal(passesReleaseGate(run, jobs.map((job, i) => i === 0 ? { ...job, name: 'new-job' } : job), sha), false)
})
test('Windows-only successful dispatch cannot satisfy publication', () => {
  assert.equal(passesReleaseGate({ ...run, event: 'workflow_dispatch' },
    jobs.map(job => ({ ...job, conclusion: job.name.startsWith('windows-agent (') ? 'success' : 'skipped' })), sha), false)
})
test('legacy amd64-only CI cannot publish a multi-platform release', () => {
  const legacy = ['windows-agent', 'build-and-test', 'schema'].map(name => ({ name, status: 'completed', conclusion: 'success' }))
  assert.equal(passesReleaseGate(run, legacy, sha), false)
})
test('the old four-job multi-platform gate cannot publish the expanded release', () => {
  const old = ['windows-agent', 'build-and-test (amd64)', 'build-and-test (arm64)', 'schema']
    .map(name => ({ name, status: 'completed', conclusion: 'success' }))
  assert.equal(passesReleaseGate(run, old, sha), false)
})
test('publication downloads the three exact native artifacts without a Windows overwrite', () => {
  const workflow = readFileSync(new URL('../../.github/workflows/release.yml', import.meta.url), 'utf8')
  const downloads = [...workflow.matchAll(/uses: actions\/download-artifact@v4\n        with:\n([\s\S]*?)(?=\n      -)/g)]
    .map(match => match[1]).filter(input => input.includes('path: release/bin'))
  assert.equal(downloads.length, 3)
  assert.deepEqual(downloads.map(input => input.match(/^          name: (.+)$/m)?.[1]).sort(),
    ['agent-linux-amd64', 'agent-linux-arm64', 'agent-windows-amd64'])
  for (const input of downloads) {
    assert.ok(input.includes('run-id: ${{ needs.verify.outputs.ci-run }}'))
    assert.doesNotMatch(input, /pattern:|merge-multiple:/)
  }
})
test('release chooses a full successful run and fails when none exists', async () => {
  const github = { rest: { actions: { listWorkflowRuns: 'runs', listJobsForWorkflowRun: 'jobs' } },
    paginate: async (endpoint, args) => endpoint === 'runs' ? [{ ...run, id: 1 }, run] : args.run_id === 1 ? jobs.slice(0, 1) : jobs }
  assert.equal((await findValidatedRun(github, 'owner', 'repo', sha)).id, 123)
  github.paginate = async endpoint => endpoint === 'runs' ? [run] : jobs.slice(0, 1)
  await assert.rejects(findValidatedRun(github, 'owner', 'repo', sha), /No successful full CI/)
})
