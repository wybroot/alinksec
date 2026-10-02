import assert from 'node:assert/strict'
import test from 'node:test'
import { findValidatedRun, passesReleaseGate } from '../release/ci-gate.mjs'

const sha = 'a'.repeat(40)
const run = { id: 123, head_sha: sha, head_branch: 'main', event: 'push', status: 'completed', conclusion: 'success' }
const jobs = ['windows-agent', 'build-and-test', 'schema'].map(name => ({ name, conclusion: 'success' }))
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
  }
})
test('Windows-only successful dispatch cannot satisfy publication', () => {
  assert.equal(passesReleaseGate({ ...run, event: 'workflow_dispatch' },
    jobs.map(job => ({ ...job, conclusion: job.name === 'windows-agent' ? 'success' : 'skipped' })), sha), false)
})
test('release chooses a full successful run and fails when none exists', async () => {
  const github = { rest: { actions: { listWorkflowRuns: 'runs', listJobsForWorkflowRun: 'jobs' } },
    paginate: async (endpoint, args) => endpoint === 'runs' ? [{ ...run, id: 1 }, run] : args.run_id === 1 ? jobs.slice(0, 1) : jobs }
  assert.equal((await findValidatedRun(github, 'owner', 'repo', sha)).id, 123)
  github.paginate = async endpoint => endpoint === 'runs' ? [run] : jobs.slice(0, 1)
  await assert.rejects(findValidatedRun(github, 'owner', 'repo', sha), /No successful full CI/)
})
