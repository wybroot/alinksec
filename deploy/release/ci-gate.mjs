const required = ['windows-agent', 'build-and-test', 'schema']

export function passesReleaseGate(run, jobs, sha) {
  return run.head_sha === sha && run.head_branch === 'main' &&
    ['push', 'workflow_dispatch'].includes(run.event) && run.status === 'completed' &&
    run.conclusion === 'success' && required.every(name =>
      jobs.some(job => job.name === name && job.conclusion === 'success'))
}

export async function findValidatedRun(github, owner, repo, sha) {
  const runs = await github.paginate(github.rest.actions.listWorkflowRuns, {
    owner, repo, workflow_id: 'ci.yml', head_sha: sha, status: 'success', per_page: 100,
  })
  for (const run of runs) {
    const jobs = await github.paginate(github.rest.actions.listJobsForWorkflowRun, {
      owner, repo, run_id: run.id, filter: 'latest', per_page: 100,
    })
    if (passesReleaseGate(run, jobs, sha)) return run
  }
  throw new Error(`No successful full CI for ${sha}. All three jobs must pass on main; Windows-only CI cannot release.`)
}
