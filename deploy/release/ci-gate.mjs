export const requiredJobs = Object.freeze([
  'cluster (amd64)', 'cluster (arm64)', 'scap-resolver',
  'native-scap (ubuntu-24.04, linux-amd64)', 'native-scap (ubuntu-24.04-arm, linux-arm64)',
  'native-scap (windows-latest, windows-amd64)',
  'windows-agent (windows-2025)', 'windows-agent (windows-2022)',
  'build-and-test (amd64)', 'build-and-test (arm64)',
  'system-acceptance (amd64)', 'system-acceptance (arm64)',
  'linux-native (amd64)', 'linux-native (arm64)',
  'sqlite-maintenance (amd64)', 'sqlite-maintenance (arm64)',
  'deployment (amd64)', 'deployment (arm64)',
  'native-yara (linux-amd64)', 'native-yara (linux-arm64)', 'native-yara (windows-amd64)',
  'schema', 'baseline-upstream', 'vendor-advisories', 'opencti-native', 'source-trust', 'reporting',
])

export function passesReleaseGate(run, jobs, sha) {
  return run.head_sha === sha && run.head_branch === 'main' &&
    ['push', 'workflow_dispatch'].includes(run.event) && run.status === 'completed' &&
    run.conclusion === 'success' && jobs.length === requiredJobs.length &&
    requiredJobs.every(name => {
      const matching = jobs.filter(job => job.name === name)
      return matching.length === 1 && matching[0].status === 'completed' && matching[0].conclusion === 'success'
    })
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
  throw new Error(`No successful full CI for ${sha}. All ${requiredJobs.length} required jobs must complete successfully on main; partial or outdated CI cannot release.`)
}
