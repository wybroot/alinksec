# Local validation constraints

- This machine has approximately 2 GiB of RAM. Avoid memory-heavy validation.
- Run validation scenarios serially. By default, run at most one validation
  container at a time and stop that container before starting the next scenario.
- Never start the complete Docker Compose stack or multiple test stacks together.
  Select the required service explicitly and prevent automatic dependency startup
  where the check does not require dependencies.
- If a check needs multiple services running together, first assess available
  memory and use the smallest required set, starting services sequentially.
- Run builds serially as well; do not overlap Docker builds, application builds,
  or integration tests.
- Prefer local builds and validation when the platform supports them. Use CI for
  other platforms or checks that still exceed safe local limits after tuning.
- Native build watchdogs may use a 384 MiB minimum available-memory threshold
  with a 256 MiB language heap and one build worker. Stop on full memory PSI
  above 10%; do not increase concurrency just because CPU load is low.
- Pause the application server before frontend bundling or race-test compilation.
  Native builds also need a resource watchdog; a language heap limit alone does
  not bound total process memory. Prefer Docker memory/CPU limits for heavy builds.
- If a full frontend build hits the watchdog, use the matching CI `web-dist`
  artifact. For browser checks, pause the backend and use a page-scoped preview
  with captured API responses. Do not repeatedly increase local memory limits.
- Check memory and swap before container validation. Swap is an emergency buffer,
  not a reason to increase concurrency. Stop validation if memory pressure rises.
- Stop containers created for a completed check; preserve existing user services
  and data volumes.

# Module development workflow

- Run independent CI jobs in parallel on separate GitHub runners when GitHub
  capacity permits. Do not apply this machine's serial validation limits across
  independent CI runners. Keep checks that share ports, containers or state
  ordered within one runner.

- The user authorized grouping adjacent, related backlog items on 2026-10-24.
  Develop modules 20/21 together, then modules 22/23 together, with one branch,
  review and complete CI validation per group. Preserve the remaining backlog.
- Create each group branch from the latest merged `main`. When its tree already
  matches the fully validated feature tree, development may proceed while the
  exact merged-main CI runs remotely. Track that pending acceptance explicitly
  and fix any failures before accepting the dependent group.
- Complete the group's functionality, system applicability, failure handling,
  security boundaries and validation together. Keep unrelated implementation
  outside the active group.
- Open a new pull request only after the group's implementation and required
  validation are complete. Keep an existing pull request in draft while its
  group is still being improved.
- After implementation and required validation are complete, merge the group PR
  into `main` under the user's standing instruction. Verify its merged source,
  start full merged-main CI and track acceptance. Synchronize canonical local
  `main` after those checks pass; the next group may proceed under the preceding
  rule while the exact merged-main checks run remotely.
- Do not base a group on an unmerged branch or stack its PR on an unmerged PR.
- Version releases and production deployments require separate user instructions;
  module merge authorization does not authorize either action.
