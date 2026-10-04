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

- Complete one functional module on its own branch before moving to another.
- Stay on that module's branch while completing its functionality, system
  applicability, failure handling, security boundaries, and validation.
- Record other modules as ordered backlog items; do not begin their
  implementation during the active module's work.
- Open a new pull request only after the module's implementation and required
  validation are complete. Keep an existing pull request in draft while its
  module is still being improved.
- Defer merges and version releases until the user instructs proceeding after
  the planned functionality is complete.
