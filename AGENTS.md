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
- Check memory and swap before container validation. Swap is an emergency buffer,
  not a reason to increase concurrency. Stop validation if memory pressure rises.
- Stop containers created for a completed check; preserve existing user services
  and data volumes.
