# Deployment Validation

Run checks serially on low-memory machines. Build the server before starting API
validation, and stop one scenario before starting another.

## Native Windows Service

On a disposable Windows host, run in `agent/` with administrator permissions:

```powershell
go build -o alinksec-agent-windows-amd64.exe ./cmd/agent
$env:ALINKSEC_SMOKE_ALLOW_FIXTURES = 'true'
$env:ALINKSEC_SMOKE_AGENT_BIN = (Resolve-Path .\alinksec-agent-windows-amd64.exe).Path
go test -v -count=1 -timeout=4m -run '^TestNativeWindowsService$' ./cmd/agent
```

The test refuses to replace an existing `alinksec-agent` service. It copies the
actual executable to a path containing spaces, enrolls it against a loopback
gRPC fixture with a temporary CA, and starts it through Windows SCM. It verifies
mTLS heartbeats, native software/process/account assets, a software collection
command and ACK, SCM interrogation, successful stop/start, automatic recovery
after the Agent RESTART command, retained certificates, and no recovery after
an explicit service stop. Decoy and active-response rules remain disabled.

The fixture implements the Agent protocol; it is not the Java platform, and this
check does not claim a complete Windows security-engine acceptance. On exit the
test disables recovery, stops and deletes its service, closes the TLS listener,
and removes temporary files. Ordinary `go test` runs skip the integration unless
fixture writes are explicitly enabled. The Windows CI job runs it against the
native executable; Linux hosts can only cross-compile this test.

Pure Markdown pushes skip CI; pull requests continue to run validation.
For a Windows-only change, `gh workflow run CI -f windows_only=true` executes
only the native Windows checks. Normal push and pull-request runs keep all jobs.

## Local SQLite

Requires Bash, Java 21, Node.js 22.22 or later, and `flock`. After `mvn -B package`
in `server/`, run from the repository root:

```sh
bash deploy/tests/api-smoke-local.sh
```

Set `JAVA_BIN` to an absolute Java executable path if it is not on `PATH`.
The script starts one local server with a 256 MiB heap and a fresh SQLite database,
runs the API contracts serially, and stops the server on exit. It starts no Docker
containers. Successful runs remove their temporary data; failures keep logs and
data under `.tmp/`. A lock prevents concurrent local runs.

## Compose API Contracts

CI runs the same eight API contracts against disposable PostgreSQL and SQLite
deployments over HTTPS. Required environment variables:

| Variable | Value |
| --- | --- |
| `ALINKSEC_SMOKE_DB` | `postgres` or `sqlite` |
| `ALINKSEC_SMOKE_ALLOW_FIXTURES` | `true`, explicitly allowing fixture writes |
| `ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD` | The disposable deployment's admin password |
| `ALINKSEC_SMOKE_CA_FILE` | Path to the deployment's platform CA certificate |
| `ALINKSEC_SMOKE_ENV_FILE` | Optional Compose env file, including a custom project name |
| `ALINKSEC_SMOKE_BASE_URL` | Optional API URL; defaults to `https://127.0.0.1:8443` |

```sh
node --test --test-concurrency=1 deploy/tests/api-smoke.test.mjs
```

Use a fresh database without existing findings. Reserved `ci-smoke-*` fixtures
are checked before insertion and removed afterward. Plain HTTP is accepted only
on loopback addresses for local validation. `ALINKSEC_SMOKE_SQLITE_FILE` allows
direct access to a local SQLite file without maintenance containers.

## Agent TLS Identity

`AgentChannelSecurityIntegrationTest` starts the production gRPC server on an
ephemeral port with temporary certificates. It enrolls clients over TLS, uses
their issued certificates for mTLS streams, and verifies database state after
cross-agent asset reports and ACKs. It also checks anonymous connections,
disabled/deleted identities, normal command completion, and isolation ACKs.
It sends protocol messages without executing host firewall commands.

The default `mvn -B package` runs these checks against a temporary SQLite database
without containers. To check PostgreSQL, first migrate a disposable database and
set `ALINKSEC_INTEGRATION_PG_URL`, `ALINKSEC_INTEGRATION_PG_USER`, and
`ALINKSEC_INTEGRATION_PG_PASSWORD` to its JDBC URL and application role credentials.
Then run in `server/`:

```sh
mvn -B -T1 -pl alinksec-bootstrap -am \
  -Dtest=AgentChannelSecurityIntegrationTest \
  -Dsurefire.failIfNoSpecifiedTests=false \
  -Dalinksec.integration.database=postgres test
```

Run only one database scenario at a time. PostgreSQL checks insert and remove
their own random agent/token/report fixtures; use a disposable test deployment.

## Standalone Server Image

Build the server image before starting its validation container. The Dockerfile
uses BuildKit's Maven dependency cache, a 320 MiB Maven heap, and one build thread.
On Docker/buildx versions supporting `--resource`, run from the repository root:

```sh
docker build --resource memory=896m --resource memory-swap=1280m \
  --resource cpu-quota=100000 -f deploy/docker/Dockerfile.server \
  -t alinksec-server-validation .
ALINKSEC_SMOKE_SERVER_IMAGE=alinksec-server-validation \
  bash deploy/tests/server-image-smoke.sh
```

Requires Docker, Bash, `flock`, and Node.js 22.22 or later. The script uses one
server container with SQLite, a 512 MiB memory limit, one CPU, and a 256 MiB JVM
heap. Published HTTP and gRPC ports use random loopback bindings. The data bind
mount is temporary, and the container runs as the host user so fixture writes
also work on CI runners without root-owned database files.

Checks include the eight shared API contracts, a CA-verified gRPC TLS handshake,
certificate SANs, leaf-only web TLS files, and restart persistence of assets,
isolation state, migration history, certificates, and JWT validity. The restart
check reloads Docker's port mappings because ephemeral host ports can change.
It verifies persisted isolation state without executing a host firewall action.

The script shares the local API validation lock, stops its container on exit,
and removes successful runs' data. Failures retain logs and data under `.tmp/`.
CI runs it after image builds and before starting the full deployment.

## Standalone Web Image

Build the web image serially, with no validation server running. The Dockerfile
uses a locked npm dependency cache, a 384 MiB installation heap, and a 768 MiB
Vite build heap. On Docker/buildx versions supporting `--resource`:

```sh
docker build --resource memory=896m --resource memory-swap=1280m \
  --resource cpu-quota=100000 -f deploy/docker/Dockerfile.web \
  -t alinksec-web-validation .
ALINKSEC_SMOKE_WEB_IMAGE=alinksec-web-validation \
  bash deploy/tests/web-image-smoke.sh
```

Requires a local Linux Docker engine with an IPv4 bridge, Bash, Java 21, `flock`,
Node.js 22.22 or later, and the packaged server JAR. Set `JAVA_BIN` if Java is not
on `PATH`. Bridge port 8080 must be available. The production Nginx template
defaults to `server:8080` and refreshes Docker DNS every five seconds; this native
server check sets `ALINKSEC_BACKEND_HOST` to the bridge address.

The script starts one native SQLite server with a 256 MiB heap, bound to Docker's
bridge address, and one 96 MiB Nginx container with one CPU and worker autotuning.
It uses the production image, configuration, and generated leaf certificate;
HTTPS and redirect ports are published only on random loopback ports. No server,
database, or maintenance container is started.

Checks cover trusted and untrusted CA connections, a mismatched certificate host,
TLS 1.2/1.3, HTTP redirects, security headers, SPA route fallback, every generated
asset and its cache/content type, missing asset 404s, and the screen's map JSON.
The eight shared API contracts then run through the HTTPS reverse proxy,
including login, JWT access, role permissions, and audit redaction.

The shared local validation lock prevents overlapping scenarios. The script
stops both processes and removes temporary data on success; failures retain
server/Nginx logs and data under `.tmp/`. CI runs this check after image builds
and the standalone server check. Set `ALINKSEC_SMOKE_BROWSER=true` to also run
the actual browser workflow below. Full Compose wiring is checked separately
on the CI runner.

## Maintenance Failures

```sh
bash deploy/tests/sqlite-maintenance.test.sh
```

This check simulates backup, restore, and rollback failures without starting
containers or changing a deployment.

## Real SQLite Maintenance

After packaging the server, run serially:

```sh
docker build --resource memory=512m --resource memory-swap=768m \
  --resource cpu-quota=100000 -f deploy/docker/Dockerfile.sqlite-maintenance \
  -t alinksec-sqlite-maintenance:latest .
ALINKSEC_MAINTENANCE_TEST_ALLOW_FIXTURES=true \
  bash deploy/tests/sqlite-maintenance-local.sh
```

Requires a local Linux Docker engine, Compose, Bash, Java 21, `flock`, and Node.js
22.22 or later. Set `JAVA_BIN` if Java is not on `PATH`. The script extracts the
production maintenance service into a random temporary project with bind-mounted
fixture directories. It never starts the full deployment or touches its volumes.
A native SQLite server uses a 256 MiB heap; tool containers run serially with
64 MiB memory, 96 MiB memory plus swap, and one CPU. A shared lock excludes other
local validation scenarios.
Default capabilities are dropped; only `DAC_OVERRIDE` is added so the root CLI
can access private backup directories owned by a different host UID.

The six checks cover the configured CLI/volume user, online `VACUUM INTO` backup
of committed WAL data, duplicate/unsafe/missing/corrupt backup rejection, CLI
restore followed by a real server restart, startup refusal for an incompatible
migration checksum followed by recovery from a safety snapshot, and all eight
shared API contracts after recovery. Backup, verification, and corrupt-restore
rejection invoke `deploy/sqlite-maintenance.sh` itself.

Successful CLI restores and safety recovery coordinate the native process
directly. Automatic Compose stop/start and rollback remain covered by the
13 simulated workflow cases and the separate full-deployment CI check.

The production image is built from checksum-pinned official SQLite 3.46.1 sources
with a static CLI and no shell or network tools. Build it before running checks.
The build defaults to the Aliyun Alpine mirror; set
`--build-arg ALPINE_MIRROR=dl-cdn.alpinelinux.org` to use the official mirror,
as the CI runner does.
`ALINKSEC_MAINTENANCE_TEST_IMAGE` can select a controlled alternative; the script
checks the CLI version and prints the selected image. CI builds and tests the
production image. Containers and Java are stopped on exit, successful
runs delete fixture data, and failures retain logs/data under `.tmp/`.

## PostgreSQL Migrations

```sh
ALINKSEC_MIGRATION_TEST_ALLOW_FIXTURES=true \
  bash deploy/tests/postgres-migrations.test.sh
```

Requires Bash, `psql`, `pg_dump`, `pg_restore`, and connection variables `PGHOST`,
`PGDATABASE`, `PGUSER`, and `PGPASSWORD`. The owner must be able to create databases
and roles. Use a disposable PostgreSQL instance and backup tools compatible with
its server version. The script starts no containers; CI executes it inside its
existing PostgreSQL 17 service so that client and server versions match.

The 13 checks cover missing/empty migration directories, rejected bootstrap SQL,
38-table initialization, a simulated legacy upgrade, repeat execution, minimum
application privileges, transaction rollback, changed/missing released files,
CRLF checksum normalization, and legacy backup restore followed by upgrade.
The legacy schema is a fixture derived from the current bootstrap; it is not a
backup of a published previous release.

Randomly named databases and an application role isolate all fixture writes from
the connection database. They are removed on exit, and cleanup failures fail the
check. Failed runs retain logs and the temporary backup under the executing
host/container's `/tmp/`; successful runs remove them. Run serially and use at
most one PostgreSQL validation container with a 256 MiB memory limit.

## Actual Agent Workflows

Build the real Agent and its disposable Linux fixture image serially:

```sh
mkdir -p .tmp
(cd agent && CGO_ENABLED=0 go build -o ../.tmp/alinksec-agent-validation ./cmd/agent)
docker build --resource memory=512m --resource memory-swap=768m \
  --resource cpu-quota=100000 -f deploy/tests/fixtures/Dockerfile.agent \
  -t alinksec-agent-validation .
ALINKSEC_SMOKE_ALLOW_FIXTURES=true \
  ALINKSEC_SMOKE_AGENT_BIN=.tmp/alinksec-agent-validation \
  bash deploy/tests/agent-workflow-local.sh
ALINKSEC_SMOKE_ALLOW_FIXTURES=true bash deploy/tests/firewall-local.sh
```

The Agent check runs a native Java server and one 256 MiB Agent container at a
time. Two Agents enroll using TLS and issued mTLS identities, apply policy
changes, install approved CA-verified packages, and complete the correct
findings, including commands queued while offline. Isolation uses actual
iptables inside the container and preserves the platform channel through
Agent/server restarts. SAN/CA recovery rejects old trust before re-enrollment.
The same Agent also verifies file change alerts, permission-preserving restoration,
deletion and symlink replacement, persistent baselines, approved file changes,
SSH thresholds and exceptions, off-hours login alerts, actual SSH-port firewall
rules, restart persistence, automatic expiry and allowlist release.
Fixture hardware identities and all writable state belong to the temporary
scenario. Only test containers receive `NET_ADMIN`; host firewall rules,
production volumes, and other services are not changed.
Protected Agent state and CA files are read inside the container, keeping their
private file permissions compatible with a non-root host runner. After all
Agents and the server stop, one isolated 64 MiB container removes only the
scenario's Agent work directories before the host removes the remaining fixtures.

The separate 64 MiB firewall check applies the production script to an isolated
container chain. Real DNAT traffic verifies original destination ports,
management/Agent source restrictions, established connections, unrelated ports,
idempotence, and removal. The chain is attached to the container INPUT hook;
the host's Docker FORWARD/DOCKER-USER wiring must also be checked at deployment.

## Browser Workflows

Protection configuration checks cover file paths, SSH thresholds, response mode,
block duration, save/refresh persistence, numeric control accessibility and mobile
layout. CI retains the full production bundle as `web-dist` for seven days. On
very small machines, validate the protection page with the backend paused and
captured API responses, then use the successful matching commit's CI bundle;
keep full-build and real-API browser checks on CI when local resource limits stop
them.

After `npm ci` in `web/`, install the browser once with
`npx playwright install --with-deps --only-shell chromium`. Then run:

```sh
ALINKSEC_SMOKE_WEB_IMAGE=alinksec-web-validation \
  ALINKSEC_SMOKE_BROWSER=true bash deploy/tests/web-image-smoke.sh
```

This uses the production HTTPS proxy, actual login, 105-host pagination and
later-page collection, single/batch repair approval requests, persisted rule
toggles, target versions and repair rates. Dashboard, host detail, and screen
canvases must contain nonblank pixels. Malicious labels are checked in a visible
tooltip. Desktop/mobile screenshots and result JSON remain under
`.tmp/browser-artifacts-*`. The browser pins only the scenario's leaf public
key; the preceding HTTP checks verify its CA and reject wrong CA/hostname.

## Serial Release Checks

`release-validation.sh` runs the local gates in dependency order, including
two fresh source snapshots, a version change, clean images, their startup and
restart, actual Agents, firewall, browser, and maintenance. It checks available
memory, rejects concurrent validation containers, and records each completed
step under `.tmp/release-validation.*`. It never starts the full Compose stack.
Guard race detection requires a C compiler and runs before the Agent build.

```sh
ALINKSEC_SMOKE_ALLOW_FIXTURES=true \
  bash deploy/tests/postgres-validation-local.sh
node --test --test-concurrency=1 deploy/tests/deployment-config.test.mjs
bash deploy/tests/release-validation.sh
```

Set `JAVA_BIN`, `MAVEN_BIN`, `GO_BIN`, `ALINKSEC_MAVEN_REPO`, and
`ALINKSEC_SMOKE_POSTGRES_IMAGE` when local tools or cached images use custom
paths. The PostgreSQL wrapper uses one 256 MiB database container and runs
migration/permission, mTLS, and API checks before removing it. A formal backup
from the previous supported release and successful remote CI remain separate
release requirements.
