# Deployment Validation

Release target: v0.0.2, adding Linux ARM64 to the earlier
v0.0.1 amd64 release. Publication requires `windows-agent`,
`build-and-test (amd64)`, `build-and-test (arm64)` and `schema` to pass on the
exact tagged main commit. It reuses all three tested native Agents, builds and
smoke-tests containers serially on each native architecture, then merges the
tested digests into multi-platform component tags and publishes GitHub assets.
See [release process](../../docs/13-版本发布流程.md).

```sh
node deploy/release/check-version.mjs v0.0.2
node --test --test-concurrency=1 deploy/tests/release-*.test.mjs
```

`check-version.mjs` needs Java 21 and Docker Compose; it starts no containers.
It parses Maven XML and npm JSON and checks product versions and image defaults.
The release gate tests reject mismatched commits, failed or skipped jobs and
successful Windows-only or legacy amd64-only runs. Platform tests reject
mislabeled binaries, images from the wrong commit and incomplete image indexes.
CI keeps tested native binary artifacts for 14 days. See the
[ARM64 guide](../../docs/14-ARM64支持.md) for source builds and native CI coverage.

Source validation uses local image overrides `ALINKSEC_SERVER_IMAGE`,
`ALINKSEC_WEB_IMAGE` and `ALINKSEC_SQLITE_MAINTENANCE_IMAGE`; production Compose
defaults to component tags for `VERSION`, which must be published before pulling.
When testing a locally built maintenance image, set
`ALINKSEC_SQLITE_MAINTENANCE_IMAGE=alinksec-sqlite-maintenance:latest`.

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

## Security Libraries

`LibraryIntegrationTest` uses a temporary SQLite database and local HTTP fixtures
to check manual/remote merging, malformed imports, transactional rollback,
conditional requests, provider adapters (including native MISP), persistent console
schedules, retry delays, interrupted-run recovery, bounded history, retention and signed S3 operations.
The worker checks also cover duplicate requests, pausing during a download and
retrying after failure, using a gated HTTP fixture without external services.
It does not require provider credentials or access production feeds or buckets.
Run serially from `server/`:

```sh
mvn -B -T1 -pl alinksec-bootstrap -am -DforkCount=0 \
  -Dtest=LibraryIntegrationTest,SqliteDatabaseIntegrationTest,VulnMatchServiceTest,JwtAuthInterceptorTest \
  -Dsurefire.failIfNoSpecifiedTests=false test
```

See [security library configuration](../../docs/15-安全库同步与存储.md) for
production source credentials, capacity limits and matching boundaries.

The portable MISP bridge/package checks use local fixtures and a simulated curl,
with no provider credentials, server build or containers:

```sh
python3 -B -m unittest discover -s deploy/tests -p 'test_library_feed_tools.py' -v
bash -n deploy/libraries/refresh-misp.sh
```

They verify package compatibility, complete snapshots, deduplication, stable
publication, bounded inputs and preservation of the previous file on failures.
See [open-source platform integration](../../docs/16-开源安全平台对接指南.md)
for the MISP workflow and the remaining OpenCTI/Vulnerability-Lookup adapter work.

After building the production frontend, CI runs `node test/libraries-browser.mjs`
from `web/`. It serves the bundle on loopback and replays captured disposable
PostgreSQL responses to exercise schedule edits, rejected saves/reset, execution history, role
visibility and desktop/mobile layout. Screenshots and results are saved in
`.tmp/library-browser-artifacts`. This complements backend tests; it does not
claim to connect to a production MISP instance.

On small machines, the same script accepts `ALINKSEC_LIBRARY_PREVIEW_DIST` pointing
to a page-scoped preview built from the current source. Pause the backend and run
under the local memory watchdog. Preview results go to
`.tmp/library-preview-artifacts` and are labelled separately from the production
bundle check. If memory pressure stops the browser, leave that check for CI;
do not increase local limits or count the interrupted run as a pass.

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
layout. CI retains the full production bundle as `web-dist-amd64` and
`web-dist-arm64` for seven days. On
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
migration/permission, mTLS, and API checks before removing it. Publication also
requires successful full CI on the exact release commit and the Release workflow.

## Isolated PAM checks

Build `.tmp/pam-native.test` from `agent/internal/baseline` with `go test -c`, then run `bash deploy/tests/pam-password-native.sh`. The dedicated Ubuntu24 image serially checks actual password changes and login authentication, including lockout thresholds, consecutive-failure reset, root behavior, finite unlock and bypass controls. Never run these native mutation tests against host PAM: the wrapper mounts source read-only, uses no network or data volumes, and removes the container. Both Linux architectures must execute the tests in CI; ordinary test skips are not acceptance. Production checks read only the fixed service configurations. See [login check scope](../../docs/24-PAM登录失败锁定核查.md).

## Native systemd observations

`systemd-native.sh`同时成组执行维护候选的十三次原生状态对照与只读C时钟探针。仅唯一运行时timer/service，清理timer在六小时后且120秒测试预算内清理，不触发真实清理；唯一通知型sleep不能冒充timesyncd，真实时间服务仅只读观察，不改时钟。busctl带类型ExecStart保留argv边界，强制结构/整数/变化/截止时间不跳过。完整同步/不同步组合为标注的协议夹具，参考边界见[systemd维护说明](../../docs/40-systemd清理调度与内核同步指示核查.md)。

`bash deploy/tests/systemd-native.sh` requires a disposable GitHub-hosted Ubuntu24 runner and the compiled `.tmp/baseline-native.test`. It serially creates one unique test service, verifies running/inactive/failed/exited/masked/missing/invalid states and ignored client environment redirects, and cleans up that unit. Existing auditd/rsyslog units are queried read-only; these observations do not assert event capture or log delivery. Both architectures must execute this opt-in test in CI, not merely skip it in ordinary Go tests. Do not enable mutation fixtures on a user host. See [check scope](../../docs/25-systemd服务状态核查.md).

`bash deploy/tests/auditd-native.sh` uses one disposable Ubuntu24 container, drops all capabilities, disables networking and mounts the repository read-only. The real auditd 3.1.2 parser accepts or rejects private disk configuration; after valid parsing, audit-control denial prevents daemon registration. This validates configuration parsing and private log metadata, without proving daemon operation or log delivery. Duplicate/long-line inputs remain Agent errors even when the native parser accepts them. See [on-disk scope](../../docs/28-auditd磁盘配置与日志目标核查.md).

`sudoers-native.sh` 在精确Ubuntu24 sudo包的隔离容器中，用原生visudo/cvtsudoers对照16组有限声明语义。工作区只读、网络关闭、capabilities为零，访问/默认ACL边界必跑；不执行提权命令，不把磁盘声明当实际授权、认证或日志交付。详见 [sudoers核查范围](../../docs/31-sudoers磁盘策略核查.md)。

`systemd-native.sh` 在临时 Ubuntu24 GitHub-hosted runner 串行验证服务观察和当前 Ctrl-Alt-Del 两条管理器路径。唯一无依赖 target 与唯一运行时管理器片段完整清理并核对原 burst 值；真实特殊目标仅只读查询，不触发按键、信号或关机。范围见 [Ctrl-Alt-Del核查](../../docs/34-Ctrl-Alt-Del当前systemd策略核查.md)。

PAM隔离验证同时成组覆盖core/nofile/nproc声明和实际getrlimit/普通文件与fork拒绝，含root nproc例外；只在专用无宿主/etc挂载的Ubuntu24镜像打开会话。生产候选仍为只读声明观察，范围见 [PAM会话资源限制](../../docs/35-PAM会话资源限制核查.md)。

OpenSSH名称解析/横幅批次：CI的`Check native OpenSSH name resolution and banner declarations with mandatory input boundaries`以root执行`TestNativeSSHNotice`，需`ALINKSEC_SSH_NOTICE_NATIVE_REQUIRED=true`和Ubuntu24精确OpenSSH9.6包。六组/十次原生比较，必须执行数值UID/GID、ACL、链接/FIFO、有限Include及变化/截止时间边界，不能跳过。仅临时主机密钥/配置、实际固定选择器只读，无监听/认证/宿主配置变更。SQLite/PostgreSQL REST保留两项完整快照和三种结果阶段，页面增加三张桌面/手机图；报告为协议夹具。范围见[核查说明](../../docs/36-OpenSSH名称解析与横幅声明核查.md)。

`bash deploy/tests/ipv4-host-native.sh`依次创建九个独立Docker网络命名空间，退出或异常均清理本场景容器。Docker先设全局值，runner子进程确认目标与宿主命名空间不同后，仅以nsenter进入容器网络命名空间顺序准备局部值，避免全局写入重置和OCI映射顺序；容器/proc/sys保持只读。NET_ADMIN仅用于创建两个未启用dummy接口（含点名称）；每场景128MiB/一个CPU，容器无SYS_ADMIN、privileged或host网络、宿主/etc及数据卷。编译`.tmp/baseline-native.test`后运行，root、双开关和隔离镜像标记缺一拒绝测试角色写入。原生对照覆盖max(all,interface)、default继承、全部接口及局部/全局转发，强制角色可信性、ACL、输入上限/变化/共同截止时间不允许跳过。完整REST/页面报告是协议夹具，实际数据包强制未验证，见[IPv4主机范围](../../docs/39-IPv4主机角色与全部接口当前参考核查.md)。
