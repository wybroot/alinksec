#!/usr/bin/env bash
set -Eeuo pipefail
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
cd "$repo_dir"
for command in docker node npm flock; do command -v "$command" >/dev/null; done
export JAVA_BIN="$(realpath "$(command -v "${JAVA_BIN:-java}")")"
export MAVEN_BIN="$(realpath "$(command -v "${MAVEN_BIN:-mvn}")")"
go_bin="$(realpath "$(command -v "${GO_BIN:-go}")")"
export JAVA_HOME="$(dirname "$(dirname "$JAVA_BIN")")"
export ALINKSEC_SMOKE_ALLOW_FIXTURES=true
export ALINKSEC_MAINTENANCE_TEST_ALLOW_FIXTURES=true
export ALINKSEC_SMOKE_AGENT_BIN="$repo_dir/.tmp/alinksec-agent-validation"
export ALINKSEC_SMOKE_SERVER_IMAGE=alinksec-server-validation
export ALINKSEC_SMOKE_WEB_IMAGE=alinksec-web-validation
export ALINKSEC_SMOKE_BROWSER=true
export ALINKSEC_SMOKE_AGENT_IMAGE=alinksec-agent-validation
export ALINKSEC_SQLITE_MAINTENANCE_IMAGE=alinksec-sqlite-maintenance:latest
mkdir -p "$repo_dir/.tmp"
exec 8>"$repo_dir/.tmp/release-validation.lock"
flock -n 8 || { echo 'Another release validation is already running.' >&2; exit 1; }
artifacts="$(mktemp -d "$repo_dir/.tmp/release-validation.XXXXXX")"
printf 'Validation artifacts: %s\n' "$artifacts"
trap 'printf "Validation stopped; completed steps: %s\n" "$artifacts/completed.log" >&2' ERR

check_memory() {
  local required=$1 available
  available=$(awk '/MemAvailable:/ { print int($2 / 1024) }' /proc/meminfo)
  if ((available < required)); then
    printf 'Available memory %s MiB is below required %s MiB. Validation stopped.\n' "$available" "$required" >&2
    exit 1
  fi
  [[ -z "$(docker ps -q)" ]] || { echo 'Stop other validation scenarios before continuing.' >&2; exit 1; }
}
step() {
  local label=$1
  shift
  printf '\nRunning: %s\n' "$label"
  "$@"
  printf '%s\n' "$label" >>"$artifacts/completed.log"
}
build_image() {
  local dockerfile=$1 image=$2 context=$3 memory=${4:-896}
  check_memory 1024
  flock -n "$repo_dir/.tmp/api-smoke-local.lock" \
    docker build --resource "memory=${memory}m" --resource "memory-swap=$((memory + 384))m" \
      --resource cpu-quota=100000 --no-cache -f "$dockerfile" -t "$image" "$context"
}

check_memory 1024
step 'Deployment configuration, port bindings and profiles' node --test --test-concurrency=1 "$script_dir/deployment-config.test.mjs"
maven_args=(-B -ntp -T1 -f server/pom.xml '-DargLine=-Xmx192m -XX:MaxMetaspaceSize=128m -XX:ActiveProcessorCount=1')
if [[ -n "${ALINKSEC_MAVEN_REPO:-}" ]]; then maven_args+=("-Dmaven.repo.local=$ALINKSEC_MAVEN_REPO"); fi
step 'Server tests and package' env MAVEN_OPTS='-Xmx256m -XX:MaxMetaspaceSize=128m -XX:ActiveProcessorCount=1' "$MAVEN_BIN" "${maven_args[@]}" package
step 'SQLite API contracts' bash "$script_dir/api-smoke-local.sh"
check_memory 896
step 'PostgreSQL migration, permissions, mTLS and API' bash "$script_dir/postgres-validation-local.sh"
check_memory 1024
step 'Agent tests' env GOMAXPROCS=1 GOMEMLIMIT=256MiB GOFLAGS=-p=1 "$go_bin" -C agent test ./...
step 'Guard policy race detection' env GOMAXPROCS=1 GOMEMLIMIT=256MiB GOFLAGS=-p=1 "$go_bin" -C agent test -race ./internal/guard
step 'Agent binary' env GOMAXPROCS=1 GOMEMLIMIT=256MiB GOFLAGS=-p=1 CGO_ENABLED=0 "$go_bin" -C agent build -o "$ALINKSEC_SMOKE_AGENT_BIN" ./cmd/agent
step 'Web dependency installation' env NODE_OPTIONS=--max-old-space-size=384 npm --prefix web ci --cache "$repo_dir/.tmp/npm-cache"
step 'Web tests' npm --prefix web test
step 'Web production dependency audit' npm --prefix web audit --omit=dev --registry=https://registry.npmjs.org
step 'Browser installation' env PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$repo_dir/.tmp/playwright}" npm --prefix web exec -- playwright install --only-shell chromium
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-$repo_dir/.tmp/playwright}"

mkdir -p "$artifacts/source-first" "$artifacts/source-second"
step 'Fresh first source snapshot' node "$script_dir/snapshot-source.mjs" "$artifacts/source-first"
step 'Fresh second source snapshot' node "$script_dir/snapshot-source.mjs" "$artifacts/source-second"
step 'Changed-version snapshot' "$JAVA_BIN" -Xmx128m "$script_dir/ChangeSnapshotVersion.java" "$artifacts/source-second" 0.1.1-VALIDATION
step 'First clean server image' build_image deploy/docker/Dockerfile.server "$ALINKSEC_SMOKE_SERVER_IMAGE" "$artifacts/source-first"
step 'First server image startup and restart' bash "$script_dir/server-image-smoke.sh"
step 'Second clean server image with changed version' build_image deploy/docker/Dockerfile.server "$ALINKSEC_SMOKE_SERVER_IMAGE" "$artifacts/source-second"
step 'Changed-version server image startup and restart' bash "$script_dir/server-image-smoke.sh"
step 'Production SQLite maintenance image' build_image deploy/docker/Dockerfile.sqlite-maintenance alinksec-sqlite-maintenance:latest "$repo_dir" 512
step 'Actual Agent fixture image' build_image deploy/tests/fixtures/Dockerfile.agent "$ALINKSEC_SMOKE_AGENT_IMAGE" "$repo_dir" 512
step 'Actual Agent policy, repair, isolation and TLS recovery' bash "$script_dir/agent-workflow-local.sh"
step 'Isolated production source firewall' bash "$script_dir/firewall-local.sh"
step 'Web production image' build_image deploy/docker/Dockerfile.web "$ALINKSEC_SMOKE_WEB_IMAGE" "$repo_dir"
step 'Browser workflows, charts and HTTPS proxy' bash "$script_dir/web-image-smoke.sh"
step 'Real SQLite maintenance and recovery' bash "$script_dir/sqlite-maintenance-local.sh"
step 'Maintenance failure handling' bash "$script_dir/sqlite-maintenance.test.sh"
step 'Diff whitespace' git diff --check
printf '\nLocal validation completed: %s\n' "$artifacts/completed.log"
printf 'Release publication also requires the matching full CI and release workflow.\n'
