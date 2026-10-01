#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
image="${ALINKSEC_SMOKE_SERVER_IMAGE:?Set ALINKSEC_SMOKE_SERVER_IMAGE to the built server image}"
for command in docker node flock; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done
docker image inspect "$image" >/dev/null
mkdir -p "$repo_dir/.tmp"
exec 9>"$repo_dir/.tmp/api-smoke-local.lock"
flock -n 9 || { echo 'Another local API validation is already running.' >&2; exit 1; }

test_root="$(mktemp -d "$repo_dir/.tmp/server-image-smoke.XXXXXX")"
container_name="alinksec-image-smoke-${BASHPID}-${RANDOM}"
container_id=''
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$container_id" ]]; then
    docker logs "$container_id" >"$test_root/server.log" 2>&1 || true
    docker stop --timeout 15 "$container_id" >/dev/null || status=1
  fi
  if ((status != 0)); then
    if [[ -f "$test_root/server.log" ]]; then
      tail -n 100 "$test_root/server.log" >&2
    fi
    printf 'Validation artifacts: %s\n' "$test_root" >&2
  else
    rm -rf -- "$test_root"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir -p "$test_root/data"
container_id="$(docker run --detach --rm --init --name "$container_name" \
  --memory=512m --memory-swap=768m --cpus=1 --pids-limit=128 \
  --user "$(id -u):$(id -g)" \
  --mount "type=bind,src=$test_root/data,dst=/app/data" \
  --publish 127.0.0.1::8080 --publish 127.0.0.1::9443 \
  --env SPRING_PROFILES_ACTIVE=sqlite --env ALINKSEC_METRICS_ENABLED=false \
  --env ALINKSEC_SQLITE_PATH=/app/data/alinksec.db \
  --env ALINKSEC_WEB_TLS_DIR=/app/data/web-tls \
  --env ALINKSEC_PUBLIC_HOST=ci.alinksec.test \
  --env ALINKSEC_SERVER_TLS_SANS=localhost,127.0.0.1,ci.alinksec.test \
  --env ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD=image-smoke-admin-password \
  --env ALINKSEC_BOOTSTRAP_ENROLL_TOKEN=ENROLL-image-smoke \
  --env 'JAVA_TOOL_OPTIONS=-Xmx256m -XX:MaxMetaspaceSize=128m -XX:ActiveProcessorCount=1' \
  "$image")"
http_port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "8080/tcp") 0).HostPort}}' "$container_id")"
grpc_port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "9443/tcp") 0).HostPort}}' "$container_id")"

env ALINKSEC_SMOKE_DB=sqlite ALINKSEC_SMOKE_ALLOW_FIXTURES=true \
  ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD=image-smoke-admin-password \
  ALINKSEC_SMOKE_BASE_URL="http://127.0.0.1:$http_port" \
  ALINKSEC_SMOKE_SQLITE_FILE="$test_root/data/alinksec.db" \
  ALINKSEC_SMOKE_GRPC_PORT="$grpc_port" ALINKSEC_SMOKE_CONTAINER_ID="$container_id" \
  node "$script_dir/server-image-smoke.mjs"
