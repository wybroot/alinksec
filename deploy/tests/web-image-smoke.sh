#!/usr/bin/env bash
set -Eeuo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
image="${ALINKSEC_SMOKE_WEB_IMAGE:?Set ALINKSEC_SMOKE_WEB_IMAGE to the built web image}"
jar="$repo_dir/server/alinksec-bootstrap/target/alinksec-bootstrap.jar"
for command in docker node flock; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done
java_bin="$(command -v "${JAVA_BIN:-java}")"
java_bin="$(realpath "$java_bin")"
[[ -f "$jar" ]] || { echo 'Build the server with mvn -B package first.' >&2; exit 1; }
docker image inspect "$image" >/dev/null
mkdir -p "$repo_dir/.tmp"
exec 9>"$repo_dir/.tmp/api-smoke-local.lock"
flock -n 9 || { echo 'Another local API validation is already running.' >&2; exit 1; }

# The production Nginx upstream uses server:8080. Bind Java only to Docker's bridge.
gateway="$(docker network inspect bridge --format '{{json .IPAM.Config}}' | node --input-type=module -e '
  import { readFileSync } from "node:fs";
  import { isIP } from "node:net";
  const gateway = JSON.parse(readFileSync(0, "utf8")).find(c => isIP(c.Gateway) === 4)?.Gateway;
  if (!gateway) throw new Error("This check requires a local Linux Docker IPv4 bridge");
  console.log(gateway);
')"
node --input-type=module - "$gateway" <<'NODE'
import net from 'node:net'
const server = net.createServer()
server.on('error', error => { throw new Error(`Docker bridge port 8080 is unavailable: ${error.message}`) })
server.listen(8080, process.argv[2], () => server.close())
NODE

test_root="$(mktemp -d "$repo_dir/.tmp/web-image-smoke.XXXXXX")"
server_pid=''
container_id=''
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$container_id" ]]; then
    docker logs "$container_id" >"$test_root/web.log" 2>&1 || true
    docker stop --timeout 10 "$container_id" >/dev/null || status=1
  fi
  if [[ -n "$server_pid" ]]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if ((status != 0)); then
    for log in "$test_root/server.log" "$test_root/web.log"; do
      if [[ -f "$log" ]]; then tail -n 80 "$log" >&2; fi
    done
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
(
  cd "$test_root"
  exec env SPRING_PROFILES_ACTIVE=sqlite ALINKSEC_METRICS_ENABLED=false \
    ALINKSEC_SQLITE_PATH="$test_root/data/alinksec.db" \
    ALINKSEC_CERT_DIR="$test_root/data/certs" \
    ALINKSEC_WEB_TLS_DIR="$test_root/data/web-tls" \
    ALINKSEC_SIG_DIR="$test_root/data/signature" \
    ALINKSEC_PATCH_DIR="$test_root/data/patch" \
    ALINKSEC_UPGRADE_DIR="$test_root/data/agent-upgrade" \
    ALINKSEC_PUBLIC_HOST=ci.alinksec.test \
    ALINKSEC_SERVER_TLS_SANS=localhost,127.0.0.1,ci.alinksec.test \
    ALINKSEC_SIG_BASE=ci.alinksec.test:8443 \
    ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD=web-smoke-admin-password \
    ALINKSEC_BOOTSTRAP_ENROLL_TOKEN=ENROLL-web-smoke \
    ALINKSEC_JWT_SECRET=web-smoke-jwt-secret \
    "$java_bin" -Xmx256m -XX:MaxMetaspaceSize=128m -XX:ActiveProcessorCount=1 \
    -jar "$jar" --server.address="$gateway" --server.port=8080 \
    --alinksec.server.port=0
) >"$test_root/server.log" 2>&1 &
server_pid=$!

node --input-type=module - "$gateway" "$server_pid" "$test_root/data/web-tls/server.key" <<'NODE'
import { existsSync } from 'node:fs'
import { setTimeout as delay } from 'node:timers/promises'
const [gateway, pid, key] = process.argv.slice(2)
for (let attempt = 0; attempt < 90; attempt++) {
  process.kill(Number(pid), 0)
  try {
    const response = await fetch(`http://${gateway}:8080/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'web-smoke-admin-password' }),
      signal: AbortSignal.timeout(1000),
    })
    if (response.ok && (await response.json()).code === 0 && existsSync(key)) process.exit(0)
  } catch {}
  await delay(500)
}
throw new Error('Local SQLite server did not become ready')
NODE

container_id="$(docker run --detach --rm --init --name "alinksec-web-smoke-${BASHPID}-${RANDOM}" \
  --memory=96m --memory-swap=128m --cpus=1 --pids-limit=64 \
  --env "ALINKSEC_BACKEND_HOST=$gateway" \
  --mount "type=bind,src=$test_root/data/web-tls,dst=/etc/nginx/tls,readonly" \
  --publish 127.0.0.1::80 --publish 127.0.0.1::443 \
  --env NGINX_ENTRYPOINT_WORKER_PROCESSES_AUTOTUNE=1 "$image")"
http_port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "80/tcp") 0).HostPort}}' "$container_id")"
https_port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "443/tcp") 0).HostPort}}' "$container_id")"

env ALINKSEC_SMOKE_DB=sqlite ALINKSEC_SMOKE_ALLOW_FIXTURES=true \
  ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD=web-smoke-admin-password \
  ALINKSEC_SMOKE_BASE_URL="https://127.0.0.1:$https_port" \
  ALINKSEC_SMOKE_CA_FILE="$test_root/data/certs/ca.crt" \
  ALINKSEC_SMOKE_SQLITE_FILE="$test_root/data/alinksec.db" \
  ALINKSEC_SMOKE_HTTP_PORT="$http_port" ALINKSEC_SMOKE_CONTAINER_ID="$container_id" \
  node "$script_dir/web-image-smoke.mjs"

if [[ "${ALINKSEC_SMOKE_BROWSER:-false}" == true ]]; then
  env ALINKSEC_SMOKE_ALLOW_FIXTURES=true \
    ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD=web-smoke-admin-password \
    ALINKSEC_SMOKE_BASE_URL="https://127.0.0.1:$https_port" \
    ALINKSEC_SMOKE_CA_FILE="$test_root/data/certs/ca.crt" \
    ALINKSEC_SMOKE_SQLITE_FILE="$test_root/data/alinksec.db" \
    node "$repo_dir/web/test/browser-smoke.mjs"
fi
