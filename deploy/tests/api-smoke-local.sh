#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_dir=$(cd "$script_dir/../.." && pwd)
jar="$repo_dir/server/alinksec-bootstrap/target/alinksec-bootstrap.jar"
java_bin=$(command -v "${JAVA_BIN:-java}")
java_bin=$(realpath "$java_bin")
command -v node >/dev/null
command -v flock >/dev/null
if [[ ! -f "$jar" ]]; then
  echo 'Build the server with mvn -B package before running local API validation.' >&2
  exit 1
fi

mkdir -p "$repo_dir/.tmp"
exec 9>"$repo_dir/.tmp/api-smoke-local.lock"
if ! flock -n 9; then
  echo 'Another local API validation is already running.' >&2
  exit 1
fi

test_root=$(mktemp -d "$repo_dir/.tmp/api-smoke-local.XXXXXX")
server_pid=''
cleanup() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n "$server_pid" ]]; then
    kill -TERM "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  if [[ "$status" -ne 0 ]]; then
    tail -n 100 "$test_root/server.log" >&2 || true
    printf 'Validation artifacts: %s\n' "$test_root" >&2
  else
    rm -rf -- "$test_root"
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

http_port=$(node --input-type=module -e '
  import net from "node:net";
  const server = net.createServer();
  server.listen(0, "127.0.0.1", () => {
    console.log(server.address().port);
    server.close();
  });
')
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
    ALINKSEC_PUBLIC_HOST= ALINKSEC_SERVER_TLS_SANS=localhost,127.0.0.1,::1 \
    ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD=local-smoke-admin-password \
    ALINKSEC_BOOTSTRAP_ENROLL_TOKEN=ENROLL-local-smoke \
    ALINKSEC_JWT_SECRET=local-smoke-jwt-secret \
    "$java_bin" -Xmx256m -XX:MaxMetaspaceSize=128m -XX:ActiveProcessorCount=1 \
    -jar "$jar" --server.address=127.0.0.1 --server.port="$http_port" \
    --alinksec.server.port=0
) >"$test_root/server.log" 2>&1 &
server_pid=$!

# Wait for bootstrap credentials, which are created after Tomcat starts.
node --input-type=module - "$http_port" "$server_pid" <<'NODE'
import { setTimeout as delay } from 'node:timers/promises'
const [port, pid] = process.argv.slice(2)
for (let attempt = 0; attempt < 60; attempt++) {
  process.kill(Number(pid), 0)
  try {
    const response = await fetch(`http://127.0.0.1:${port}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'admin', password: 'local-smoke-admin-password' }),
      signal: AbortSignal.timeout(1000),
    })
    if (response.ok && (await response.json()).code === 0) process.exit(0)
  } catch {}
  await delay(500)
}
throw new Error('Local SQLite server did not become ready')
NODE

env ALINKSEC_SMOKE_DB=sqlite ALINKSEC_SMOKE_ALLOW_FIXTURES=true \
  ALINKSEC_BOOTSTRAP_ADMIN_PASSWORD=local-smoke-admin-password \
  ALINKSEC_SMOKE_BASE_URL="http://127.0.0.1:$http_port" \
  ALINKSEC_SMOKE_SQLITE_FILE="$test_root/data/alinksec.db" \
  node --test --test-concurrency=1 "$script_dir/api-smoke.test.mjs"
