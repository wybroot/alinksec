#!/usr/bin/env bash
set -Eeuo pipefail

[[ "${ALINKSEC_MAINTENANCE_TEST_ALLOW_FIXTURES:-}" == true ]] || {
  echo 'Set ALINKSEC_MAINTENANCE_TEST_ALLOW_FIXTURES=true for disposable validation.' >&2
  exit 1
}
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
for command in docker node flock; do
  command -v "$command" >/dev/null || { echo "Missing command: $command" >&2; exit 1; }
done
java_bin="$(command -v "${JAVA_BIN:-java}")"
java_bin="$(realpath "$java_bin")"
[[ -f "$repo_dir/server/alinksec-bootstrap/target/alinksec-bootstrap.jar" ]] || {
  echo 'Build the server with mvn -B package first.' >&2
  exit 1
}
mkdir -p "$repo_dir/.tmp"
exec 9>"$repo_dir/.tmp/api-smoke-local.lock"
flock -n 9 || { echo 'Another local API validation is already running.' >&2; exit 1; }
exec env JAVA_BIN="$java_bin" node "$script_dir/sqlite-maintenance-local.mjs"
