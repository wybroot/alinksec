#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${ALINKSEC_SMOKE_ALLOW_FIXTURES:-}" == true ]] || {
  echo 'Set ALINKSEC_SMOKE_ALLOW_FIXTURES=true for disposable validation.' >&2
  exit 1
}
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
java_bin="$(realpath "$(command -v "${JAVA_BIN:-java}")")"
maven_bin="$(realpath "$(command -v "${MAVEN_BIN:-mvn}")")"
mkdir -p "$repo_dir/.tmp"
exec 9>"$repo_dir/.tmp/api-smoke-local.lock"
flock -n 9 || { echo 'Another local validation is already running.' >&2; exit 1; }
exec env JAVA_BIN="$java_bin" MAVEN_BIN="$maven_bin" node "$script_dir/postgres-validation-local.mjs"
