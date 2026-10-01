#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${ALINKSEC_SMOKE_ALLOW_FIXTURES:-}" == true ]] || {
  echo 'Set ALINKSEC_SMOKE_ALLOW_FIXTURES=true for isolated validation.' >&2
  exit 1
}
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
mkdir -p "$repo_dir/.tmp"
exec 9>"$repo_dir/.tmp/api-smoke-local.lock"
flock -n 9 || { echo 'Another local validation is already running.' >&2; exit 1; }
exec node "$script_dir/firewall-local.mjs"
