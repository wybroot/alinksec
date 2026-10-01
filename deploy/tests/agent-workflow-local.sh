#!/usr/bin/env bash
set -Eeuo pipefail
[[ "${ALINKSEC_SMOKE_ALLOW_FIXTURES:-}" == true ]] || {
  echo 'Set ALINKSEC_SMOKE_ALLOW_FIXTURES=true for disposable validation.' >&2
  exit 1
}
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "$script_dir/../.." && pwd)"
for command in docker node flock dpkg-deb; do command -v "$command" >/dev/null; done
java_bin="$(realpath "$(command -v "${JAVA_BIN:-java}")")"
agent_bin="$(realpath "${ALINKSEC_SMOKE_AGENT_BIN:?Set ALINKSEC_SMOKE_AGENT_BIN}")"
mkdir -p "$repo_dir/.tmp"
exec 9>"$repo_dir/.tmp/api-smoke-local.lock"
flock -n 9 || { echo 'Another local validation is already running.' >&2; exit 1; }
exec env JAVA_BIN="$java_bin" ALINKSEC_SMOKE_AGENT_BIN="$agent_bin" \
  node "$script_dir/agent-workflow-local.mjs"
