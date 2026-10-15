#!/usr/bin/env bash
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "Native isolation validation requires a disposable GitHub-hosted runner" >&2
  exit 1
fi
root="$(pwd)"
mkdir -p .tmp/isolation-native
(
  cd agent
  CGO_ENABLED=0 go test -c -o ../.tmp/agent-isolation-native.test ./cmd/agent
)
sudo env GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  ALINKSEC_ISOLATION_NATIVE_REQUIRED=true \
  ALINKSEC_SMOKE_AGENT_BIN="$root/.tmp/alinksec-agent" \
  ALINKSEC_ISOLATION_EVIDENCE_FILE="$root/.tmp/isolation-native/result.json" \
  "$root/.tmp/agent-isolation-native.test" -test.v -test.timeout=3m -test.run '^TestNativeIsolationLifecycle$'
sudo chown "$(id -u):$(id -g)" "$root/.tmp/isolation-native/result.json"
