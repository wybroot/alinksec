#!/usr/bin/env bash
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "Native configuration validation requires a disposable GitHub-hosted runner" >&2
  exit 1
fi
root="$(pwd)"
mkdir -p .tmp/config-native
(
  cd agent
  CGO_ENABLED=0 go test -c -o ../.tmp/agent-config-native.test ./cmd/agent
)
sudo env GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  ALINKSEC_CONFIG_NATIVE_REQUIRED=true \
  ALINKSEC_SMOKE_AGENT_BIN="$root/.tmp/alinksec-agent" \
  ALINKSEC_CONFIG_EVIDENCE_FILE="$root/.tmp/config-native/result.json" \
  "$root/.tmp/agent-config-native.test" -test.v -test.timeout=3m -test.run '^TestConfigIntegrityLifecycle$'
sudo chown "$(id -u):$(id -g)" "$root/.tmp/config-native/result.json"
