#!/usr/bin/env bash
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "Native upgrade validation requires a disposable GitHub-hosted runner" >&2
  exit 1
fi
root="$(pwd)"
mkdir -p .tmp/upgrade-native
(
  cd agent
  CGO_ENABLED=0 go build -trimpath -o ../.tmp/alinksec-upgrade-broken ./internal/upgrade/testdata/broken
  CGO_ENABLED=0 go test -c -o ../.tmp/agent-upgrade-native.test ./cmd/agent
)
sudo env GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  ALINKSEC_UPGRADE_NATIVE_REQUIRED=true \
  ALINKSEC_SMOKE_AGENT_BIN="$root/.tmp/alinksec-agent" \
  ALINKSEC_UPGRADE_BROKEN_BIN="$root/.tmp/alinksec-upgrade-broken" \
  ALINKSEC_UPGRADE_EVIDENCE_FILE="$root/.tmp/upgrade-native/result.json" \
  "$root/.tmp/agent-upgrade-native.test" -test.v -test.timeout=4m -test.run '^TestNativeUpgradeLifecycle$'
sudo chown "$(id -u):$(id -g)" "$root/.tmp/upgrade-native/result.json"
