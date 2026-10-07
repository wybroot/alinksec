#!/usr/bin/env bash
set -euo pipefail

# Fixture writes are restricted to disposable GitHub-hosted Ubuntu24 runners.
# No existing audit or logging service is started/stopped/configured.
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "Native systemd fixtures require a disposable GitHub-hosted runner" >&2
  exit 1
fi
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]]
[[ -x .tmp/baseline-native.test ]]
sudo env ALINKSEC_SYSTEMD_NATIVE_REQUIRED=true ALINKSEC_SYSTEMD_FIXTURES_ALLOWED=true \
  .tmp/baseline-native.test -test.v -test.timeout=60s -test.run '^TestNativeSystemdService$'
