#!/usr/bin/env bash
set -euo pipefail
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "Native audit fixtures require a disposable GitHub-hosted runner" >&2
  exit 1
fi
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]]
[[ -x .tmp/baseline-native.test ]]
sudo env GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  ALINKSEC_AUDIT_NATIVE_REQUIRED=true ALINKSEC_AUDIT_FIXTURES_ALLOWED=true \
  .tmp/baseline-native.test -test.v -test.timeout=60s -test.run '^TestNativeKernelAudit$'
