#!/usr/bin/env bash
set -euo pipefail

# Only a unique unattached policy is loaded on a disposable hosted runner.
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "Native AppArmor fixtures require a disposable GitHub-hosted runner" >&2
  exit 1
fi
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]]
[[ -x .tmp/baseline-native.test ]]
if [[ ! -x /usr/sbin/apparmor_parser || ! -x /usr/sbin/aa-status ]]; then
  sudo apt-get update
  sudo apt-get install -y --no-install-recommends apparmor
fi
sudo env ALINKSEC_APPARMOR_NATIVE_REQUIRED=true ALINKSEC_APPARMOR_FIXTURES_ALLOWED=true \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  .tmp/baseline-native.test -test.v -test.timeout=120s -test.run '^TestNativeAppArmor$'
