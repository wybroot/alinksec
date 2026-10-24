#!/usr/bin/env bash
set -euo pipefail

# Fixture writes are restricted to disposable GitHub-hosted Ubuntu24 runners.
# Unique harmless units and a unique runtime manager drop-in are cleaned up.
# Never start special shutdown targets or send keyboard/SIGINT events.
if [[ "${GITHUB_ACTIONS:-}" != true || "${RUNNER_ENVIRONMENT:-}" != github-hosted ]]; then
  echo "Native systemd fixtures require a disposable GitHub-hosted runner" >&2
  exit 1
fi
source /etc/os-release
[[ "$ID" == ubuntu && "$VERSION_ID" == 24.04 ]]
[[ -x .tmp/baseline-native.test ]]
# This independent job can reach the manager while the runner is still booting.
# Wait for readiness before creating fixtures; never retry failed assertions.
manager_deadline=$((SECONDS + 120))
while true; do
  manager_state="$(timeout 5s /usr/bin/systemctl --system is-system-running 2>/dev/null || true)"
  case "$manager_state" in
    running|degraded) break ;;
  esac
  if (( SECONDS >= manager_deadline )); then
    echo "Native systemd fixture manager never became ready: $manager_state" >&2
    /usr/bin/systemctl --system list-jobs --no-pager >&2 || true
    exit 1
  fi
  sleep 1
done
echo "Native systemd fixture manager ready: $manager_state"
gcc -Wall -Wextra -Werror -O2 deploy/tests/systemd-clock-readonly.c -o .tmp/systemd-clock-readonly
sudo env ALINKSEC_SYSTEMD_NATIVE_REQUIRED=true ALINKSEC_SYSTEMD_FIXTURES_ALLOWED=true \
  GITHUB_ACTIONS=true RUNNER_ENVIRONMENT=github-hosted \
  ALINKSEC_CLOCK_READONLY_PROBE="$(pwd)/.tmp/systemd-clock-readonly" \
  .tmp/baseline-native.test -test.v -test.timeout=120s -test.run '^TestNativeSystemd(Service|CtrlAltDel|Maintenance|Rescue)$'
