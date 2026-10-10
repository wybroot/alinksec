#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
test -x "$repo/.tmp/baseline-native.test"
docker build -f deploy/tests/cron/Dockerfile -t alinksec-cron-native-validation:latest .
# Only disposable container cron files and controlled @reboot marker jobs.
# No host scheduler, writable repository, network or host data volume.
docker run --rm --network=none --memory=128m --memory-swap=192m --cpus=1 --pids-limit=64 \
  --cap-drop=ALL --cap-add=CHOWN --cap-add=SETUID --cap-add=SETGID \
  --security-opt=no-new-privileges:true \
  --mount "type=bind,src=$repo,dst=/workspace,readonly" \
  --workdir /workspace/agent/internal/baseline \
  --env ALINKSEC_CRON_NATIVE_REQUIRED=true \
  alinksec-cron-native-validation:latest \
  /workspace/.tmp/baseline-native.test -test.v -test.timeout=60s -test.run '^TestNativeCronMetadata$'
