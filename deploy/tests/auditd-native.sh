#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
test -x "$repo/.tmp/baseline-native.test"
docker build -f deploy/tests/auditd/Dockerfile -t alinksec-auditd-native-validation:latest .
# No audit-control/read/write capabilities; the real auditd parser may run but
# cannot register a daemon or change the host audit state/rules. Only disposable
# container files are changed. The shared repository is read-only.
docker run --rm --network=none --memory=128m --memory-swap=192m --cpus=1 --pids-limit=64 \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --mount "type=bind,src=$repo,dst=/workspace,readonly" \
  --workdir /workspace/agent/internal/baseline \
  --env ALINKSEC_AUDITD_NATIVE_REQUIRED=true \
  alinksec-auditd-native-validation:latest \
  /workspace/.tmp/baseline-native.test -test.v -test.timeout=60s -test.run '^TestNativeAuditdConfig$'
