#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
test -x "$repo/.tmp/pam-native.test"
docker build -f deploy/tests/pam/Dockerfile -t alinksec-pam-native-validation:latest .
# The workspace is read-only. All PAM configuration and password changes below
# belong to the disposable Ubuntu24.04 filesystem, with no host /etc mounts.
docker run --rm --network=none --memory=256m --memory-swap=384m --cpus=1 --pids-limit=128 \
  --security-opt=no-new-privileges:true \
  --cap-drop=SYS_RESOURCE \
  --mount "type=bind,src=$repo,dst=/workspace,readonly" \
  --workdir /workspace/agent/internal/baseline \
  alinksec-pam-native-validation:latest \
  /workspace/.tmp/pam-native.test -test.v -test.run '^TestNativePAM(Password|Auth|Limits)$'
