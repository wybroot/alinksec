#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
test -x "$repo/.tmp/pam-native.test"
# Reuse the exact Ubuntu24 image built by the preceding PAM validation. This
# is a new disposable container, with no network, host /etc or data volumes.
docker image inspect alinksec-pam-native-validation:latest >/dev/null
docker run --rm --network=none --memory=192m --memory-swap=256m --cpus=1 --pids-limit=64 \
  --security-opt=no-new-privileges:true --cap-drop=ALL \
  --cap-add=CHOWN --cap-add=FOWNER --cap-add=DAC_OVERRIDE --cap-add=AUDIT_WRITE \
  --env ALINKSEC_SHADOW_DEFAULTS_NATIVE_REQUIRED=true \
  --env ALINKSEC_SHADOW_DEFAULTS_ISOLATED_REQUIRED=true \
  --mount "type=bind,src=$repo,dst=/workspace,readonly" \
  --workdir /workspace/agent/internal/baseline \
  alinksec-pam-native-validation:latest \
  /workspace/.tmp/pam-native.test -test.v -test.run '^TestNativeShadowAccountDefaults$'
