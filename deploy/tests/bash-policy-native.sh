#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
test -x "$repo/.tmp/pam-native.test"
# A new disposable Ubuntu24 container reuses the previous PAM image. No network,
# host /etc or data volumes. SETUID/SETGID are only for the ordinary-user fixture.
docker image inspect alinksec-pam-native-validation:latest >/dev/null
docker run --rm --network=none --memory=192m --memory-swap=256m --cpus=1 --pids-limit=64 \
 --security-opt=no-new-privileges:true --cap-drop=ALL \
 --cap-add=CHOWN --cap-add=FOWNER --cap-add=DAC_OVERRIDE --cap-add=SETUID --cap-add=SETGID \
 --env ALINKSEC_BASH_NATIVE_REQUIRED=true --env ALINKSEC_BASH_ISOLATED_REQUIRED=true \
 --mount "type=bind,src=$repo,dst=/workspace,readonly" \
 --workdir /workspace/agent/internal/baseline alinksec-pam-native-validation:latest \
 /workspace/.tmp/pam-native.test -test.v -test.run '^TestNativeBashGlobalPolicy$'
