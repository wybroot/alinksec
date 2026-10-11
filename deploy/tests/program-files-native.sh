#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
test -x "$repo/.tmp/pam-native.test"
docker image inspect alinksec-pam-native-validation:latest >/dev/null
# Unique filesystem replicas only; source read-only, no host /etc or data volumes.
# FSETID is solely for the numerical SGID fixture; SYS_CHROOT is for read-only
# ldconfig in the private replica. No privileged fixture file is executed.
docker run --rm --network=none --memory=128m --memory-swap=192m --cpus=1 --pids-limit=64 \
  --security-opt=no-new-privileges:true --cap-drop=ALL --cap-add=CHOWN --cap-add=FOWNER --cap-add=FSETID --cap-add=SYS_CHROOT \
  --env ALINKSEC_PROGRAM_FILES_NATIVE_REQUIRED=true --env ALINKSEC_PROGRAM_FILES_ISOLATED_REQUIRED=true \
  --mount "type=bind,src=$repo,dst=/workspace,readonly" --workdir /workspace/agent/internal/baseline \
  alinksec-pam-native-validation:latest /workspace/.tmp/pam-native.test -test.v -test.run '^TestNativeProgramFiles$'
