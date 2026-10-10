#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
test -x "$repo/.tmp/baseline-native.test"
docker build -f deploy/tests/sudoers/Dockerfile -t alinksec-sudoers-native-validation:latest .
# Native syntax/JSON tools only in this private container. No elevated command,
# password, account, network or host sudo policy operations.
docker run --rm --network=none --memory=128m --memory-swap=192m --cpus=1 --pids-limit=64 \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --mount "type=bind,src=$repo,dst=/workspace,readonly" \
  --workdir /workspace/agent/internal/baseline \
  --env ALINKSEC_SUDOERS_NATIVE_REQUIRED=true \
  alinksec-sudoers-native-validation:latest \
  /workspace/.tmp/baseline-native.test -test.v -test.timeout=90s \
  -test.run '^(TestNativeSudoersDeclarations|TestSudoersRefusesUnsafeInputs|TestSudoersUnknownPolicyCannotPass|TestSudoersChangesAndOneDeadline)$'
