#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
test -x "$repo/.tmp/baseline-native.test"
docker build -f deploy/tests/apt/Dockerfile -t alinksec-apt-native-validation:latest .
docker run --rm --network=none --memory=128m --memory-swap=192m --cpus=1 --pids-limit=64 \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --mount "type=bind,src=$repo,dst=/workspace,readonly" \
  --workdir /workspace/agent/internal/baseline \
  --env ALINKSEC_APT_NATIVE_REQUIRED=true \
  alinksec-apt-native-validation:latest \
  /workspace/.tmp/baseline-native.test -test.v -test.timeout=90s \
  -test.run '^(TestNativeAPTInstallPolicy|TestAPTPolicyCases|TestAPTRefusesUnsafeInputs|TestAPTChangesAndOneDeadline|TestAPTUnknownSyntaxAndBooleans)$'
