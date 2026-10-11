#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
test "${GITHUB_ACTIONS:-}" = true
test "${RUNNER_ENVIRONMENT:-}" = github-hosted
test -x "$repo/.tmp/dnf-native.test"
docker build -f deploy/tests/dnf/Dockerfile -t alinksec-dnf-native-validation:latest .
docker run --rm --network=none --memory=192m --memory-swap=256m --cpus=1 --pids-limit=64 \
  --cap-drop=ALL --security-opt=no-new-privileges:true \
  --mount "type=bind,src=$repo,dst=/workspace,readonly" \
  --workdir /workspace/agent/internal/baseline \
  --env ALINKSEC_DNF_ISOLATED_REQUIRED=true --env GOMEMLIMIT=96MiB \
  alinksec-dnf-native-validation:latest \
  /workspace/.tmp/dnf-native.test -test.v -test.timeout=120s -test.run '^TestNativeDNFSignature$'
