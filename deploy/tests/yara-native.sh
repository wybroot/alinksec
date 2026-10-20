#!/usr/bin/env bash
set -euo pipefail
build_root="$(pwd)/.tmp/yara-native"
bash deploy/tests/yara-build.sh "$build_root"
mkdir -p "$build_root/agent"
cp "$build_root/yara-84b0e3cc0e42f8f8e6b84d19c97ec3ac6ff8aee8/COPYING" "$build_root/LICENSE-YARA.txt"
# Go on Windows needs native paths; all compiler/runtime dependencies link static.
if [[ ${RUNNER_OS:-} == Windows ]]; then
  prefix=$(cygpath -m "$build_root/install")
  evidence=$(cygpath -m "$build_root")
  binary="$evidence/agent/alinksec-agent-yara-windows-amd64.exe"
else
  prefix="$build_root/install"
  evidence="$build_root"
  binary="$build_root/agent/alinksec-agent-yara-$(go env GOOS)-$(go env GOARCH)"
fi
export CGO_ENABLED=1 CGO_CFLAGS="-I$prefix/include" CGO_LDFLAGS="-L$prefix/lib"
export ALINKSEC_YARA_NATIVE_REQUIRED=true
export ALINKSEC_YARA_WORKER_EVIDENCE_FILE="$evidence/worker.json"
export ALINKSEC_YARA_EVIDENCE_FILE="$evidence/scan.json"
export ALINKSEC_YARA_EVENT_EVIDENCE_FILE="$evidence/event.json"
export ALINKSEC_YARA_AGENT_EVIDENCE_FILE="$evidence/agent.json"
export ALINKSEC_YARA_AGENT_BIN="$binary"
go -C agent build -tags nativeyara -trimpath -ldflags '-s -w' -o "$binary" ./cmd/agent
go -C agent test -tags nativeyara -v -count=1 -timeout=4m -run '^TestNativeYARA' ./internal/yara ./internal/virusscan ./internal/guard ./cmd/agent
