#!/bin/sh
set -eu
agent_workdir="${ALINKSEC_TEST_WORKDIR:-/work}"
if [ ! -f "$agent_workdir/certs/client.crt" ]; then
  /fixtures/alinksec-agent install --server "$ALINKSEC_TEST_SERVER" \
    --token "$ALINKSEC_TEST_TOKEN" --ca-file /fixtures/ca.crt --workdir "$agent_workdir"
fi
cp /fixtures/agent.yml "$agent_workdir/agent.yml"
exec /fixtures/alinksec-agent run --workdir "$agent_workdir"
