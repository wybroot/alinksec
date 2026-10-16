#!/bin/sh
set -eu
agent_workdir="${ALINKSEC_TEST_WORKDIR:-/work}"
# This disposable fixture runs the Agent as root. Host-created bind mounts start
# with the runner's UID; prepare the service-owned private directory explicitly.
mkdir -p "$agent_workdir"
chown 0:0 "$agent_workdir"
chmod 0700 "$agent_workdir"
if [ ! -f "$agent_workdir/certs/client.crt" ]; then
  /fixtures/alinksec-agent install --server "$ALINKSEC_TEST_SERVER" \
    --token "$ALINKSEC_TEST_TOKEN" --ca-file /fixtures/ca.crt --workdir "$agent_workdir"
fi
/fixtures/alinksec-agent config apply --from /fixtures/agent.yml --workdir "$agent_workdir"
exec /fixtures/alinksec-agent run --workdir "$agent_workdir"
