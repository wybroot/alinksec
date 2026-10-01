#!/bin/sh
set -eu
if [ ! -f /work/certs/client.crt ]; then
  /fixtures/alinksec-agent install --server "$ALINKSEC_TEST_SERVER" \
    --token "$ALINKSEC_TEST_TOKEN" --ca-file /fixtures/ca.crt --workdir /work
fi
cp /fixtures/agent.yml /work/agent.yml
exec /fixtures/alinksec-agent run --workdir /work
