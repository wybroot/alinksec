#!/bin/sh
set -eu

cert=/etc/nginx/tls/server.crt
key=/etc/nginx/tls/server.key

for attempt in $(seq 1 60); do
  if [ -s "$cert" ] && [ -s "$key" ]; then
    exit 0
  fi
  sleep 2
done

echo "platform TLS certificate was not generated within 120 seconds" >&2
exit 1
