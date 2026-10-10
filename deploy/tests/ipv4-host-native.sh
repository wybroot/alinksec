#!/usr/bin/env bash
set -euo pipefail
repo=$(cd -- "$(dirname -- "$0")/../.." && pwd)
test -x "$repo/.tmp/baseline-native.test"
command -v nsenter >/dev/null
docker build -f deploy/tests/ipv4-host/Dockerfile -t alinksec-ipv4-host-native-validation:latest .
container=''
cleanup() { if [[ -n "$container" ]]; then docker rm -f "$container" >/dev/null 2>&1 || true; fi; }
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
# Each scenario has a separate disposable network namespace. Docker applies
# namespace-local sysctls before its read-only /proc/sys mount. No SYS_ADMIN,
# privileged mode, host networking, host /etc or data volumes are needed.
for scenario in strict each-strict loose-interface loose-all disabled future-loose local-forward future-forward global-forward; do
  all_rp=1; default_rp=0; lo_rp=0; ip_forward=0; default_forward=0; lo_forward=0; rp_pass=true; forward_pass=true
  case "$scenario" in
    each-strict) all_rp=0; default_rp=1; lo_rp=1 ;;
    loose-interface) lo_rp=2; rp_pass=false ;;
    loose-all) all_rp=2; rp_pass=false ;;
    disabled) all_rp=0; rp_pass=false ;;
    future-loose) default_rp=2; rp_pass=false ;;
    local-forward) lo_forward=1; forward_pass=false ;;
    future-forward) default_forward=1; forward_pass=false ;;
    global-forward) ip_forward=1; default_forward=1; lo_forward=1; forward_pass=false ;;
  esac
  # A new namespace may inherit global forwarding=1. First Docker sets the
  # global value; only afterwards does a separate child enter that private
  # namespace to set local values. This avoids OCI map ordering and leaves the
  # container's /proc/sys read-only without granting it SYS_ADMIN.
  container=$(docker run -d --rm --network=none --memory=128m --memory-swap=192m --cpus=1 --pids-limit=64 \
    --security-opt=no-new-privileges:true --cap-drop=ALL --cap-add=NET_ADMIN --cap-add=CHOWN --cap-add=FOWNER \
    --sysctl "net.ipv4.ip_forward=$ip_forward" --sysctl "net.ipv4.conf.all.rp_filter=$all_rp" \
    --sysctl "net.ipv4.conf.default.rp_filter=$default_rp" --sysctl "net.ipv4.conf.lo.rp_filter=$lo_rp" \
    --env ALINKSEC_IPV4_HOST_NATIVE_REQUIRED=true --env ALINKSEC_IPV4_HOST_ISOLATED_REQUIRED=true \
    --env "ALINKSEC_IPV4_HOST_SCENARIO=$scenario" --env "ALINKSEC_IPV4_HOST_RP_PASS=$rp_pass" --env "ALINKSEC_IPV4_HOST_FORWARD_PASS=$forward_pass" \
    --mount "type=bind,src=$repo,dst=/workspace,readonly" --workdir /workspace/agent/internal/baseline \
    alinksec-ipv4-host-native-validation:latest /bin/sleep 120)
  pid=$(docker inspect --format '{{.State.Pid}}' "$container")
  [[ "$pid" =~ ^[1-9][0-9]*$ ]]
  private_ns=$(sudo readlink "/proc/$pid/ns/net")
  host_ns=$(readlink /proc/self/ns/net)
  [[ -n "$private_ns" && "$private_ns" != "$host_ns" ]]
  sudo nsenter --net="/proc/$pid/ns/net" -- /usr/sbin/sysctl -w \
    "net.ipv4.conf.default.forwarding=$default_forward" "net.ipv4.conf.lo.forwarding=$lo_forward"
  [[ "$(sudo readlink "/proc/$pid/ns/net")" == "$private_ns" ]]
  [[ "$(readlink /proc/self/ns/net)" == "$host_ns" ]]
  docker exec "$container" /workspace/.tmp/baseline-native.test -test.v -test.run '^TestNativeIPv4Host$'
  docker stop "$container" >/dev/null
  container=''
done
