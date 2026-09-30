#!/usr/bin/env bash
set -Eeuo pipefail

CHAIN="ALINKSEC-INGRESS"
: "${EXTERNAL_INTERFACE:?set EXTERNAL_INTERFACE, for example eth0}"

if [[ "${1:-}" == "remove" ]]; then
  while iptables -C DOCKER-USER -i "$EXTERNAL_INTERFACE" -j "$CHAIN" 2>/dev/null; do
    iptables -D DOCKER-USER -i "$EXTERNAL_INTERFACE" -j "$CHAIN"
  done
  iptables -F "$CHAIN" 2>/dev/null || true
  iptables -X "$CHAIN" 2>/dev/null || true
  echo "Removed ALinkSec DOCKER-USER rules."
  exit 0
fi

: "${MANAGEMENT_CIDR:?set MANAGEMENT_CIDR, for example 10.10.0.0/24}"
: "${AGENT_CIDR:?set AGENT_CIDR, for example 10.20.0.0/16}"

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Run as root." >&2
  exit 1
fi
if ! iptables -L DOCKER-USER -n >/dev/null 2>&1; then
  echo "DOCKER-USER is unavailable; start Docker before applying these rules." >&2
  exit 1
fi

iptables -N "$CHAIN" 2>/dev/null || true
iptables -F "$CHAIN"
iptables -C DOCKER-USER -i "$EXTERNAL_INTERFACE" -j "$CHAIN" 2>/dev/null || \
  iptables -I DOCKER-USER 1 -i "$EXTERNAL_INTERFACE" -j "$CHAIN"

iptables -A "$CHAIN" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A "$CHAIN" -s "$MANAGEMENT_CIDR" -p tcp -m conntrack --ctorigdstport 8443 -j ACCEPT
iptables -A "$CHAIN" -s "$MANAGEMENT_CIDR" -p tcp -m conntrack --ctorigdstport 8081 -j ACCEPT
iptables -A "$CHAIN" -s "$AGENT_CIDR" -p tcp -m conntrack --ctorigdstport 9443 -j ACCEPT
iptables -A "$CHAIN" -s "$AGENT_CIDR" -p tcp -m conntrack --ctorigdstport 8443 -j ACCEPT
iptables -A "$CHAIN" -p tcp -m conntrack --ctorigdstport 9443 -j DROP
iptables -A "$CHAIN" -p tcp -m conntrack --ctorigdstport 8443 -j DROP
iptables -A "$CHAIN" -p tcp -m conntrack --ctorigdstport 8081 -j DROP
iptables -A "$CHAIN" -j RETURN

echo "Applied ALinkSec source restrictions on $EXTERNAL_INTERFACE."
