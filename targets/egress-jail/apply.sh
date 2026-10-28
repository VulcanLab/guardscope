#!/bin/sh
# targets/egress-jail/apply.sh — T2/T3 forced-egress policy (default-deny
# output), applied INSIDE the harness container's network namespace.
#
# Runs as a one-shot compose service that shares the harness netns
# (network_mode: "service:<harness>", CAP_NET_ADMIN), applies an nftables
# output policy, and exits. The rules persist in the kernel netns; the
# harness (unprivileged uid) cannot remove them — enforcement is at the
# container network layer and holds regardless of the harness configuration
# (main.tex Table 1, T2/T3).
#
# Policy (v2):
#   accept  loopback (embedded docker DNS 127.0.0.11 lives here)
#   accept  ESTABLISHED/RELATED — replies to INBOUND connections (the driver's
#           published replay port arrives via docker-proxy; its response
#           packets must not be dropped by the output policy). New outbound
#           connections stay blocked, so this does not weaken egress.
#   accept  -> EGRESS_ALLOW_HOST:EGRESS_ALLOW_PORT (the enforcement point)
#   reject  every other tcp (fast ECONNREFUSED: deterministic prevented
#           outcomes — a DROP would hang connects until timeout)
#   reject  every other udp (icmp-port-unreachable; unconnected dgram
#           sockets do not surface it — prevented-ness for UDP is adjudicated
#           by the served-action log, not by the replay status)
#   drop    everything else (icmp, ...)
#
# The runner gates the replay on this container's clean exit (run.py
# docker-waits the egress jails), so a run never starts uninspected.
#
# IDEMPOTENCE: the table is deleted first — `nft -f` ADDS to an existing
# table, and a stale v1-style `tcp flags syn reject` ordered before the ct
# rule rejects SYN-ACKs (flags syn matches SYN|ACK as a mask test), killing
# all inbound reply paths (observed live 2026-10-06).

set -eu

ALLOW_HOST="${EGRESS_ALLOW_HOST:-gateway}"
ALLOW_PORT="${EGRESS_ALLOW_PORT:-8090}"

GW_IP="$(getent hosts "$ALLOW_HOST" | awk '{print $1; exit}')"
if [ -z "$GW_IP" ]; then
  echo "egress-jail: cannot resolve $ALLOW_HOST from this netns" >&2
  exit 1
fi

nft delete table ip inspection_egress 2>/dev/null || true
nft -f - <<RULES
table ip inspection_egress {
  chain output {
    type filter hook output priority filter; policy drop;
    oif "lo" accept
    ct state established,related accept
    ip daddr $GW_IP tcp dport $ALLOW_PORT accept
    tcp flags syn reject
    ip protocol udp reject
  }
}
RULES

echo "egress-jail: default-deny output applied (allow ${GW_IP}:${ALLOW_PORT} only)"
