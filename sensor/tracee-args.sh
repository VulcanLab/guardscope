#!/bin/sh
# Canonical Tracee invocation for the inspection testbed (C5).
# Single source of truth for sensor args; the runner (C9) and compose
# (../compose/t0.yaml via Dockerfile.tracee) must both use it.
#
# Scoping rationale (verified on the original local host, M0 smoke + M3 smoke):
#   --scope container      capture only container-context events (host noise
#                          excluded); per-container post-filtering happens in
#                          the mapping/reconciliation layers. `--scope
#                          container=new` did NOT capture events on this host.
#   --events ...           the minimal event set the six-class mapping needs:
#                          execve (process_spawn), connect/sendto/sendmsg
#                          (network; node's dgram sends UDP via sendmsg),
#                          security_file_open (file_write, credential_access),
#                          write (stdio_tool_call: JSON-RPC on pipes)
#   --output json          NDJSON events on stdout; Tracee's own log messages
#                          go to stderr. A file sink (`--output json:<path>`)
#                          is broken in this build — console capture via
#                          docker logs is the verified mode.
#
# First-start eBPF warm-up takes tens of seconds; output flushes in large
# batches (30-90 s lag observed). Callers must wait for readiness before
# replaying traces.

exec /tracee/tracee \
  --scope container \
  --events execve,connect,sendto,sendmsg,security_file_open,write,net_packet_udp \
  --output json