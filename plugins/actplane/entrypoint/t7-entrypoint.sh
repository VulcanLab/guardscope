#!/bin/bash
# plugins/actplane/entrypoint/t7-entrypoint.sh — the T7 control supervisor.
# Contract mapping (DESIGN.md 3):
#   provision  = this container (privileged, pid: host, the mounts the
#                incident/probe pinned: tracefs, /sys/fs/bpf, securityfs)
#   configure  = compile the fixture policy -> config blob; engine LOAD with
#                the config (probe 2026-10-31: write-sink rules are NOT
#                installable as runtime deltas — config-at-load is required)
#   ready      = the engine reports "ActPlane: ready"; the runner's
#                enforcement_ready gate then drives a deny test action
#                through the harness (docker exec) and checks its record
#   collect    = the shim tails the loader's event stream and appends
#                decision-record/1 lines to /var/log/control/decisions.jsonl
#                (one record per match; raw_ref = the source event line)
#   teardown   = trap: engine down + remove the /sys/fs/bpf/actplane pin
#                (probe: the singleton pin survives process exit — without
#                this, the next cell inherits the old engine's feature set)
set -euo pipefail

POLICY=/policy/t7.ap.yaml
BLOB=/run/t7-policy.bin
EVENTS=/var/log/control/actplane-events.log
RECORDS=/var/log/control/decisions.jsonl
SHIM=/opt/actplane-shim/translate.py
: "${CONTROL_STREAM_ID:=kernel-control}"
: "${CONTROL_RUN_ID:=unknown-run}"

log() { echo "[t7-entrypoint] $*"; }

teardown() {
  log "teardown: stopping loader and clearing the singleton pin"
  kill "${LOADER_PID:-}" 2>/dev/null || true
  sleep 1
  rm -rf /sys/fs/bpf/actplane 2>/dev/null || true
  log "teardown done"
}
trap teardown EXIT INT TERM

mkdir -p /var/log/control /run
: > "$EVENTS"; : > "$RECORDS"

# --- configure: compile the fixture policy (no privileges needed) ---------
log "configure: compiling $POLICY"
actplane compile --policy "$POLICY" --out "$BLOB" --force

# --- provision + configure (engine load with the config) -------------------
# Seed the harness container's init pid: the loader watches THAT process
# tree only (the measured agent tree; never targets/sensor/unrelated).
# The harness container name arrives via env (HARNESS_CONTAINER).
HARNESS_CONTAINER="${HARNESS_CONTAINER:-}"
if [ -z "$HARNESS_CONTAINER" ]; then
  log "FATAL: HARNESS_CONTAINER env not set"; exit 2
fi
for i in $(seq 1 120); do
  PID=$(docker inspect -f '{{.State.Pid}}' "$HARNESS_CONTAINER" 2>/dev/null || true)
  [ -n "${PID:-}" ] && [ "$PID" != "0" ] && break
  sleep 1
done
if [ -z "${PID:-}" ] || [ "$PID" = "0" ]; then
  log "FATAL: harness container $HARNESS_CONTAINER never started"; exit 2
fi
log "provision: seeding engine on $HARNESS_CONTAINER (pid $PID)"

: > /run/loader.out
/opt/actplane/process --config "$BLOB" --seed-pid "$PID" \
  > "$EVENTS" 2> /run/loader.err &
LOADER_PID=$!
for i in $(seq 1 120); do
  grep -q "ActPlane: ready" /run/loader.err /run/loader.out 2>/dev/null && break
  kill -0 "$LOADER_PID" 2>/dev/null || {
    log "FATAL: loader exited early:"; cat /run/loader.err || true; exit 2; }
  sleep 1
done
grep -q "ActPlane: ready" /run/loader.err /run/loader.out 2>/dev/null || {
  log "FATAL: engine never became ready"; cat /run/loader.err || true; exit 2; }
log "ready: engine loaded with the fixture config, watching pid $PID tree"

# --- collect: shim the event stream into decision-record/1 ----------------
log "collect: shim streaming $EVENTS -> $RECORDS"
tail -f -n +1 "$EVENTS" | "$SHIM" \
  --stream-id "$CONTROL_STREAM_ID" --run-id "$CONTROL_RUN_ID" \
  --plugin actplane --plugin-version 0.1.8 \
  >> "$RECORDS" &
SHIM_PID=$!

# Keep the foreground alive; teardown on signal.
log "control up; waiting for termination"
wait "$LOADER_PID" || true
