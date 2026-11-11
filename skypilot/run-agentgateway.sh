#!/usr/bin/env bash
# The agentgateway campaign (run ON the instance, user ubuntu, AFTER
# provision-agentgateway-host.sh and the repo rsync to ~/guardscope).
#
# Design T1 under the agentgateway binding (plugins/agentgateway, the CNCF
# agentgateway control, record_source ingested), sensor-backed (Tracee):
#   - examples/t1-mock-agentgateway.yaml (mock-harness fixture)
#   - examples/t1-pi-agentgateway.yaml   (pi fixture)
# each as a warmup run + acceptance run pair (the README's warmup rule: the
# first live run of a design fails the leftover check BY DESIGN), then the
# formal L2 correlation fidelity check (framework/fidelity.py wired live by
# skypilot/fidelity-agentgateway.py) against the acceptance topology.
#
# Session-ops discipline (the t7recheck + m2 lessons, applied):
#   - per-run tracee force-recreate (a long-lived tracee accumulates
#     multi-GB log dumps; the capture covers only that run) + Tracee
#     warm-up wait (the sensor needs ~10s+ before events flow; a synthetic
#     in-container exec triggers a flush if the host is quiet);
#   - docker log bounds applied in the provision script (daemon.json);
#   - staging dirs pre-created (docker creates missing host mount points
#     as ROOT, which blocks the runner's compile step);
#   - exactly ONE sensor at a time: the pair is torn down (down -v WITH
#     --profile sensor) before the next pair's sensor starts (the
#     designspace lesson: concurrent host-wide Tracee instances starve the
#     eBPF buffers and correctly FAIL the runs);
#   - the collector's .ready marker must precede each run's window (the
#     capture was open before the first action) — asserted per run;
#   - the vendor-log volume accumulates rows across runs on the long-lived
#     topology: the acceptance run's excluded-rows count must equal the
#     warmup run's scoped count (the scope is the readiness probe's
#     issuance time, probe-time-based, same-host clocks) — asserted per
#     pair (checker risk item); a mismatch aborts the campaign.
set -uxo pipefail

CHECKOUT="$HOME/guardscope"
LOGDIR="$HOME/campaign-logs"
mkdir -p "$LOGDIR"

# ---- environment -----------------------------------------------------------
docker info >/dev/null 2>&1 || { echo "FATAL: docker unusable (re-login for the docker group?)"; exit 1; }
cd "$CHECKOUT"
python3 -m venv .venv
.venv/bin/pip install -q -e .
export PATH="$CHECKOUT/.venv/bin:$PATH"

export GUARDSCOPE_WORKDIR="$HOME/experiments/guardscope"
export GUARDSCOPE_STAGING_DIR="$HOME/experiments/guardscope/runs"
mkdir -p "$GUARDSCOPE_WORKDIR"
# pre-create the staging subdirs the compose files mount (root-owned mounts
# block the compile step)
mkdir -p "$GUARDSCOPE_STAGING_DIR/pi" "$GUARDSCOPE_STAGING_DIR/mock" \
         "$GUARDSCOPE_STAGING_DIR/openclaw"
cd "$GUARDSCOPE_WORKDIR"

bash "$CHECKOUT/env/check-server.sh" 2>&1 | tee "$LOGDIR/env-check.log"

# ---- helpers ---------------------------------------------------------------
READY_PATH="/var/log/gateway/agentgateway-trace.jsonl.ready"
VENDOR_PATH="/var/log/gateway/agentgateway-trace.jsonl"

ready_marker_ns () {  # $1=collector container
  docker exec "$1" cat "$READY_PATH" 2>/dev/null | tr -d '[:space:]'
}

wait_collector_ready () {  # $1=prefix — the .ready sidecar proves the
  # collector's follow window opened before anything the runs will do
  local c="${1}-agentgateway-trace" ns=""
  for _ in $(seq 1 60); do
    ns=$(ready_marker_ns "$c"); [ -n "$ns" ] && { echo "$ns"; return 0; }
    sleep 1
  done
  echo "FATAL: collector $c never wrote its .ready marker" >&2
  return 1
}

fresh_sensor () {  # $1=prefix $2=base $3=overlay $4=harness-container
  # per-run sensor re-arm: force-recreate tracee so its docker log (the
  # capture source) covers only this run, then wait until Tracee actually
  # emits (the ~10s eBPF warm-up; a synthetic in-container exec triggers a
  # flush if the host stays quiet)
  docker compose -f "$CHECKOUT/$2" -f "$CHECKOUT/$3" \
    --profile sensor up -d --force-recreate tracee 2>&1 | tail -1
  local c="${1}-tracee"
  for _ in $(seq 1 60); do
    docker logs "$c" > /tmp/tracee-probe.log 2>&1 || true
    grep -q '"eventName"' /tmp/tracee-probe.log && { echo "tracee READY (event seen)"; return 0; }
    sleep 2
  done
  # no event yet — trigger one (out-of-window, harmless) and wait for flush
  docker exec "$4" /bin/true 2>/dev/null || true
  for _ in $(seq 1 60); do
    docker logs "$c" > /tmp/tracee-probe.log 2>&1 || true
    grep -q '"eventName"' /tmp/tracee-probe.log && { echo "tracee READY (event seen after synthetic trigger)"; return 0; }
    sleep 2
  done
  echo "WARN: tracee never emitted an event within 240s (proceeding; the run's own R3/R4 will judge the capture)"
}

run_scoped_rows () {  # $1=run log — the runner's scoping print:
  # "[run_id] ingested control agentgateway: N vendor row(s) in this run's
  #  scope (M row(s) of earlier runs excluded, ...)"
  grep -oE '[0-9]+ vendor row\(s\) in this run' "$1" | grep -oE '^[0-9]+' | head -1
}
run_excluded_rows () {
  grep -oE '\([0-9]+ row\(s\) of earlier runs excluded' "$1" | grep -oE '[0-9]+' | head -1
}
run_id_of_log () {  # $1=run log
  sed -n 's/^\[\(.*\)\] ingested control agentgateway:.*/\1/p' "$1" | head -1
}

# ---- one experiment pair ---------------------------------------------------
# $1=prefix (container prefix: t1-mock or t1) $2=base $3=overlay
# $4=experiment-stem $5=harness-container
run_pair () {
  local prefix="$1" base="$2" overlay="$3" exp="$4" harness="$5"
  local COMPOSE
  COMPOSE=(-f "$CHECKOUT/$base" -f "$CHECKOUT/$overlay")
  cd "$GUARDSCOPE_WORKDIR"

  echo "=== pair $prefix: bring-up (base $base + overlay $overlay) ==="
  docker compose "${COMPOSE[@]}" up -d 2>&1 | tee "$LOGDIR/$prefix-up.log"
  docker compose "${COMPOSE[@]}" --profile sensor up -d tracee \
    2>&1 | tee "$LOGDIR/$prefix-sensor-up.log"
  local ready_ns
  ready_ns=$(wait_collector_ready "$prefix") \
    || { echo "FATAL ($prefix): collector readiness"; return 1; }
  echo "$prefix: collector .ready marker at $ready_ns"

  guardscope validate "$CHECKOUT/examples/$exp.yaml" \
    2>&1 | tee "$LOGDIR/$prefix-validate.log"

  # -- warmup run (fails the leftover check BY DESIGN on first live run)
  fresh_sensor "$prefix" "$base" "$overlay" "$harness"
  guardscope run "$CHECKOUT/examples/$exp.yaml" 2>&1 \
    | tee "$LOGDIR/$prefix-run1-warmup.log" \
    || echo "WARMUP RUN FAILED (expected on the first live run of the design: R4-leftovers)"
  local w_id w_log="$LOGDIR/$prefix-run1-warmup.log"
  w_id=$(run_id_of_log "$w_log")
  [ -n "$w_id" ] || { echo "FATAL ($prefix): warmup run produced no run (see $w_log)"; return 1; }
  local w_scoped w_excluded
  w_scoped=$(run_scoped_rows "$w_log"); w_excluded=$(run_excluded_rows "$w_log")
  echo "$prefix warmup $w_id: scoped=$w_scoped excluded=$w_excluded"
  "$CHECKOUT/.venv/bin/python" "$CHECKOUT/skypilot/verify-agentgateway-run.py" \
    "$GUARDSCOPE_WORKDIR/runs/$w_id" \
    --execution "$GUARDSCOPE_WORKDIR/runs/$exp/execution.json" \
    --ready-ns "$ready_ns" --excluded "${w_excluded:-0}" --warmup \
    2>&1 | tee "$LOGDIR/$prefix-verify-warmup.log" || return 1

  # -- acceptance run (the measurement)
  fresh_sensor "$prefix" "$base" "$overlay" "$harness"
  guardscope run "$CHECKOUT/examples/$exp.yaml" 2>&1 \
    | tee "$LOGDIR/$prefix-run2-accepted.log"
  local a_rc=$?
  local a_id a_log="$LOGDIR/$prefix-run2-accepted.log"
  a_id=$(run_id_of_log "$a_log")
  [ -n "$a_id" ] || { echo "FATAL ($prefix): acceptance run produced no run (rc=$a_rc; see $a_log)"; return 1; }
  local a_scoped a_excluded
  a_scoped=$(run_scoped_rows "$a_log"); a_excluded=$(run_excluded_rows "$a_log")
  echo "$prefix acceptance $a_id: scoped=$a_scoped excluded=$a_excluded (warmup scoped=$w_scoped)"
  "$CHECKOUT/.venv/bin/python" "$CHECKOUT/skypilot/verify-agentgateway-run.py" \
    "$GUARDSCOPE_WORKDIR/runs/$a_id" \
    --execution "$GUARDSCOPE_WORKDIR/runs/$exp/execution.json" \
    --ready-ns "$ready_ns" --excluded "${a_excluded:-0}" \
    --expect-excluded "${w_scoped:-0}" \
    2>&1 | tee "$LOGDIR/$prefix-verify-accepted.log"
  local v_rc=$?

  # -- the formal L2 fidelity check against the acceptance topology (still up)
  "$CHECKOUT/.venv/bin/python" "$CHECKOUT/skypilot/fidelity-agentgateway.py" \
    --collector "${prefix}-agentgateway-trace" --checkout "$CHECKOUT" \
    --out "$LOGDIR/$prefix-fidelity-check.json" --publish \
    2>&1 | tee "$LOGDIR/$prefix-fidelity.log"
  local f_rc=$?

  # -- teardown (WITH the sensor profile: down without it leaves a host-wide
  #    tracee running and starves the next pair's eBPF buffers)
  docker compose "${COMPOSE[@]}" --profile sensor down -v \
    2>&1 | tee "$LOGDIR/$prefix-down.log"
  echo "=== pair $prefix done: run rc=$a_rc verify rc=$v_rc fidelity rc=$f_rc ==="
  [ "$a_rc" -eq 0 ] && [ "$v_rc" -eq 0 ] && [ "$f_rc" -eq 0 ]
}

mkdir -p "$LOGDIR"
RUN_PAIRS="${RUN_PAIRS:-t1-mock,t1-pi}"   # resume support: a pair list
if [[ ",$RUN_PAIRS," == *",t1-mock,"* ]]; then
  run_pair t1-mock compose/t1-mock.yaml plugins/agentgateway/overlay/t1-mock.yaml \
    t1-mock-agentgateway t1-mock \
    2>&1 | tee -a "$LOGDIR/pair-t1-mock.log" || { echo "FATAL: t1-mock pair failed"; exit 1; }
fi

if [[ ",$RUN_PAIRS," == *",t1-pi,"* ]]; then
  run_pair t1 compose/t1.yaml plugins/agentgateway/overlay/t1.yaml \
    t1-pi-agentgateway t1-pi \
    2>&1 | tee -a "$LOGDIR/pair-t1-pi.log" || { echo "FATAL: t1-pi pair failed"; exit 1; }
fi

echo "CAMPAIGN DONE — runs under $GUARDSCOPE_WORKDIR/runs, logs under $LOGDIR"
