#!/usr/bin/env bash
# The t7/t2 acceptance re-check (run ON the instance, user ubuntu, AFTER
# provision-t7-host.sh stage 2 and the repo rsync to ~/guardscope).
# t7: the actplane binding (examples/t7-actplane.yaml) — warmup run then
#     the accepted measurement (the README's warmup rule); expect PASS,
#     R1-R5 green, C6 denials_confirmed=1 (a032), counts 6 checked-allowed
#     / 1 checked-denied / 8 bypassed / 0 prevented, R5 "minus kernel-denied
#     ['a032']" (commit 3ff787d).
# t2: the agt-gateway binding (examples/t2-pi.yaml) — same warmup rule;
#     the egress-jail prevented path must still fire live (2 prevented:
#     a021/a022-class outcomes, untouched by the taxonomy change).
#
# 2026-11-03 fix: run 1 fired ZERO control events — the 0.4 s trace window
# raced the actplane engine's post-load readiness (the acceptance session
# was driven manually, minutes after bring-up; this script runs seconds
# after `compose up`). The t7 path now waits for the control's readiness
# AND proves enforcement with a live kill probe (exec /bin/echo must be
# killed by the kill arm) before running the experiment.
set -uxo pipefail

CHECKOUT="$HOME/guardscope"
LOGDIR="$HOME/recheck-logs"
mkdir -p "$LOGDIR"
cd "$CHECKOUT"
python3 -m venv .venv
.venv/bin/pip install -q -e .
export PATH="$CHECKOUT/.venv/bin:$PATH"

export GUARDSCOPE_WORKDIR="$HOME/experiments/guardscope"
export GUARDSCOPE_STAGING_DIR="$HOME/experiments/guardscope/runs"
mkdir -p "$GUARDSCOPE_WORKDIR"
cd "$GUARDSCOPE_WORKDIR"

bash "$CHECKOUT/env/check-server.sh" 2>&1 | tee "$LOGDIR/env-check.log"

kc_ready () {
  # capture-then-grep (never pipe docker logs into grep -q: grep exits
  # early, docker logs takes SIGPIPE, and pipefail turns it into a
  # false "not ready")
  docker logs t7-kernel-control > /tmp/kc.log 2>&1
  grep -q "control up; waiting for termination" /tmp/kc.log
}

wait_t7_ready () {
  # 1. the supervisor must report "control up"
  for _ in $(seq 1 60); do
    kc_ready && break
    sleep 1
  done
  kc_ready || { echo "FATAL: kernel control never came up"; return 1; }
  # 2. enforcement must actually work: a probe exec of /bin/echo (the kill
  #    arm's target) must produce a kill event
  docker exec t7-kernel-control sh -c \
    ': > /var/log/control/actplane-events.log' || return 1
  for _ in $(seq 1 30); do
    docker exec t7-pi sh -c 'exec /bin/echo readiness-probe' \
      >/dev/null 2>&1 || true
    sleep 1
    if docker exec t7-kernel-control sh -c \
        'grep -q "\"effect\":\"kill\"" /var/log/control/actplane-events.log'; then
      echo "t7 control READY: kill arm fired on the probe exec"
      # clean the probe events out of the streams the runs will read
      docker exec t7-kernel-control sh -c \
        ': > /var/log/control/actplane-events.log; : > /var/log/control/decisions.jsonl'
      return 0
    fi
  done
  echo "FATAL: t7 kill-arm probe never fired"; return 1
}

fresh_sensor () {  # $1=design  $2=base  $3=overlay
  # capture_tracee dumps the tracee container's docker log FROM ITS START:
  # recreate the sensor before each run so the capture covers only that
  # run (a long-lived tracee accumulates the harness-startup noise storms
  # into multi-GB dumps and mapping stalls for tens of minutes).
  # ALSO: Tracee needs ~10s to initialize before events flow (observed
  # live 2026-11-03: the 0.4 s trace outran it and the run lost all kernel
  # evidence), so wait until its log carries an event.
  docker compose -f "$CHECKOUT/compose/$2" -f "$CHECKOUT/$3" \
    --profile sensor up -d --force-recreate tracee 2>&1 | tail -1
  local c="${1}-tracee"
  for _ in $(seq 1 90); do
    docker logs "$c" > /tmp/tracee-probe.log 2>&1 || true
    grep -q '"eventName"' /tmp/tracee-probe.log && break
    sleep 1
  done
  grep -q '"eventName"' /tmp/tracee-probe.log \
    || echo "WARN: tracee never emitted an event"
}

run_pair () {  # $1=design  $2=base  $3=overlay  $4=experiment
  cd "$GUARDSCOPE_WORKDIR"
  # pre-create the staging subdirs the compose files mount: docker creates
  # missing host mount points as ROOT, which then blocks the runner's
  # compile step (writes compiled.json as user ubuntu)
  mkdir -p "$GUARDSCOPE_STAGING_DIR/pi" "$GUARDSCOPE_STAGING_DIR/openclaw"
  docker compose -f "$CHECKOUT/compose/$2" -f "$CHECKOUT/$3" up -d \
    2>&1 | tee "$LOGDIR/$1-up.log"
  docker compose -f "$CHECKOUT/compose/$2" -f "$CHECKOUT/$3" \
    --profile sensor up -d tracee 2>&1 | tee "$LOGDIR/$1-sensor.log"
  if [ "$1" = "t7" ]; then
    wait_t7_ready || exit 1
  else
    sleep 20   # gateway settle: no kernel load to wait for
  fi
  fresh_sensor "$1" "$2" "$3"
  guardscope validate "$CHECKOUT/examples/$4" \
    2>&1 | tee "$LOGDIR/$1-validate.log"
  # warmup: the first live run of the design fails the leftover check BY
  # DESIGN (README); its nonzero exit must not abort the script
  guardscope run "$CHECKOUT/examples/$4" 2>&1 \
    | tee "$LOGDIR/$1-run1-warmup.log" || echo "warmup failed (expected on first run)"
  # the accepted measurement (fresh sensor again: the warmup's capture is
  # done, the noise between runs stays out of this capture)
  fresh_sensor "$1" "$2" "$3"
  guardscope run "$CHECKOUT/examples/$4" 2>&1 \
    | tee "$LOGDIR/$1-run2-accepted.log"
  docker compose -f "$CHECKOUT/compose/$2" -f "$CHECKOUT/$3" down -v \
    2>&1 | tee "$LOGDIR/$1-down.log"
}

run_pair t7 t7.yaml plugins/actplane/overlay/t7.yaml t7-actplane.yaml
run_pair t2 t2.yaml plugins/agt-gateway/overlay/t2.yaml t2-pi.yaml

echo "RECHECK DONE — artifacts under $GUARDSCOPE_WORKDIR/runs, logs under $LOGDIR"
