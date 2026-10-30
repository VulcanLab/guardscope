# Ground-truth sensor: Tracee (privileged eBPF container)

Runs OUTSIDE the deployed topology (measurement instrument only; not reachable
from the agent per main.tex assumptions).

## Image

Pinned in `../env/versions.env` (`TRACEE_IMAGE` / `TRACEE_TAG`, currently
`aquasec/tracee:latest`, observed version v0.24.1 on the original local host). Requires
Linux >= 5.8 with BTF (`/sys/kernel/btf/vmlinux`), which
`../env/probe-server.sh` verifies.

NOTE: `aquasec/tracee:0.20.0` FAILS on the original local host's kernel (7.1.6 Asahi,
aarch64): `libbpf: prog 'tracepoint__sched__sched_process_exec': failed to
load: -22` → use `latest` (v0.24.1) instead. When pinning for reproducibility,
pin the image **digest** rather than the `latest` tag.

## Smoke test (M0 acceptance step — VALIDATED 2026-09-10)

Validated on the original local host (Fedora Asahi, kernel 7.1.6, aarch64). Tracee runs
detached; events go to the container console (table format by default):

```bash
# 1. Start the sensor (privileged, host pid/cgroup namespaces for enrichment)
docker run -d --name tracee-smoke --privileged --pid=host --cgroupns=host \
  -v /etc/os-release:/etc/os-release-host:ro \
  -v /var/run:/var/run:ro \
  aquasec/tracee:latest --scope container --events execve

# 2. Wait ~30 s (first-start eBPF warm-up is slow on this host), then trigger
#    a target container
sleep 30
docker run --name smoke-target alpine sh -c "sleep 600" &
sleep 60   # Tracee's console output flushes in large periodic batches

# 3. Verify capture: the target's execve appears with container ID + image
docker logs tracee-smoke 2>&1 | grep -F "sleep 600"
#   -> 02:50:06:... 6341dc95301c  alpine:latest 0  sh  ... execve
#      pathname: /bin/sleep, argv: [sleep 600], envp: []

# 4. Clean up
docker rm -f tracee-smoke smoke-target
```

Observed on the original local host (2026-09-10): eBPF loads; execve events from both
host-launched containers and long-running compose services are captured with
container ID, image name, UID, PID/TID (host namespaces), and full argv/envp.
Only warnings: missing `/boot/config-*` (KConfig assumed — harmless) and
cosmetic `--output json:<file>` path handling in this build (pipe or console
output verified working instead).

Operational notes for the measurement pipeline (M3+):

- Tracee's container-console output flushes in large batches (~30–90 s lag
  observed under low event volume); the JSON file/pipe output for real runs
  must account for this before reconciliation reads the stream.
- First-start eBPF warm-up takes tens of seconds; the runner should wait for
  Tracee's readiness signal before replaying traces.
- `--scope container=new` did not capture events on this host in our trials;
  `--scope container` (all containers) plus post-filtering by container ID is
  the verified working mode.
- A concurrent trivial `alpine sh -c "sleep 600"` container was observed with
  correct container context → container-context capture works.

A dedicated `compose/t0.yaml` wiring (sensor + harness containers) arrives in
M3; this file only pins the smoke procedure.

## Container-enrichment startup race (found 2026-10-06 on AWS EC2)

A container created DURING Tracee's first-start eBPF warm-up may never enter
Tracee's container cache: `--scope container` then silently drops ALL events
from that container (no events at all, ever — not a flush-lag effect).
Observed when `docker compose --profile sensor up` started the topology and
the sensor simultaneously: the harness container created ~0.2 s after Tracee
started produced zero events, while the one created ~0.3 s before it was
captured normally. Restarting the sensor after the topology is up fixes it
(all events captured immediately).

Bring-up order for every compose design (t0/t1/…). Designs with a
gateway slot (t1/t2/t3/t5) are placeholder bases + control-binding
overlays (DESIGN.md 7): merge the overlay AFTER the base (base first —
the overlay's relative build context resolves against the first compose
file's directory); t0/t4/t6 are single-file fixtures:

    # t0/t4/t6:
    docker compose -f compose/<design>.yaml up -d --build   # topology only
    # t1/t2/t3/t5 (base + the control's overlay):
    docker compose -f compose/<design>.yaml -f plugins/agt-gateway/overlay/<design>.yaml up -d --build
    # wait for harness containers to be healthy, then every design:
    docker compose -f compose/<design>.yaml [-f <overlay>] --profile sensor up -d tracee
    sleep 75                                                # eBPF warm-up

If the sensor ever starts with (or during) the topology, restart it once the
harness containers are healthy.

Fresh-host first-boot effects: on a brand-new environment the first run per
harness reconciles `fail` on R4 leftovers — first-boot writes (pi's
`~/.pi/agent/auth.json` + `models-store.json`, openclaw module-cache `.mjs`
opens, `getent` spawns, mcp-fs `__pycache__` compilation). One warm-up run
per harness (freshly recreated topology → one discarded run) makes the next
run reconcile clean. The original local host never showed this because its state was
already warm.

## M3 — Sensor wiring + mapping layer (done 2026-09-10)

### Components

- `tracee-args.sh` — canonical Tracee invocation (single source of truth;
  `--scope container --events execve,connect,sendto,security_file_open,write
  --output json`). Console/stdout JSON output is the verified mode on this
  host (`--output json:<file>` is broken in this build); Tracee log messages
  go to stderr, events flush in large batches (30–90 s lag observed).
- `Dockerfile.tracee` — `aquasec/tracee` pinned by digest (v0.24.1, validated
  in the M3 smoke) + the invocation script; used by the compose `tracee`
  service (privileged, `pid: host`, `cgroup: host`, NOT on `t0net`).
- `mapping/rules.yaml` — event → six-class mapping rules, pinned `version: 5`
  (v1 at M3; v4 live-validated in M4/M5; v5 (M6) adds `/workspace/replay/` to
  the file_write exclusions — adapter log/result writes are instrumentation).
  The version is embedded in run records so re-mapping stays reproducible.
- `mapping/map_events.py` — stateful mapper: raw Tracee NDJSON (file or
  stdin) → canonical action records (JSONL) with provenance (`raw_index`,
  `retval` — the M6 failed-command-lookup dedupe needs the syscall return
  value), plus an unmapped bucket (full record fields: ts/container/pid/
  process + best-effort path/port/flags detail, so M6 reconciliation's
  unrelated-event allowlists work without re-reading the raw stream) and a
  stderr summary line.
- `smoke_workload.py` — the M3 acceptance workload: performs all six action
  classes from container context and prints per-action ns bounds.

### Mapping notes (validated against real Tracee v0.24.1 events)

- `connect` carries the destination in `addr`; `sendto` in `dest_addr`
  (null-dest sends show `AF_UNSPEC` and stay unmapped). `sin_port` renders as
  a string; the parser accepts both.
- `security_file_open` renders `flags` as an int in v0.24.1 output; the mapper
  decodes int or text forms.
- Raw `write` events expose fd as an int and `buf` as an unresolvable
  pointer, so JSON-RPC payloads are NOT visible at syscall level. The
  `stdio_tool_call` heuristic therefore tracks the MCP tool-server process
  (execve argv marker `mcp-stdio/server.py`) and counts its writes to fd 1
  (stdout, the response pipe): 1 response write per JSON-RPC request in the
  sequential replay. The execve itself also maps as `process_spawn`, and each
  MCP fs tool call also produces `file_write` opens from the server process —
  expected multiplicity, reconciled in M6.
- Port lists in `rules.yaml` decide `http_tool_call` (:8080) vs
  `direct_network` (:9000 tcp, :9001 udp); other ports stay unmapped
  (DNS, health checks, co-tenant containers on this shared host).
- `/var/log/targets/` and `/tmp/tracee/` opens are excluded from
  `file_write` (target-internal instrumentation).

### M3 smoke (acceptance, validated 2026-09-10 on the original local host)

```bash
docker compose -f compose/t0.yaml --profile sensor up -d --build
sleep 40                                        # eBPF warm-up + first events
docker run --rm --network inspection-t0_t0net \
  -v $(pwd):/repo:ro python:3.12-slim \
  python3 /repo/sensor/smoke_workload.py        # prints per-action ns window
sleep 90                                        # Tracee batch-flush lag
docker logs t0-tracee 2>/dev/null > /tmp/tracee-raw.jsonl
python3 sensor/mapping/map_events.py \
  --in /tmp/tracee-raw.jsonl --out /tmp/mapped.jsonl
# stderr summary shows all six classes mapped; scope by the workload's
# [start_ns, end_ns] window on the `ts` field (epoch ns) to exclude unrelated
# co-tenant container events, then reconcile per class (M6).
```

Validated 2026-09-10: all six classes mapped within the workload window,
including exact canonical matches — `execve /bin/sh -c echo hi`,
`POST http-endpoint:8080` (2 connects), TCP :9000 + UDP :9001,
`file:///run/secrets/token` read, `/workspace/out/*` writes
(O_WRONLY|O_CREAT|O_TRUNC), and 3 MCP stdio response writes (initialize + 2
tool calls).
