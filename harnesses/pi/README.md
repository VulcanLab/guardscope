# Pi replay adapter (M5)

Replay injection for the Pi coding harness (C2, C3): the canonical trace is
executed **inside the pi agent process** — no LLM anywhere. (OpenCode was
spiked first and deferred: 1.18.30 has no no-LLM tool-execute route; see the
implementation-plan M5 note.)

## Injection point (validated 2026-09-10, pi 0.85.1)

```
driver (runner/trigger_pi.py)
  └─ docker exec -i t0-pi pi --mode rpc --no-session -e /opt/inspection/adapter/replay.ts
       └─ RPC over stdin/stdout: {"type":"prompt","message":"/inspection-replay <path>"}
            └─ pi process (inspection-replay extension command — executes
               immediately via RPC, no agent run, docs/rpc.md)
                 ├─ spawn python3 MCP stdio server   (pi child -> Tracee pid)
                 ├─ fetch() to http-endpoint         (connection-pooled)
                 ├─ net/dgram to net-peer            (tcp_connect / sendmsg + net_packet_udp)
                 ├─ execFile /bin/sh, /bin/echo      (pi children)
                 ├─ fs.writeFile /workspace/out/*    (pi process)
                 └─ fs.readFile /run/secrets/*       (pi process)
```

- Extension commands are the documented no-LLM surface: "If the message is an
  extension command (e.g. `/mycommand`), it executes immediately even during
  streaming" (pi docs/rpc.md). The driver sends one `prompt` command and waits
  for the matching `response`.
- The container entrypoint only seeds targets and sleeps; **one pi RPC process
  is execed per replay run**, so the pi process lifetime ≈ the replay window
  (clean Tracee scoping; no harness-internal idle noise).
- The adapter is TypeScript loaded via jiti (`pi -e`); no transpile step.
- Global extensions do not exist in the container (fresh `~/.pi`), so no
  user-extension noise.

## Replay contract (same as OpenClaw, M4)

- Input: compiled trace JSON (see `../../trace/compile/pi/compile.py`), staged
  by the driver at `/workspace/replay/compiled.json` (bind: `runs/pi/`).
- Output: `replay-result.json` written by the adapter to `REPLAY_LOG_DIR`
  (host: `runs/pi/`) with `{ok, executed, failed, window_ns, window_epoch_ns,
  replay_log, results[]}`; `window_epoch_ns` scopes the Tracee stream for
  reconciliation (`ts` is epoch ns).
- Replay log: JSONL at `$REPLAY_LOG_DIR/replay-log.jsonl` (mark-start /
  mark-end + one record per action: id/class/op/started_ns/status/detail/error
  + started_epoch_ns).
- Env knobs: `REPLAY_LOG_DIR`, `MCP_SERVER_CMD` (JSON argv array).
- The compiled plan (kind + arguments per action) is identical to OpenClaw's
  (enforced by a compiler test), so both adapters execute the same action
  surface from the same canonical spec.

## Gotchas (found live, 2026-09-10)

- pi runs on **Node, not Bun** — use `node:child_process` etc., not `Bun.*`.
- The container runs as root; artifacts it writes into the bind-mounted
  `runs/pi/` are root-owned. The driver pre-creates the dir as the host user,
  cleans stale files via `docker exec`, and chowns the dir back to the host
  uid after each run (same class of issue as the M4 target-logs gotcha).
- Bring the network targets up before replaying (`docker compose up -d`):
  `fetch failed` / `getaddrinfo ENOTFOUND net-peer` mean the targets are down,
  not a DNS problem.
- Stale `replay-result.json` from a failed run silently poisons the next run's
  poll — the driver removes it via `docker exec` before staging.
- `sudo` is not passwordless on the original local host; never rely on host-side sudo for
  cleanup of root-owned bind-mount files — go through `docker exec`.

## Kernel-level multiplicities (for M6 reconciliation)

Same classes as OpenClaw (M4) plus one pi-specific finding:

- **stdio**: initialize handshake response + 3 tool-call responses → 4 writes
  from the MCP python3 child (a001–a003).
- **process_spawn (pi-specific)**: node/pi resolve commands through the PATH,
  and Tracee records each `execve` attempt — the pi shim (`/usr/local/bin/pi`
  → `node`) and the MCP server launch (`python3` from PATH) appear as 4 execve
  records each (ENOENT PATH probes included) before the successful exec.
  Reconciliation must dedupe execve probes per successful exec.
- **http**: node `fetch` pools connections → 3 http_tool_call actions share 1
  `connect` to :8080.
- **file_write**: double `security_file_open` per write action (open +
  re-open); same for credential_access (each read opens twice).
- **udp**: dgram sends via `sendmsg` (unparsed destination); `net_packet_udp`
  (`dst_port`) is the UDP observation.
- runc/container-start `execve` + `/proc/*/oom_score_adj` noise appears inside
  the window (compose restarts, driver chown) — window/container/process scoping
  in M6 reconciliation handles it (same as the OpenClaw profile).

## Usage

```bash
docker compose -f compose/t0.yaml up -d --build pi              # harness + targets
python3 -m pytest tests/test_compile_pi.py -v                   # 14 compiler tests
python3 runner/trigger_pi.py --compile                          # compile + replay + read result
# under Tracee: --profile sensor up, replay, wait ~90s for flush,
# docker logs t0-tracee > runs/pi/tracee-events.json, then map_events.py
```