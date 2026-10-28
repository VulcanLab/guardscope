# OpenClaw replay adapter (M4)

Replay injection for the OpenClaw harness (C2, C3): the canonical trace is
executed **inside the OpenClaw gateway process** — no LLM anywhere.

## Injection point (validated 2026-09-10, OpenClaw 2026.9.3)

```
driver (runner/trigger_openclaw.py)
  └─ POST /tools/invoke {tool: "replay_trace", args: {trace: <compiled>}}
       └─ gateway process (inspection-replay plugin, api.registerTool)
            ├─ spawn python3 MCP stdio server   (harness child -> Tracee pid 128)
            ├─ fetch() to http-endpoint         (connection-pooled)
            ├─ net/dgram to net-peer            (tcp_connect / sendmsg + net_packet_udp)
            ├─ execFile /bin/sh, /bin/echo      (harness children)
            ├─ fs.writeFile /workspace/out/*    (gateway process)
            └─ fs.readFile /run/secrets/*       (gateway process)
```

- `POST /tools/invoke` is an always-enabled, gateway-auth + tool-policy-gated
  endpoint for invoking a single tool without an agent turn — the documented
  extension surface for exactly this driver-driven injection.
- The plugin is installed from `adapter/` (`openclaw plugins install`, digest-
  pinned base image). `typebox` is vendored into the plugin's `node_modules/`
  from the image's pnpm store (`cp -rL`; a plain copy follows the dangling
  pnpm symlink).
- Tool execution happens in the gateway process; child processes (MCP server,
  /bin/sh, /bin/echo) are therefore harness children and Tracee attributes
  them to container `t0-openclaw`.

## Replay contract

- Input: compiled trace JSON (see `../../trace/compile/openclaw/compile.py`),
  posted as the `trace` argument. Output: `{ok, executed, failed, window_ns,
  window_epoch_ns, replay_log, results[]}`; `window_epoch_ns` scopes the
  Tracee stream for reconciliation (`ts` field is epoch ns).
- Replay log: JSONL at `$REPLAY_LOG_DIR/replay-log.jsonl` (marks + one record
  per action: id/class/op/started_ns/status/detail/error + started_epoch_ns).
- Env knobs: `REPLAY_LOG_DIR`, `MCP_SERVER_CMD` (JSON argv array).

## Gotchas (found live, 2026-09-10)

- The gateway process must run with `HOME=/home/node` even when started as
  root via `setpriv` (it stats `~/.openclaw/state/...`).
- `curl` from the host to `POST /tools/invoke` works; Python's `urllib` sends
  header sets the gateway closes the connection on — the driver uses raw
  `http.client` instead.
- Host port 18789 is reserved by real deployments (the user's gateway binds
  it); compose publishes the testbed gateway on 127.0.0.1:28789.
- Plugin log volume: the in-harness MCP server (node user) appends its
  served-action log to the shared `target-logs` volume owned by root-running
  target services; `targets/common.py` tolerates the permission error and the
  entrypoint chowns the dir to node.
- Python's `urllib`-triggered RemoteDisconnected, the `rej`/`reject` typo that
  crashed the gateway on first use, and the pnpm symlink copy are all
  recorded here because the M5 (OpenCode) adapter will hit the same class of
  issues.

## Kernel-level multiplicities (for M6 reconciliation)

- **stdio**: 1 response write per JSON-RPC request, PLUS the initialize
  handshake response → 4 writes for a003+initialize+2 tool calls (a001/a002).
  The MCP server execve also maps as `process_spawn`.
- **http**: node `fetch` pools connections → 3 http_tool_call actions share
  1 `connect` to :8080 (action-level ≠ kernel-connection-level).
- **file_write**: every MCP fs tool call also opens the target file from the
  server process (write mode) → 2 file_write observations per write action.
  Direct writes (a041/a042) show open + write each.
- **udp**: node dgram sends via `sendmsg`, whose destination Tracee 0.24 does
  not parse; `net_packet_udp` (parsed `dst_port`) is the UDP observation, and
  each datagram may appear twice (egress/loopback capture).

## Usage

```bash
docker compose -f compose/t0.yaml up -d --build openclaw      # harness + targets
python3 runner/trigger_openclaw.py --compile                  # compile + replay + save result
```

## M6-era gotchas (found live, 2026-09-10)

- `POST /tools/invoke` wraps the tool response: the reply is
  `{ok, result: <replay result>}`; `runner/trigger_openclaw.py` unwraps
  `result` so the saved replay-result.json matches the adapter contract.
- Shared target-log volume across harnesses: the `toy-mcp-fs.log` /
  `http-endpoint.log` / `net-peer.log` files may be owned by the OTHER
  harness's user (pi runs as root, this gateway as node). An append from
  the wrong user fails silently (`targets/common.py` tolerates OSError) and
  the served-action evidence vanishes. Chown the `*.log` files to `node`
  (plus `chmod a+w`) inside this container before replaying
  (`docker exec t0-openclaw chown node:node /var/log/targets/*.log`).
- The gateway is long-lived: HTTP connection pooling can carry a `connect`
  from a PREVIOUS replay, so a run's window may contain 0 new connects to
  :8080 (profile `http_connects_min: 0`).
