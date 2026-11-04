# C4 — Side-effect targets (M2)

Deterministic (no LLM) targets exercised by the canonical trace
`../trace/traces/baseline.yaml`. Every served action is logged as one JSON
line (see `common.py`) so reconciliation (M6) can debug expected-vs-observed
mismatches from first-class artifacts.

| Target (dir) | Trace class | Runs as | Serves |
|---|---|---|---|
| `mcp-stdio/` | `stdio_tool_call` | harness-child process (stdio; wired into harness MCP config in M4/M5) | MCP tools `write_file`, `read_file`, `list_directory` (newline-delimited JSON-RPC 2.0) |
| `mcp-agent/` | (the F3 delegation fixture's target-side addition; belongs to no canonical class) | harness-child process, opened only for the fixture's `tool-agent`-performed actions (adapter env `F3_SERVER_CMD`) | MCP tool `run_task`: an ordinary-looking local tool whose internal agent performs the handed effects beyond the tool's response and writes its hand-off records |
| `mcp-agent/` (the `http-server.py` sibling) | (the F4 remote delegation fixture; belongs to no canonical class) | its own compose service on the EXECUTOR host of the two-host topology (`compose/executor.yaml`, port 8091) — never a harness child: the hand-off crosses the network | HTTP `POST /task`: the same hidden-agent pattern over HTTP; the far server's internal agent performs the effects ON ITS OWN MACHINE and writes its acceptance records with `machine: "executor"` |
| `a2a-agent/` | (the F5 remote delegation fixture; belongs to no canonical class) | its own compose service on the EXECUTOR host of the two-host topology (`compose/executor.yaml`, port 8092) | A2A-style task submission (`message/send`, v1 synchronous): the far agent performs the effects on its own machine and returns the report as the completed task's artifact |
| `http-endpoint/` | `http_tool_call` | compose service `http-endpoint:8080` | `POST /hook`, `GET /health`, `PUT /state` |
| `net-peer/` | `direct_network` | compose service `net-peer` | TCP :9000, UDP :9001 (echo/ack) |
| `credentials/` | `credential_access` | in-harness-container files via `seed.sh` | `/run/secrets/token`, `/run/secrets/db_password` |
| `fs/` | `file_write` | in-harness-container paths via `setup.sh` | `/workspace/out/` |

## Logging

Each target writes one JSON object per event: `{"ts", "target", "event", ...}`.

- Console: stdout (`docker logs`) for HTTP/net-peer; **stderr** for the MCP
  stdio server (its stdout is protocol-only per the MCP stdio transport spec).
- `$TARGET_LOG_DIR/<target>.log` (default `/var/log/targets/`): the compose
  `target-logs` volume, shared by all containers, is the reconciliation-facing
  writer.

## Ports and paths (override via env)

| Env var | Default | Used by |
|---|---|---|
| `HTTP_PORT` | 8080 | http-endpoint |
| `NET_TCP_PORT` / `NET_UDP_PORT` | 9000 / 9001 | net-peer |
| `F4_LISTEN_PORT` | 8091 | mcp-agent/http-server.py (the executor host) |
| `A2A_LISTEN_PORT` | 8092 | a2a-agent (the executor host) |
| `TARGET_LOG_DIR` | /var/log/targets | all targets (log-file writer) |
| `SECRETS_DIR` | /run/secrets | credentials/seed.sh |
| `WORKSPACE_DIR` | /workspace | fs/setup.sh |

## The remote hand-off's routing (F4/F5)

The remote servers are ORDINARY HTTP endpoints from the adapter's
perspective; whether the hand-off crosses an enforcement point is the
deployment DESIGN's business, not the fixtures':

- unset `GATEWAY_URL` (the t0-remote overlay's shape): the adapter POSTs
  the remote server directly.
- `GATEWAY_URL` set: the hand-off crosses the gateway as MCP `tools/call`
  (routes `f4_remote_task` / `f5_remote_task`, gateway/server.py
  `REMOTE_TOOL_ROUTES`); the gateway enforces the call and PROXIES the
  plain HTTP request to the remote server (the deployed policy must
  allow the route names, exactly like any other tool). The gateway needs
  `F4_TOOL_SERVER_URL` / `F5_AGENT_SERVER_URL` in ITS env for the
  routes' addresses.
- `T4_MODE`/`T6_MODE` set: the remote call is a REAL harness tool call
  (`f4_remote_tool` / `f5_remote_agent`, registered by the adapter
  extension) — it crosses pi's tool pipeline, so the `tool_call` hook
  (the enforcement point) fires on it.

The per-action response cycle (connect + headers + BODY READ + parse) is
bounded by the adapter's 20 s action timeout
(`INSPECTION_ACTION_TIMEOUT_MS` overrides it for the offline tests).

## Compose

```bash
docker compose -f compose/t0.yaml up -d --build
docker compose -f compose/t0.yaml ps
docker compose -f compose/t0.yaml down -v   # -v also clears target-logs
```

Smoke: `docker compose -f compose/t0.yaml exec http-endpoint python3 -c
"import urllib.request; print(urllib.request.urlopen('http://localhost:8080/health').read())"`.

## M2 acceptance

Each target observably logs what it serves (validated by
`tests/test_targets.py`, which exercises all of them locally without Docker);
no target requires LLM involvement. MCP stdio + credential/workspace targets
are in-container processes by design (they must run inside the harness
container in M4/M5 so Tracee attributes their events to harness context);
http-endpoint and net-peer are standalone compose services on `t0net`.