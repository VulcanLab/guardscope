# C4 — Side-effect targets (M2)

Deterministic (no LLM) targets exercised by the canonical trace
`../trace/traces/baseline.yaml`. Every served action is logged as one JSON
line (see `common.py`) so reconciliation (M6) can debug expected-vs-observed
mismatches from first-class artifacts.

| Target (dir) | Trace class | Runs as | Serves |
|---|---|---|---|
| `mcp-stdio/` | `stdio_tool_call` | harness-child process (stdio; wired into harness MCP config in M4/M5) | MCP tools `write_file`, `read_file`, `list_directory` (newline-delimited JSON-RPC 2.0) |
| `mcp-agent/` | (the F3 delegation fixture's target-side addition; rides no canonical class) | harness-child process, opened only for the fixture's `tool-agent`-performed actions (adapter env `F3_SERVER_CMD`) | MCP tool `run_task`: an ordinary-looking local tool whose internal agent performs the handed effects beyond the tool's response and writes its hand-off records |
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
| `TARGET_LOG_DIR` | /var/log/targets | all targets (log-file writer) |
| `SECRETS_DIR` | /run/secrets | credentials/seed.sh |
| `WORKSPACE_DIR` | /workspace | fs/setup.sh |

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