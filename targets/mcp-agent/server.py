#!/usr/bin/env python3
"""Toy MCP stdio server with an agent hiding inside (the F3 delegation
fixture, the study's scenario class S3 local): targets/mcp-stdio/server.py's
sibling, same wire protocol, same shape of an ordinary local tool server —
but its run_task tool is secretly an agent. The tool call arrives from the
replay adapter looking like every ordinary tool call (the same NDJSON
JSON-RPC on stdin/stdout, the same tools/list shape, the same carriers on
the wire); the server's INTERNAL agent performs its own effects beyond the
tool's response (the network connects, process starts, file writes the
caller never asked the tool to make visible), writes its acceptance record
(delegation-record/1), and only then answers.

The hand-off records:
  - the ADAPTER (harnesses/pi/adapter/replay.ts) writes the "sent" line
    before the tools/call — channel "tool", protocol "mcp", carrier
    "mcp_meta" (the delegation id travels in the same tools/call _meta the
    action id travels in, so the call stays byte-shaped like every ordinary
    tool call);
  - THIS server writes the "accepted" line the moment its internal agent
    takes the work — before performing the effects, so a hand-off the
    server took and then failed on stays visible.

The chain ids travel on the tools/call _meta (the mcp_meta carrier):
  io.inspection/delegation_id         this hand-off's id (required — no
                                      id means no hand-off happened: the
                                      server refuses, never invents one)
  io.inspection/root_delegation_id    the chain root (defaults to this id)
  io.inspection/hop                   the hop count (defaults to 1)

The effects are the process-level executor semantics of the harness side
(harnesses/pi/f2-helper.py perform_action): file writes, TCP connects, UDP
sends, program starts. A tool-transport kind or an unsupported kind in a
run_task step is a fixture mistake and is refused, not improvised.

Everything is additive: this is a NEW server file, not a mode on the
existing toy-mcp-fs server — the existing baseline runs' behavior does not
change (targets/mcp-stdio/server.py is untouched; the adapter opens this
server only for the F3 fixture's tool-agent-performed actions, F3_SERVER_CMD
env, default this file's in-container copy). Dependency-free (stdlib only)
for reproducibility, like the toy servers.

Run stand-alone (what the tests do; no container needed):
    REPLAY_LOG_DIR=/tmp/x INSPECTION_RUN_ID=r python3 server.py
"""

import itertools
import json
import os
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path

SERVER_NAME = "toy-mcp-agent"
SERVER_VERSION = "0.1.0"
SUPPORTED_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18"]
LATEST_SUPPORTED = SUPPORTED_VERSIONS[-1]

RECORDS_NAME = "delegation-records.jsonl"
META_DELEGATION_ID = "io.inspection/delegation_id"
META_ROOT_DELEGATION_ID = "io.inspection/root_delegation_id"
META_HOP = "io.inspection/hop"
# per-stream monotonic seq (delegation-record/1): this server process is
# one stream (stream_id toy-mcp-agent-<pid>); repeated hand-offs in the
# same process must not repeat seq 0
_ACCEPT_SEQ = itertools.count()

# Mirrors the harness-side executors' per-kind timeouts
# (harnesses/pi/adapter/replay.ts ACTION_TIMEOUT_MS).
ACTION_TIMEOUT_S = 20

# Crockford base32 (the delegation-record/1 record_id alphabet: no I, L, O, U)
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _text_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


def _error_result(message: str) -> dict:
    return {"content": [{"type": "text", "text": json.dumps(
        {"status": "error", "error": message})}], "isError": True}


TOOLS = [
    {
        "name": "run_task",
        "description": ("Run a task: a list of steps (file writes, network "
                        "connects, program starts) performed by the "
                        "server's task runner."),
        "inputSchema": {
            "type": "object",
            "required": ["steps"],
            "properties": {
                "steps": {
                    "type": "array",
                    "description": "The task's steps.",
                    "items": {"type": "object"},
                },
            },
        },
    },
]


# --- the delegation record (the server's side of the hand-off) --------------------

def ulid() -> str:
    """record_id (delegation-record/1): a ULID — 48-bit millisecond
    timestamp + 80 random bits, Crockford base32, 26 chars."""
    raw = int.from_bytes(os.urandom(10), "big")
    val = (int(time.time() * 1000) << 80) | raw
    return "".join(_CROCKFORD[(val >> (5 * i)) & 31] for i in range(25, -1, -1))


def now_rfc3339_ms() -> str:
    dt = datetime.now(timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def task_digest(step_ids: list) -> str:
    """A digest of the handed task (the step ids, no payloads) — computed
    the same way the adapter does, so the two sides' records join on it."""
    payload = json.dumps(sorted(str(i) for i in step_ids),
                         separators=(",", ":"))
    return sha256(payload.encode()).hexdigest()[:16]


def write_accepted_record(meta: dict, run_id: str, step_ids: list) -> None:
    """Append the internal agent's acceptance line to the replay volume's
    delegation record stream (delegation-record/1, exactly the frozen
    schema). Record emission must never break the tool response (a lost
    line is a reported problem downstream, never a lost effect)."""
    did = meta.get(META_DELEGATION_ID)
    log_dir = Path(os.environ.get("REPLAY_LOG_DIR", "/workspace/replay"))
    log_dir.mkdir(parents=True, exist_ok=True)
    rec = {
        "schema": 1,
        "record_id": ulid(),
        "run_id": run_id,
        "stream_id": f"{SERVER_NAME}-{os.getpid()}",
        "seq": next(_ACCEPT_SEQ),
        "ts": now_rfc3339_ms(),
        "event": "accepted",
        "channel": "tool",
        "delegation_id": did,
        "parent_delegation_id": None,
        "root_delegation_id": meta.get(META_ROOT_DELEGATION_ID) or did,
        "hop": int(meta.get(META_HOP, 1)),
        "from_actor": "pi-root",
        "to_actor": "f3-tool-agent",
        "task_digest": task_digest(step_ids),
        "protocol": "mcp",
        "machine": "origin",
        "carrier": "mcp_meta",
        "actor_pid": os.getpid(),
    }
    with open(log_dir / RECORDS_NAME, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


# --- the effects (the same executor semantics as the harness side) ---------------

def perform_step(step: dict) -> dict:
    """Perform one task step's effect from this process (the server's
    internal agent performing its own effects beyond the tool's
    response). The kinds are the process-level effect ones; a
    tool-transport kind here is a fixture mistake and is refused."""
    kind = step.get("kind")
    if kind == "file_write":
        path = Path(step["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        data = step.get("data", "")
        if step.get("append"):
            with open(path, "a", encoding="utf-8") as f:
                f.write(data)
        else:
            path.write_text(data, encoding="utf-8")
        return {"path": str(path), "bytes": len(data.encode())}
    if kind == "tcp_connect":
        with socket.create_connection((step["host"], int(step["port"])),
                                      timeout=ACTION_TIMEOUT_S) as sock:
            sock.sendall(step.get("payload", "").encode())
        return {"host": step["host"], "port": int(step["port"])}
    if kind == "udp_send":
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(step.get("payload", "").encode(),
                        (step["host"], int(step["port"])))
        return {"host": step["host"], "port": int(step["port"])}
    if kind == "spawn":
        proc = subprocess.run(step["cmd"], capture_output=True,
                              timeout=ACTION_TIMEOUT_S)
        if proc.returncode != 0:
            raise RuntimeError(
                f"spawned {step['cmd']} exited {proc.returncode}")
        return {"cmd": step["cmd"]}
    raise ValueError(f"unsupported kind {kind!r} for a tool-agent-performed "
                     f"action {step.get('id')!r}")


def run_task(args: dict, meta: dict) -> dict:
    """The hidden agent: take the hand-off, record the acceptance, perform
    the effects, and answer like an ordinary tool. The response text IS
    the agent's report (JSON) — the adapter parses it and keeps the
    delegation_id echo, so the run's per-action trace-back joins on the
    exact echo like every other fixture."""
    did = (meta or {}).get(META_DELEGATION_ID)
    if not did or not str(did).strip():
        return _error_result("no delegation id on the tools/call _meta — "
                            "this call was dispatched without a hand-off "
                            "(the mcp_meta carrier is missing)")
    steps = args.get("steps")
    if not isinstance(steps, list) or not steps:
        return _error_result("run_task needs a non-empty 'steps' list")
    run_id = os.environ.get("INSPECTION_RUN_ID", "unattributed")

    # 1. the acceptance: the internal agent took the work — BEFORE the
    #    effects, so a taken-and-failed hand-off stays visible
    write_accepted_record(meta, run_id, [s.get("id") for s in steps])

    # 2. the effects, one result row per step (ok detail | error); a
    #    failed effect is a result, not a broken tool
    results = []
    for step in steps:
        try:
            results.append({"id": step.get("id"), "status": "ok",
                            "detail": perform_step(step)})
        except Exception as exc:
            results.append({"id": step.get("id"), "status": "error",
                            "error": str(exc)})
    ok = all(r["status"] == "ok" for r in results)
    report = {"status": "ok" if ok else "error",
              "delegation_id": str(did),
              "actor": "f3-tool-agent",
              "results": results}
    if not ok:
        report["error"] = "; ".join(
            f"{r['id']}: {r['error']}" for r in results
            if r["status"] == "error")
    return _text_result(json.dumps(report, sort_keys=True))


# --- the stdio MCP loop (same wire protocol as the toy fs server) ----------------

def call_tool(name: str, args: dict, meta: dict) -> dict:
    if name == "run_task":
        return run_task(args, meta)
    raise KeyError(name)


def handle(msg: dict) -> dict | None:
    method = msg.get("method", "")
    if "id" in msg:  # request -> response
        if method == "initialize":
            requested = (msg.get("params") or {}).get("protocolVersion", "")
            version = requested if requested in SUPPORTED_VERSIONS else LATEST_SUPPORTED
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME,
                               "version": SERVER_VERSION},
            }}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}}
        if method == "tools/call":
            params = msg.get("params") or {}
            try:
                result = call_tool(params["name"], params.get("arguments") or {},
                                   params.get("_meta") or {})
                return {"jsonrpc": "2.0", "id": msg["id"], "result": result}
            except KeyError:
                return {"jsonrpc": "2.0", "id": msg["id"], "error": {
                    "code": -32602, "message": f"unknown tool: {params.get('name')}"}}
            except (OSError, ValueError) as exc:
                return {"jsonrpc": "2.0", "id": msg["id"], "error": {
                    "code": -32000, "message": str(exc)}}
        return {"jsonrpc": "2.0", "id": msg["id"], "error": {
            "code": -32601, "message": f"method not found: {method}"}}
    # notifications: no response
    return None


def main() -> None:
    # stderr is the only console writer: stdout carries protocol messages
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stdout.write(json.dumps(
                {"jsonrpc": "2.0", "id": None, "error": {
                    "code": -32700, "message": f"parse error: {exc}"}}) + "\n")
            sys.stdout.flush()
            continue
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, separators=(",", ":")) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    main()
