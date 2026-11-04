#!/usr/bin/env python3
"""The F5 delegation fixture's REMOTE agent server (the study's scenario
class S5): a small HTTP server that accepts a task submission over the
A2A-style agent-to-agent protocol and performs the effects ON ITS OWN
MACHINE (the executor host of the two-host topology,
compose/executor.yaml). The pi replay adapter
(harnesses/pi/adapter/replay.ts) submits each remote-agent-performed
action of the F5 trace variant (trace/traces/baseline-f5.yaml) as a task
message; the far agent takes the work, writes its acceptance record
(delegation-record/1, machine "executor"), performs the network
connects, process starts and file writes the caller never asked it to
make visible, and returns the artifacts.

The protocol (v1, simplified): one JSON-RPC envelope over HTTP POST —
    {"jsonrpc": "2.0", "id": 1, "method": "message/send",
     "params": {"message": {"messageId": ...,
                             "metadata": {"io.inspection/delegation_id": ...,
                                          "io.inspection/root_delegation_id": ...,
                                          "io.inspection/hop": 1,
                                          "io.inspection/run_id": ...},
                             "data": {"steps": [...]}}}}
The response returns the COMPLETED task synchronously (submit-and-get-
result in one round trip, the v1 simplification of the submit/poll/get
flow the real A2A protocol runs):
    {"jsonrpc": "2.0", "id": 1,
     "result": {"id": <task id>, "status": {"state": "completed"},
                "artifacts": [{"name": "report", "data": <the report>}]}}
The report's delegation_id is the exact echo the adapter keeps, so the
run's per-action trace-back joins on it like every other fixture.

The hand-off records:
  - the ADAPTER (on the origin machine) writes the "sent" line BEFORE the
    submission — channel "network" (the study's agent-to-agent boundary
    class), protocol "a2a", carrier "queue_payload", machine "origin";
  - THIS server (on the executor machine) writes the "accepted" line the
    moment it takes the work — BEFORE performing the effects, machine
    "executor" — so a hand-off the agent took and then failed on stays
    visible. The chain ids ride the task message's metadata (the
    queue_payload carrier: the submitted message IS what travels).

A submission without a delegation id in the message metadata means no
hand-off happened: the agent refuses, never invents one.

The effects are the SAME process-level executor semantics as the other
delegation fixtures' (file writes, TCP connects, UDP sends, program
starts); a tool-transport kind or an unsupported kind in a task step is
a fixture mistake and is refused, not improvised. Dependency-free
(stdlib only) for reproducibility, like the toy servers. The executor
host runs this server in its own container (targets/a2a-agent/
Dockerfile, compose/executor.yaml) with its own sensor (Tracee) — the
only design that can see what happens on the far machine.

Run stand-alone (what the tests do; no container needed):
    REPLAY_LOG_DIR=/tmp/x A2A_LISTEN_PORT=8092 python3 server.py
"""

import http.server
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

SERVER_NAME = "a2a-agent"
SERVER_VERSION = "0.1.0"

RECORDS_NAME = "delegation-records.jsonl"
META_DELEGATION_ID = "io.inspection/delegation_id"
META_ROOT_DELEGATION_ID = "io.inspection/root_delegation_id"
META_HOP = "io.inspection/hop"
META_RUN_ID = "io.inspection/run_id"
# per-stream monotonic seq (delegation-record/1): this server process is
# one stream (stream_id a2a-agent-<pid>); repeated hand-offs in the same
# process must not repeat seq 0
_ACCEPT_SEQ = itertools.count()

# Mirrors the harness-side executors' per-kind timeouts
# (harnesses/pi/adapter/replay.ts ACTION_TIMEOUT_MS).
ACTION_TIMEOUT_S = 20

# Crockford base32 (the delegation-record/1 record_id alphabet: no I, L, O, U)
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

LISTEN_HOST = os.environ.get("A2A_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("A2A_LISTEN_PORT", "8092"))


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


def log_dir() -> Path:
    return Path(os.environ.get("REPLAY_LOG_DIR", "/workspace/replay"))


def write_accepted_record(chain: dict, run_id: str, step_ids: list) -> None:
    """Append the remote agent's acceptance line to this machine's
    delegation record stream (delegation-record/1, exactly the frozen
    schema, machine "executor" — this record was written on the far
    machine, and results from different machines are never pooled).
    Record emission must never break the task response (a lost line is a
    reported problem downstream, never a lost effect)."""
    log_dir().mkdir(parents=True, exist_ok=True)
    rec = {
        "schema": 1,
        "record_id": ulid(),
        "run_id": run_id,
        "stream_id": f"{SERVER_NAME}-{os.getpid()}",
        "seq": next(_ACCEPT_SEQ),
        "ts": now_rfc3339_ms(),
        "event": "accepted",
        "channel": "network",
        "delegation_id": chain["delegation_id"],
        "parent_delegation_id": chain["parent"],
        "root_delegation_id": chain["root"],
        "hop": chain["hop"],
        "from_actor": "pi-root",
        "to_actor": "f5-remote-agent",
        "task_digest": task_digest(step_ids),
        "protocol": "a2a",
        "machine": "executor",
        "carrier": "queue_payload",
        "actor_pid": os.getpid(),
    }
    with open(log_dir() / RECORDS_NAME, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


def perform_step(step: dict) -> dict:
    """Perform one task step's effect from this process (the remote agent
    performing its own effects on its own machine). The kinds are the
    process-level effect ones; a tool-transport kind in an agent task is
    a fixture mistake and is refused."""
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
    raise ValueError(f"unsupported kind {kind!r} for a remote-agent-"
                     f"performed action {step.get('id')!r}")


def run_task(chain: dict, run_id: str, steps: list) -> dict:
    """Take the hand-off, record the acceptance, perform the effects on
    this machine, and answer with the report as the task's artifact."""
    # 1. the acceptance: the remote agent took the work — BEFORE the
    #    effects, so a taken-and-failed hand-off stays visible
    write_accepted_record(chain, run_id, [s.get("id") for s in steps])
    # 2. the effects, one result row per step (ok detail | error); a
    #    failed effect is a result, not a broken task
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
              "delegation_id": chain["delegation_id"],
              "actor": "f5-remote-agent",
              "machine": "executor",
              "results": results}
    if not ok:
        report["error"] = "; ".join(
            f"{r['id']}: {r['error']}" for r in results
            if r["status"] == "error")
    return report


class Handler(http.server.BaseHTTPRequestHandler):
    """The A2A-style task interface (v1: message/send completes the task
    synchronously and returns the artifacts in the same round trip)."""

    def _json(self, code: int, doc: dict) -> None:
        body = json.dumps(doc, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _rpc_error(self, msg_id, code: int, message: str) -> None:
        self._json(200, {"jsonrpc": "2.0", "id": msg_id,
                         "error": {"code": code, "message": message}})

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler spelling)
        if self.path == "/health":
            self._json(200, {"status": "ok", "server": SERVER_NAME,
                             "version": SERVER_VERSION})
            return
        self._json(404, {"status": "error", "error": f"no route {self.path}"})

    def do_POST(self):  # noqa: N802 (BaseHTTPRequestHandler spelling)
        if self.path != "/":
            self._json(404, {"status": "error",
                             "error": f"no route {self.path}"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            msg = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"status": "error", "error": f"bad body: {exc}"})
            return
        msg_id = msg.get("id")
        if msg.get("method") != "message/send":
            self._rpc_error(msg_id, -32601,
                            f"method not found: {msg.get('method')!r} "
                            f"(v1 serves message/send)")
            return
        message = (msg.get("params") or {}).get("message") or {}
        meta = message.get("metadata") or {}
        # the hand-off must have happened: no delegation id in the message
        # metadata means this task was submitted without a hand-off (the
        # queue_payload carrier is missing) — refuse, never invent one
        did = str(meta.get(META_DELEGATION_ID) or "").strip()
        if not did:
            self._rpc_error(msg_id, -32000,
                           "no delegation id on the message metadata — "
                           "this task was submitted without a hand-off "
                           "(the queue_payload carrier is missing)")
            return
        # the hop is a chain-position integer >= 1 (delegation-record/1: hop
        # counts hand-offs from the root, so 1 IS the first) — a malformed or
        # out-of-range hop would produce a schema-invalid record, so the
        # hand-off is refused BEFORE anything is performed or recorded
        try:
            raw_hop = meta.get(META_HOP)
            # None = the carrier's default (the first hand-off); an EXPLICIT
            # 0 must not sneak through the falsy-or fallback
            hop = 1 if raw_hop is None else int(raw_hop)
        except (TypeError, ValueError):
            hop = 0
        if hop < 1:
            self._rpc_error(msg_id, -32602,
                           f"invalid hop {meta.get(META_HOP)!r} — the chain "
                           "position must be an integer >= 1")
            return
        steps = (message.get("data") or {}).get("steps")
        if not isinstance(steps, list) or not steps:
            self._rpc_error(msg_id, -32602,
                            "the task needs a non-empty 'steps' list")
            return
        chain = {
            "delegation_id": did,
            "parent": None,   # a root hand-off from the origin agent
            "root": str(meta.get(META_ROOT_DELEGATION_ID) or "").strip()
                or did,
            "hop": hop,
        }
        run_id = (str(meta.get(META_RUN_ID) or "").strip()
                  or os.environ.get("INSPECTION_RUN_ID", "unattributed"))
        report = run_task(chain, run_id, steps)
        # the completed task: the report is the artifact (v1 synchronous —
        # the submit IS the get-result round trip)
        self._json(200, {
            "jsonrpc": "2.0", "id": msg_id,
            "result": {
                "id": f"task-{did}",
                "contextId": f"ctx-{chain['root']}",
                "status": {"state": "completed"},
                "artifacts": [{"name": "report", "data": report}],
            }})

    def log_message(self, fmt, *args):  # console noise stays off the wire
        sys.stderr.write(f"{SERVER_NAME}: {fmt % args}\n")


def main() -> None:
    server = http.server.ThreadingHTTPServer(
        (LISTEN_HOST, LISTEN_PORT), Handler)
    print(f"{SERVER_NAME} {SERVER_VERSION} listening on "
          f"{LISTEN_HOST}:{LISTEN_PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
