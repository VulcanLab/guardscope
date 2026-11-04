#!/usr/bin/env python3
"""The F4 delegation fixture's REMOTE tool server (the study's scenario
class S4 remote): targets/mcp-agent/server.py's sibling — the F3 local
hidden-agent server's SAME pattern over HTTP, on a SECOND machine. The
pi replay adapter (harnesses/pi/adapter/replay.ts) sends the task as a
plain POST over the network; to the outside world the call looks like
any other HTTP tool request. THIS server's internal agent performs its
own effects ON ITS OWN MACHINE (the executor host of the two-host
topology, compose/executor.yaml) — the network connects, process
starts, file writes the caller never asked the tool to make visible —
writes its acceptance record (delegation-record/1, machine "executor"),
and only then answers.

The hand-off records:
  - the ADAPTER (on the origin machine) writes the "sent" line BEFORE
    the POST — channel "tool", protocol "http", carrier "http_header",
    machine "origin";
  - THIS server (on the executor machine) writes the "accepted" line the
    moment its internal agent takes the work — BEFORE performing the
    effects, machine "executor" — so a hand-off the server took and then
    failed on stays visible.

The chain ids travel on the request headers (the http_header carrier —
the same x-inspection-* vocabulary the raw http tool calls' action ids
already use, so the request stays byte-shaped like every ordinary HTTP
tool call):
  x-inspection-delegation-id       this hand-off's id (required — no
                                      id means no hand-off happened: the
                                      server refuses, never invents one)
  x-inspection-root-delegation-id  the chain root (defaults to this id)
  x-inspection-hop                 the hop count (defaults to 1)
  x-inspection-run-id              the run identity (falls back to the
                                      server's INSPECTION_RUN_ID env, so
                                      the two machines' records carry the
                                      same run_id without shared state)

The effects are the SAME process-level executor semantics as the F3
server (perform_step, imported from this sibling — one implementation,
two transports); a tool-transport kind or an unsupported kind in a task
step is a fixture mistake and is refused, not improvised.

Everything is additive: this is a NEW server file — the stdio
hidden-agent server (server.py) is untouched, and the existing runs'
behavior does not change. The executor host runs this server in its own
container (targets/mcp-agent/Dockerfile, compose/executor.yaml) with its
own sensor (Tracee) — the only design that can see what happens on the
far machine. Dependency-free (stdlib only) for reproducibility, like
the toy servers.

Run stand-alone (what the tests do; no container needed):
    REPLAY_LOG_DIR=/tmp/x F4_LISTEN_PORT=8091 python3 http-server.py
"""

import http.server
import itertools
import json
import os
import sys
from pathlib import Path

# the shared executor + record identity pieces: this sibling and the F3
# stdio server are one fixture in two transports
sys.path.insert(0, str(Path(__file__).resolve().parent))
import server as _f3_server  # noqa: E402

SERVER_NAME = "toy-mcp-agent-http"
SERVER_VERSION = "0.1.0"

RECORDS_NAME = "delegation-records.jsonl"
HEADER_DELEGATION_ID = "x-inspection-delegation-id"
HEADER_ROOT_DELEGATION_ID = "x-inspection-root-delegation-id"
HEADER_HOP = "x-inspection-hop"
HEADER_RUN_ID = "x-inspection-run-id"
# per-stream monotonic seq (delegation-record/1): this server process is
# one stream (stream_id toy-mcp-agent-http-<pid>); repeated hand-offs in
# the same process must not repeat seq 0
_ACCEPT_SEQ = itertools.count()

LISTEN_HOST = os.environ.get("F4_LISTEN_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("F4_LISTEN_PORT", "8091"))


def log_dir() -> Path:
    return Path(os.environ.get("REPLAY_LOG_DIR", "/workspace/replay"))


def write_accepted_record(chain: dict, run_id: str, step_ids: list) -> None:
    """Append the internal agent's acceptance line to this machine's
    delegation record stream (delegation-record/1, exactly the frozen
    schema, machine "executor" — this record was written on the far
    machine, and results from different machines are never pooled).
    Record emission must never break the tool response (a lost line is a
    reported problem downstream, never a lost effect)."""
    log_dir().mkdir(parents=True, exist_ok=True)
    rec = {
        "schema": 1,
        "record_id": _f3_server.ulid(),
        "run_id": run_id,
        "stream_id": f"{SERVER_NAME}-{os.getpid()}",
        "seq": next(_ACCEPT_SEQ),
        "ts": _f3_server.now_rfc3339_ms(),
        "event": "accepted",
        "channel": "tool",
        "delegation_id": chain["delegation_id"],
        "parent_delegation_id": chain["parent"],
        "root_delegation_id": chain["root"],
        "hop": chain["hop"],
        "from_actor": "pi-root",
        "to_actor": "f4-remote-tool-agent",
        "task_digest": _f3_server.task_digest(step_ids),
        "protocol": "http",
        "machine": "executor",
        "carrier": "http_header",
        "actor_pid": os.getpid(),
    }
    with open(log_dir() / RECORDS_NAME, "a", encoding="utf-8") as f:
        f.write(json.dumps(rec, sort_keys=True) + "\n")


class Handler(http.server.BaseHTTPRequestHandler):
    """One request = one ordinary-looking HTTP tool call."""

    def _json(self, code: int, doc: dict) -> None:
        body = json.dumps(doc, sort_keys=True).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802 (BaseHTTPRequestHandler spelling)
        if self.path == "/health":
            self._json(200, {"status": "ok", "server": SERVER_NAME,
                             "version": SERVER_VERSION})
            return
        self._json(404, {"status": "error", "error": f"no route {self.path}"})

    def do_POST(self):  # noqa: N802 (BaseHTTPRequestHandler spelling)
        if self.path != "/task":
            self._json(404, {"status": "error",
                             "error": f"no route {self.path}"})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            doc = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._json(400, {"status": "error", "error": f"bad body: {exc}"})
            return
        # the hand-off must have happened: no delegation id on the headers
        # means this call was dispatched without a hand-off (the
        # http_header carrier is missing) — refuse, never invent one
        did = (self.headers.get(HEADER_DELEGATION_ID) or "").strip()
        if not did:
            self._json(400, {"status": "error",
                             "error": "no delegation id on the request "
                                      "headers — this call was dispatched "
                                      "without a hand-off (the http_header "
                                      "carrier is missing)"})
            return
        # the hop is a chain-position integer >= 1 (delegation-record/1: hop
        # counts hand-offs from the root, so 1 IS the first) — a malformed or
        # out-of-range hop would produce a schema-invalid record, so the
        # hand-off is refused BEFORE anything is performed or recorded
        try:
            hop = int(self.headers.get(HEADER_HOP) or "1")
        except (TypeError, ValueError):
            hop = 0
        if hop < 1:
            self._json(400, {"status": "error",
                             "error": f"invalid hop {self.headers.get(HEADER_HOP)!r} "
                                      "— the chain position must be an "
                                      "integer >= 1"})
            return
        steps = doc.get("steps")
        if not isinstance(steps, list) or not steps:
            self._json(400, {"status": "error",
                             "error": "the task needs a non-empty 'steps' "
                                      "list"})
            return
        chain = {
            "delegation_id": did,
            "parent": None,   # a root hand-off from the origin agent
            "root": (self.headers.get(HEADER_ROOT_DELEGATION_ID) or "").strip()
                or did,
            "hop": hop,
        }
        run_id = ((self.headers.get(HEADER_RUN_ID) or "").strip()
                  or os.environ.get("INSPECTION_RUN_ID", "unattributed"))

        # 1. the acceptance: the internal agent took the work — BEFORE the
        #    effects, so a taken-and-failed hand-off stays visible
        write_accepted_record(chain, run_id, [s.get("id") for s in steps])

        # 2. the effects, one result row per step (ok detail | error); a
        #    failed effect is a result, not a broken tool
        results = []
        for step in steps:
            try:
                results.append({"id": step.get("id"), "status": "ok",
                                "detail": _f3_server.perform_step(step)})
            except Exception as exc:
                results.append({"id": step.get("id"), "status": "error",
                                "error": str(exc)})
        ok = all(r["status"] == "ok" for r in results)
        report = {"status": "ok" if ok else "error",
                  "delegation_id": did,
                  "actor": "f4-remote-tool-agent",
                  "machine": "executor",
                  "results": results}
        if not ok:
            report["error"] = "; ".join(
                f"{r['id']}: {r['error']}" for r in results
                if r["status"] == "error")
        self._json(200, report)

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
