#!/usr/bin/env python3
"""agentgateway decision-stream collector (plugins/agentgateway/collector/).

agentgateway v1.5.0 writes no decision log of its own: its per-request
authorization decisions are visible only on the admin /debug/trace endpoint
(crates/agentgateway/src/management/admin.rs handle_debug_trace), which
streams dtrace events as SSE while a tracer follows it. The binding's
overlay runs THIS collector as the auxiliary `control-agentgateway-trace`
service: it follows the trace for the lifetime of the topology and persists
every event as one JSONL row on the slot's decision-log volume
(gateway-logs, compose/slots/t1.yaml log_volume):

    {"received_epoch_ns": <capture clock, ns>, "raw": <verbatim event>}

Row semantics (the shim's input contract, plugins/agentgateway/shim/
translate.py):

- `raw` is the verbatim SSE `data:` payload — a dtrace Message
  {"requestId": <u64>, "eventStart"?, "eventEnd", "severity",
   "scope"?, "message": {"type": ...}} — never edited (the shim's
  evidence locator points back at this line unchanged).
- `received_epoch_ns` is the COLLECTOR's capture clock (host clock, same
  source as the run window). agentgateway's dtrace events carry only
  relative event times (eventStart/eventEnd, µs since gateway start), so
  the capture timestamp is the record's wall-clock anchor — the same
  convention the pre-guardscope probe used (probes/agentgateway-t1/
  normalize.py capture()).
- `: ready` frames (the admin's first SSE line) mark the start of a
  capture window: the collector writes their clock reading to the .ready
  sidecar so the run record can prove the window was open before the
  first request.

Env:
    AGENTGATEWAY_ADMIN_URL    default http://gateway:15000
    AGENTGATEWAY_TRACE_OUT    default /var/log/gateway/agentgateway-trace.jsonl
    AGENTGATEWAY_TRACE_READY  default <TRACE_OUT>.ready
    AGENTGATEWAY_TRACE_FOLLOW_SECONDS  per-request follow window, capped at
                              3600 (the admin's parse_trace_follow_duration
                              maximum); the collector loops, starting a
                              fresh follow window when one ends, so the
                              decision stream keeps flowing for the whole
                              topology lifetime (rows are window-scoped
                              downstream by their capture timestamp).
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from pathlib import Path

ADMIN_URL = os.environ.get("AGENTGATEWAY_ADMIN_URL",
                           "http://gateway:15000")
TRACE_OUT = Path(os.environ.get(
    "AGENTGATEWAY_TRACE_OUT",
    "/var/log/gateway/agentgateway-trace.jsonl"))
READY_OUT = Path(os.environ.get("AGENTGATEWAY_TRACE_READY",
                                f"{TRACE_OUT}.ready"))
FOLLOW_SECONDS = max(1, min(3600, int(os.environ.get(
    "AGENTGATEWAY_TRACE_FOLLOW_SECONDS", "3600"))))


def wait_for_admin(timeout_s: int = 120) -> None:
    """Block until the admin listener answers (the gateway starts the admin
    server with the proxy; readiness here is connection-level only — the
    run-level readiness gate is the runner's enforcement-ready check)."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            req = urllib.request.Request(f"{ADMIN_URL}/", method="GET")
            urllib.request.urlopen(req, timeout=5)
        except urllib.error.HTTPError:
            return  # the listener answered (any status): the admin is up
        except OSError:
            time.sleep(1.0)
            continue
        return
    raise SystemExit(f"admin endpoint {ADMIN_URL} not reachable within "
                     f"{timeout_s}s")


def follow(out: Path, ready: Path, seconds: int) -> None:
    """One bounded follow window: POST /debug/trace?follow=<seconds>s and
    append every SSE data: payload as one JSONL row."""
    req = urllib.request.Request(
        f"{ADMIN_URL}/debug/trace?follow={seconds}s",
        method="POST", data=b"")
    with urllib.request.urlopen(req, timeout=seconds + 60) as resp, \
            out.open("a", encoding="utf-8") as fh:
        for raw_line in resp:
            line = raw_line.strip()
            if line.startswith(b": ready"):
                ready.write_text(f"{time.time_ns()}\n",
                                 encoding="utf-8")
                continue
            if not line.startswith(b"data: "):
                continue  # SSE comments/keepalives are not events
            row = {"received_epoch_ns": time.time_ns(),
                   "raw": json.loads(line[6:])}
            fh.write(json.dumps(row, separators=(",", ":")) + "\n")
            fh.flush()


def main() -> int:
    TRACE_OUT.parent.mkdir(parents=True, exist_ok=True)
    wait_for_admin()
    while True:
        # a bounded window per request (admin cap 1h); the loop keeps the
        # stream alive for the topology lifetime
        try:
            follow(TRACE_OUT, READY_OUT, FOLLOW_SECONDS)
        except (urllib.error.URLError, OSError) as exc:
            # gateway restart mid-window: the next iteration retries
            print(f"capture: follow window ended ({exc}); re-arming",
                  flush=True)
            time.sleep(2.0)
            wait_for_admin()


if __name__ == "__main__":
    raise SystemExit(main())
