#!/usr/bin/env python3
"""Minimal replay driver for OpenClaw (M4 slice of C9; run.py CLI lands in M7).

Posts the compiled trace to the harness gateway's POST /tools/invoke ->
replay_trace tool (no LLM involved), and saves the result JSON.

Usage:
  python3 runner/trigger_openclaw.py --trace trace/compile/openclaw/out/baseline.json \
      [--url http://127.0.0.1:18789] [--token inspection-t0-token] [--out runs/x/replay-result.json]
"""

import argparse
import http.client
import json
import sys
import time
from pathlib import Path
from urllib.parse import urlparse


def wait_gateway(url: str, token: str, timeout_s: float = 120) -> None:
    deadline = time.time() + timeout_s
    p = urlparse(url)
    while time.time() < deadline:
        try:
            conn = http.client.HTTPConnection(p.hostname, p.port, timeout=3)
            conn.request("GET", "/health", headers={"Authorization": f"Bearer {token}"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            if resp.status == 200:
                return
        except Exception:
            time.sleep(1)
    raise SystemExit(f"gateway at {url} not healthy after {timeout_s}s")


def invoke(url: str, token: str, trace: dict, idempotency_key: str | None = None) -> dict:
    key = idempotency_key or f"replay-{trace['meta']['spec_sha256'][:12]}"
    body = json.dumps({
        "tool": "replay_trace",
        "args": {"trace": trace},
        "idempotencyKey": key,
    }).encode()
    p = urlparse(url)
    conn = http.client.HTTPConnection(p.hostname, p.port, timeout=120)
    try:
        conn.request("POST", "/tools/invoke", body=body,
                     headers={"Authorization": f"Bearer {token}",
                              "Content-Type": "application/json"})
        resp = conn.getresponse()
        payload = json.loads(resp.read())
        if resp.status != 200:
            raise SystemExit(f"invoke failed: {resp.status} {payload}")
        return payload
    finally:
        conn.close()


def invoke_tool(url: str, token: str, tool: str, args: dict,
                idempotency_key: str | None = None) -> tuple[dict, int]:
    """Invoke one tool; returns (payload, http_status). The caller interprets:
    payload.ok -> executed; error.type == 'tool_call_blocked' -> denied."""
    body = json.dumps({"tool": tool, "args": args,
                       "idempotencyKey": idempotency_key}).encode()
    p = urlparse(url)
    conn = http.client.HTTPConnection(p.hostname, p.port, timeout=120)
    try:
        conn.request("POST", "/tools/invoke", body=body,
                     headers={"Authorization": f"Bearer {token}",
                              "Content-Type": "application/json"})
        resp = conn.getresponse()
        return json.loads(resp.read()), resp.status
    finally:
        conn.close()


# canonical tool-call interfaces, mirror of the gateway routes (adapter
# GATEWAY_TOOL_ROUTES / trace schema): (method, path) -> bare tool name
HTTP_TOOL_ROUTES = {
    "POST /hook": "post_hook",
    "GET /health": "get_health",
    "PUT /state": "put_state",
}


def canonical_tool_call(action: dict) -> tuple[str, dict]:
    """Compiled canonical action -> (bare plugin tool name, args)."""
    if action.get("kind") == "mcp":
        return action["tool"], dict(action.get("arguments") or {})
    # http: method+path route -> tool name; body is the single argument
    from urllib.parse import urlparse as _u
    path = _u(action["url"]).path
    tool = HTTP_TOOL_ROUTES[f'{action["method"]} {path}']
    args: dict = {}
    if action.get("body") is not None:
        args["body"] = action["body"]
    return tool, args


def run_replay_t4(compiled_path: Path, replay_dir: Path, container: str,
                  url: str, token: str, timeout_s: float = 300) -> dict:
    """T4/T6 flow: process phase (wrapper tool) -> one /tools/invoke per
    canonical tool call (each crosses the harness's before_tool_call hook;
    tool_call_blocked = denied) -> finalize assembles the replay result.
    Mirrors the pi two-phase flow (see harnesses/pi/adapter/replay.ts)."""
    trace = json.loads(Path(compiled_path).read_text())
    wait_gateway(url, token, timeout_s=timeout_s)

    # phase 1: process-level actions (outside the tool pipeline)
    payload, status = invoke_tool(url, token, "replay_trace_t4",
                                  {"phase": "process", "trace": trace},
                                  idempotency_key="phase-process")
    if status != 200 or not payload.get("ok", True):
        raise SystemExit(f"process phase failed: {status} {payload}")

    # phase 2: canonical tool calls — each crosses the enforcement point
    observations: dict[str, dict] = {}
    for action in trace["actions"]:
        if action["class"] not in ("stdio_tool_call", "http_tool_call"):
            continue
        tool, args = canonical_tool_call(action)
        payload, status = invoke_tool(url, token, tool, args,
                                      idempotency_key=action["id"])
        err = payload.get("error") or {}
        if payload.get("ok"):
            observations[action["id"]] = {"status": "ok"}
        elif err.get("type") == "tool_call_blocked":
            observations[action["id"]] = {"status": "denied",
                                          "error": err.get("message")}
        else:
            observations[action["id"]] = {"status": "error",
                                          "error": err.get("message") or f"http {status}"}

    # phase 3: finalize assembles the replay result from the recorded
    # per-call results (hook + execute) and the process phase
    payload, status = invoke_tool(url, token, "replay_trace_t4",
                                  {"phase": "finalize", "trace": trace,
                                   "observations": observations},
                                  idempotency_key="phase-finalize")
    if status != 200:
        raise SystemExit(f"finalize failed: {status} {payload}")

    # the finalize wrote replay-result.json into the mounted replay dir
    result = json.loads((replay_dir / "replay-result.json").read_text())
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    here = Path(__file__).resolve().parent.parent
    ap.add_argument("--trace", type=Path,
                    default=here / "trace" / "compile" / "openclaw" / "out" / "baseline.compiled.json")
    ap.add_argument("--url", default="http://127.0.0.1:28789")
    ap.add_argument("--token", default="inspection-t0-token")
    ap.add_argument("--out", type=Path, default=None, help="result JSON path")
    ap.add_argument("--compile", action="store_true",
                    help="compile the canonical spec first (trace/compile/openclaw/compile.py)")
    args = ap.parse_args()

    if args.compile:
        compile_py = here / "trace" / "compile" / "openclaw" / "compile.py"
        import subprocess
        subprocess.run([sys.executable, str(compile_py), str(here / "trace" / "traces" / "baseline.yaml"),
                        "--out", str(args.trace)], check=True)

    trace = json.loads(args.trace.read_text())
    wait_gateway(args.url, args.token)
    payload = invoke(args.url, args.token, trace)
    # the gateway wraps the tool response: {ok, result: <replay result>} —
    # the reconciliation contract expects the adapter result at top level
    result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    print(json.dumps(result, indent=1))
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(result, indent=1) + "\n")
        print(f"wrote {args.out}")
    if not result.get("ok"):
        sys.exit(1)


if __name__ == "__main__":
    main()