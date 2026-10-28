#!/usr/bin/env python3
"""Toy MCP stdio tool server for the HTTP tool class (C4, T4).

In deployment-design T4 (harness-native enforcement) the http_tool_call
actions are issued as MCP tools of the harness (pi executes them through its
tool pipeline, where the harness permission layer evaluates them). This
server exposes the three canonical HTTP tools over the stdio transport and
performs the raw HTTP request against the logging HTTP endpoint — exactly
what the adapter did directly in T0 (actions a011-a013).

Served-action evidence: the http_tool_call class is served-evidenced at the
http-endpoint target (its request log), unchanged from T0/T1. This server is
deliberately NOT registered by the stdio mapping (its argv marker differs
from the fs server's), so its JSON-RPC response writes stay unmapped
(allowlisted pipe-writes) — the kernel evidence for the http class is the
connect to the endpoint, not the pipe traffic.

Dependency-free (stdlib only) for reproducibility.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import log_event

SERVER_NAME = "toy-mcp-http-stdio"
SERVER_VERSION = "0.1.0"
SUPPORTED_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18"]
LATEST_SUPPORTED = SUPPORTED_VERSIONS[-1]

UPSTREAM = os.environ.get("HTTP_ENDPOINT_URL", "http://http-endpoint:8080")
# T5 (compose/t5.yaml sets MCP_GATEWAY_URL): tool calls are forwarded THROUGH
# the MCP Security Gateway as MCP tools/call (the gateway is the second
# enforcement point; the harness permission chain is the first), and the
# gateway's own upstream (mcp-http) performs the raw request. Unset = direct
# raw requests against UPSTREAM (T0/T4 behavior).
MCP_GATEWAY_URL = os.environ.get("MCP_GATEWAY_URL", "")

TOOLS = [
    {
        "name": "post_hook",
        "description": "POST the hook payload to the logging HTTP endpoint (trace action a011).",
        "inputSchema": {
            "type": "object",
            "required": ["body"],
            "properties": {"body": {"type": "string", "description": "Request body text"}},
        },
    },
    {
        "name": "get_health",
        "description": "GET /health from the logging HTTP endpoint (trace action a012).",
        "inputSchema": {"type": "object", "properties": {}},
    },
    {
        "name": "put_state",
        "description": "PUT the state payload to the logging HTTP endpoint (trace action a013).",
        "inputSchema": {
            "type": "object",
            "required": ["body"],
            "properties": {"body": {"type": "string", "description": "Request body text"}},
        },
    },
]

TOOL_ROUTES = {
    "post_hook": ("POST", "/hook"),
    "get_health": ("GET", "/health"),
    "put_state": ("PUT", "/state"),
}


def text_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


def call_tool(name: str, args: dict) -> dict:
    if name not in TOOL_ROUTES:
        raise KeyError(name)
    if MCP_GATEWAY_URL:
        result = gateway_tool_call(name, args)
    else:
        method, path = TOOL_ROUTES[name]
        body = args.get("body")
        result = http_request(method, path, body)
    log_event(SERVER_NAME, "tool_call", stream="stderr",
              op=name, via="gateway" if MCP_GATEWAY_URL else "direct",
              status=result.get("status"))
    return text_result(json.dumps(result, separators=(",", ":")))


def gateway_tool_call(name: str, args: dict) -> dict:
    """T5: the tool call crosses the MCP Security Gateway (the second
    enforcement point) as MCP tools/call; the gateway's upstream performs
    the raw HTTP request. The gateway's decision log records the evaluation."""
    msg = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
           "params": {"name": name, "arguments": args}}
    req = urllib.request.Request(MCP_GATEWAY_URL, data=json.dumps(msg).encode(),
                                 method="POST",
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": exc.read().decode("utf-8", "replace")}
    if data.get("error"):
        return {"status": 403, "body": json.dumps(data["error"])}
    return json.loads(data["result"]["content"][0]["text"])


def http_request(method: str, path: str, body: str | None) -> dict:
    """Perform the raw HTTP request the canonical action describes."""
    data = body.encode("utf-8") if body is not None else None
    req = urllib.request.Request(UPSTREAM + path, data=data, method=method,
                                 headers={"Content-Type": "text/plain"} if data else {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            payload = resp.read().decode("utf-8", "replace")
            return {"status": resp.status, "body": payload}
    except urllib.error.HTTPError as exc:
        return {"status": exc.code, "body": exc.read().decode("utf-8", "replace")}


def handle(msg: dict) -> dict | None:
    method = msg.get("method", "")
    if "id" in msg:  # request -> response
        if method == "initialize":
            requested = (msg.get("params") or {}).get("protocolVersion", "")
            version = requested if requested in SUPPORTED_VERSIONS else LATEST_SUPPORTED
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {
                "protocolVersion": version,
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            }}
        if method == "ping":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {}}
        if method == "tools/list":
            return {"jsonrpc": "2.0", "id": msg["id"], "result": {"tools": TOOLS}}
        if method == "tools/call":
            params = msg.get("params") or {}
            try:
                result = call_tool(params["name"], params.get("arguments") or {})
                return {"jsonrpc": "2.0", "id": msg["id"], "result": result}
            except KeyError:
                return {"jsonrpc": "2.0", "id": msg["id"], "error": {
                    "code": -32602, "message": f"unknown tool: {params.get('name')}"}}
            except OSError as exc:
                return {"jsonrpc": "2.0", "id": msg["id"], "error": {
                    "code": -32000, "message": str(exc)}}
        return {"jsonrpc": "2.0", "id": msg["id"], "error": {
            "code": -32601, "message": f"method not found: {method}"}}
    return None  # notifications: no response


def main() -> None:
    log_event(SERVER_NAME, "start", stream="stderr", pid=os.getpid(),
              upstream=UPSTREAM, supported_versions=SUPPORTED_VERSIONS)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            sys.stdout.write(json.dumps({"jsonrpc": "2.0", "id": None, "error": {
                "code": -32700, "message": f"parse error: {exc}"}}) + "\n")
            sys.stdout.flush()
            continue
        log_event(SERVER_NAME, "request", stream="stderr", method=msg.get("method"))
        resp = handle(msg)
        if resp is not None:
            sys.stdout.write(json.dumps(resp, separators=(",", ":")) + "\n")
            sys.stdout.flush()
    log_event(SERVER_NAME, "stop", stream="stderr")


if __name__ == "__main__":
    main()
