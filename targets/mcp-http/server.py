#!/usr/bin/env python3
"""MCP-over-HTTP tool server (C4, T1): the upstream side of the gateway.

The MCP stdio transport of targets/mcp-stdio/server.py, served over HTTP
instead: one JSON-RPC 2.0 endpoint at POST /mcp (single-message streamable
HTTP; one request -> one JSON-RPC response). The gateway (gateway/server.py)
forwards inspected tool calls here; this server executes the raw HTTP request
against the logging HTTP endpoint, exactly what the harness did directly in
T0 (baseline actions a011-a013).

Tool surface mirrors the canonical trace spec (trace/traces/baseline.yaml),
one tool per http_tool_call action so gateway AuditEntry.tool_name maps 1:1
onto canonical actions (AuditEntry carries tool_name but not params):

  post_hook   {body}  -> POST /hook   (a011)
  get_health  {}      -> GET  /health (a012)
  put_state   {body}  -> PUT  /state   (a013)

Dependency-free (stdlib only) for reproducibility.
"""

import json
import os
import sys
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import log_event

SERVER_NAME = "toy-mcp-http"
SERVER_VERSION = "0.1.0"
SUPPORTED_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18"]
LATEST_SUPPORTED = SUPPORTED_VERSIONS[-1]

PORT = int(os.environ.get("MCP_HTTP_PORT", "8091"))
# Upstream HTTP endpoint the tools perform raw requests against (the T0
# http-endpoint target; hostname per compose network).
UPSTREAM = os.environ.get("HTTP_ENDPOINT_URL", "http://http-endpoint:8080")

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

# tool name -> (method, path) on the upstream HTTP endpoint; keeps the
# canonical op/path visible in the compiled plan and in served-action logs.
TOOL_ROUTES = {
    "post_hook": ("POST", "/hook"),
    "get_health": ("GET", "/health"),
    "put_state": ("PUT", "/state"),
}


def text_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


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


def call_tool(name: str, args: dict) -> dict:
    if name not in TOOL_ROUTES:
        raise KeyError(name)
    method, path = TOOL_ROUTES[name]
    body = args.get("body")
    result = http_request(method, path, body)
    log_event(SERVER_NAME, "tool_call", tool=name, op=method, path=path,
              upstream=UPSTREAM, status=result["status"])
    return text_result(json.dumps(result, separators=(",", ":")))


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


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        def respond(code: int, payload: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as exc:
            body = json.dumps({"jsonrpc": "2.0", "id": None, "error": {
                "code": -32700, "message": f"parse error: {exc}"}}).encode()
            respond(400, body)
            return
        if msg.get("method") == "notifications/initialized":
            respond(202, b"")
            return
        log_event(SERVER_NAME, "request", method=msg.get("method"),
                  id=msg.get("id"), peer=str(self.client_address[0]))
        resp = handle(msg)
        if resp is None:
            respond(202, b"")
            return
        out = json.dumps(resp, separators=(",", ":")).encode()
        respond(200, out)

    def log_message(self, fmt, *args):  # silence default stderr access log
        pass


if __name__ == "__main__":
    log_event(SERVER_NAME, "start", port=PORT, upstream=UPSTREAM,
              tools=[t["name"] for t in TOOLS])
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
