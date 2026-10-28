#!/usr/bin/env python3
"""MCP-over-HTTP fs tool server (C4, T3): the stdio tool server behind the
gateway.

The MCP stdio transport of targets/mcp-stdio/server.py, served over HTTP:
one JSON-RPC 2.0 endpoint at POST /mcp, same wire shape as
targets/mcp-http/server.py. In deployment-design T3 the gateway proxies ALL
tool servers, including the local-transport fs tools, so the harness no
longer spawns the stdio server as a child; this container is its upstream.

Tool surface is exactly the stdio server's (one tool per stdio_tool_call
action), and the served-action log keeps the SAME target name ("toy-mcp-fs")
so reconciliation's served layer (R2) and the profiles' served_targets are
unchanged across designs. Tool arguments carry absolute paths; the container
has its own /workspace/out (the upstream-side workspace; T0/T1's server-side
file opens happened in the harness container and were an expected extra — in
T3 they belong to this container and are simply out of the harness scope).

Dependency-free (stdlib only) for reproducibility.
"""

import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import log_event

SERVER_NAME = "toy-mcp-fs"
SERVER_VERSION = "0.1.0"
SUPPORTED_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18"]
LATEST_SUPPORTED = SUPPORTED_VERSIONS[-1]

PORT = int(os.environ.get("MCP_FS_HTTP_PORT", "8092"))
WORKSPACE = Path(os.environ.get("FS_WORKSPACE", "/workspace"))

TOOLS = [
    {
        "name": "write_file",
        "description": "Write text data to a file (create/overwrite).",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Absolute file path"},
                "data": {"type": "string", "description": "Text to write"},
            },
            "required": ["path", "data"],
        },
    },
    {
        "name": "read_file",
        "description": "Read a text file and return its content.",
        "inputSchema": {
            "type": "object",
            "required": ["path"],
            "properties": {"path": {"type": "string", "description": "Absolute file path"}},
        },
    },
    {
        "name": "list_directory",
        "description": "List entries of a directory.",
        "inputSchema": {
            "type": "object",
            "properties": {"path": {"type": "string", "description": "Absolute directory path"}},
            "required": ["path"],
        },
    },
]


def text_result(text: str) -> dict:
    return {"content": [{"type": "text", "text": text}]}


def call_tool(name: str, args: dict) -> dict:
    # Same tool semantics (and log fields) as targets/mcp-stdio/server.py so
    # served-action logs stay comparable across designs; only the transport
    # and the executing container differ.
    if name == "write_file":
        path = Path(args["path"])
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(args["data"], encoding="utf-8")
        log_event(SERVER_NAME, "tool_call", stream="stderr",
                  op=name, path=str(path), data_bytes=len(args["data"]))
        return text_result(f"wrote {len(args['data'])} bytes to {path}")
    if name == "read_file":
        path = Path(args["path"])
        data = path.read_text(encoding="utf-8")
        log_event(SERVER_NAME, "tool_call", stream="stderr",
                  op=name, path=str(path), data_bytes=len(data))
        return text_result(data)
    if name == "list_directory":
        path = Path(args["path"])
        entries = sorted(p.name + ("/" if p.is_dir() else "") for p in path.iterdir())
        log_event(SERVER_NAME, "tool_call", stream="stderr",
                  op=name, path=str(path), entries=len(entries))
        return text_result("\n".join(entries) if entries else "(empty)")
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
    (WORKSPACE / "out").mkdir(parents=True, exist_ok=True)
    log_event(SERVER_NAME, "start", port=PORT,
              workspace=str(WORKSPACE), tools=[t["name"] for t in TOOLS])
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
