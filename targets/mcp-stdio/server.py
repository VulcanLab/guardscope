#!/usr/bin/env python3
"""Toy MCP stdio tool server (C4): the stdio_tool_call target.

Implements the MCP stdio transport (newline-delimited JSON-RPC 2.0 on
stdin/stdout; stderr is the only console logging writer because stdout
MUST carry protocol messages only) with three filesystem tools matching the
baseline trace spec (trace/traces/baseline.yaml):

  write_file {path, data}   read_file {path}   list_directory {path}

Launched as a child of the harness container (M4/M5 adapters wire it into
the harness MCP config). Dependency-free (stdlib only) for reproducibility.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import log_event

SERVER_NAME = "toy-mcp-fs"
SERVER_VERSION = "0.1.0"
# Protocol revisions this server can speak; the client's version is echoed
# back when supported, otherwise the newest supported one.
SUPPORTED_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18"]
LATEST_SUPPORTED = SUPPORTED_VERSIONS[-1]

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
    # notifications: no response
    return None


def main() -> None:
    log_event(SERVER_NAME, "start", stream="stderr", pid=os.getpid(),
              supported_versions=SUPPORTED_VERSIONS)
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError as exc:
            # Unparseable stdin input: respond with a JSON-RPC parse error so
            # the client sees the failure instead of a silent hang.
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