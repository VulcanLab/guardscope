"""T1-1 acceptance: MCP-over-HTTP tool server (targets/mcp-http).

Docker-free: starts the server on a free port against a stub logging HTTP
endpoint, then exercises the MCP JSON-RPC wire protocol the gateway forwards
(initialize / tools/list / tools/call), the tool-route coverage of the
canonical http_tool_call actions, and the served-action logs.

Run from experiments/mediation/:  python3 -m pytest tests/test_mcp_http.py -v
"""

import importlib.util
import json
import sys
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import yaml


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# Load under an explicit module name: targets/mcp-http/server.py and
# gateway/server.py are both "server.py" and must not collide in sys.modules.
mcp_http_server = _load_module(
    "mcp_http_target",
    Path(__file__).resolve().parent.parent / "targets" / "mcp-http" / "server.py")

from test_targets import free_port  # noqa: E402


class StubEndpoint(BaseHTTPRequestHandler):
    requests: list[dict] = []

    def _serve(self):
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        type(self).requests.append({"method": self.command, "path": self.path,
                                    "body": body.decode()})
        payload = b'{"accepted": true}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = _serve

    def log_message(self, fmt, *args):
        pass


def post(base: str, msg: dict) -> dict | None:
    req = urllib.request.Request(base + "/mcp", data=json.dumps(msg).encode(),
                                 method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=10) as resp:
        raw = resp.read()
        return json.loads(raw) if raw else None


def test_tool_routes_cover_all_http_actions_in_spec():
    """Every canonical http_tool_call action has a tool route (v2: a015
    shares post_hook with a011, distinguished by argument values), and tool
    names are unique so gateway AuditEntry.tool_name maps onto actions."""
    spec = yaml.safe_load((Path(__file__).resolve().parent.parent
                           / "trace" / "traces" / "baseline.yaml").read_text())
    http_actions = [a for a in spec["actions"] if a["class"] == "http_tool_call"]
    op_to_tool = {"POST": "post_hook", "GET": "get_health", "PUT": "put_state"}
    assert len(http_actions) == 4
    assert len(mcp_http_server.TOOL_ROUTES) == 3
    assert len({t["name"] for t in mcp_http_server.TOOLS}) == 3
    for a in http_actions:
        route = mcp_http_server.TOOL_ROUTES[op_to_tool[a["op"]]]
        assert route == (a["op"], a["args"]["path"]), a["id"]


def test_full_roundtrip_through_server():
    """initialize / tools/list / tools/call over the wire; tools/call performs
    the raw upstream HTTP request; unknown tools get a JSON-RPC error."""
    stub = ThreadingHTTPServer(("127.0.0.1", free_port()), StubEndpoint)
    threading.Thread(target=stub.serve_forever, daemon=True).start()
    srv = ThreadingHTTPServer(("127.0.0.1", free_port()), mcp_http_server.Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    StubEndpoint.requests = []
    old_upstream = mcp_http_server.UPSTREAM
    mcp_http_server.UPSTREAM = f"http://127.0.0.1:{stub.server_address[1]}"
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        init = post(base, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                           "params": {"protocolVersion": "2025-06-18", "capabilities": {}}})
        assert init["result"]["serverInfo"]["name"] == "toy-mcp-http"

        listing = post(base, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
        assert [t["name"] for t in listing["result"]["tools"]] == \
            ["post_hook", "get_health", "put_state"]

        call = post(base, {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                           "params": {"name": "post_hook",
                                      "arguments": {"body": "tool-call payload"}}})
        assert "error" not in call
        assert json.loads(call["result"]["content"][0]["text"])["status"] == 200
        assert StubEndpoint.requests == [{"method": "POST", "path": "/hook",
                                          "body": "tool-call payload"}]

        unknown = post(base, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                              "params": {"name": "nope", "arguments": {}}})
        assert unknown["error"]["code"] == -32602
    finally:
        mcp_http_server.UPSTREAM = old_upstream
        srv.shutdown()
        stub.shutdown()


def test_http_request_unreachable_upstream_returns_error():
    """Unreachable upstream yields a JSON-RPC-level error (OSError -> -32000
    in handle()), not a hang or a crash."""
    old = mcp_http_server.UPSTREAM
    mcp_http_server.UPSTREAM = "http://127.0.0.1:1"
    try:
        resp = mcp_http_server.handle({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                                       "params": {"name": "get_health", "arguments": {}}})
        assert resp["error"]["code"] == -32000
    finally:
        mcp_http_server.UPSTREAM = old
