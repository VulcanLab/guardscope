#!/usr/bin/env python3
"""T1 gateway service (C3/T1-2): MCP Security Gateway between harness and tools.

Deployment-design T1 ("Gateway for HTTP tools, no egress restriction"): every
harness tool call over HTTP crosses this enforcement point. The enforcement
logic is Microsoft's agent-governance-toolkit MCPGateway (agent-os-kernel
package, MCP Security Gateway spec 1.0) — this container is thin glue:

  harness ──JSON-RPC POST /mcp──▶ gateway ──intercept_tool_call()──▶ forward ──▶ upstream MCP server
                                    │
                                    └─ audit_sink ─▶ decisions.jsonl (enforcement-point record)

Protocol: single-message streamable HTTP (POST /mcp), same wire shape as
targets/mcp-http/server.py. initialize / tools/list / ping are forwarded
untouched; tools/call is intercepted: allowed -> forwarded, denied -> JSON-RPC
error returned WITHOUT contacting the upstream (fail-closed).

The audit sink writes one JSON line per decision (AuditEntry dict, spec §12:
timestamp, agent_id, tool_name, allowed, reason, approval_status) to
$GATEWAY_LOG_DIR/decisions.jsonl — the file the T1-4 enforcement-point sensor
parses — plus stdout for docker-logs capture.
"""

import json
import os
import sys
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

PORT = int(os.environ.get("GATEWAY_PORT", "8090"))
UPSTREAM = os.environ.get("UPSTREAM_URL", "http://mcp-http:8091/mcp")
# T3 ("gateway as sole enforcement point, all tools behind it"): a second
# upstream for the fs tools (targets/mcp-fs-http); unset = single-upstream
# mode (T1). Tool calls route by tool name (FS_TOOLS); tools/list merges both
# upstreams' tool lists. The gateway itself is never jailed — the egress
# policy constrains the HARNESS netns (the harness reaches only gateway:8090).
UPSTREAM_FS = os.environ.get("UPSTREAM_FS_URL", "")
FS_TOOLS = {t.strip() for t in os.environ.get(
    "FS_TOOLS", "write_file,read_file,list_directory").split(",") if t.strip()}
POLICY_PATH = Path(os.environ.get("GATEWAY_POLICY", "/etc/gateway/policy.yaml"))
LOG_DIR = Path(os.environ.get("GATEWAY_LOG_DIR", "/var/log/gateway"))
AGENT_ID = os.environ.get("GATEWAY_AGENT_ID", "t1-replay")

SUPPORTED_VERSIONS = ["2024-11-05", "2025-03-26", "2025-06-18"]
LATEST_SUPPORTED = SUPPORTED_VERSIONS[-1]

# Forwarded-to-upstream methods (everything else is a JSON-RPC error).
FORWARDED = {"initialize", "notifications/initialized", "ping", "tools/list"}


# --- policy + audit (importable without agent_os for docker-free tests) -----

def load_policy_yaml(path: Path) -> dict:
    """Parse gateway/policy.yaml into the GovernancePolicy kwargs the
    enforcement engine consumes. Kept explicit so the deployed policy is an
    auditable artifact (hashed into the run manifest by T1-4)."""
    import yaml
    raw = yaml.safe_load(path.read_text())
    return {
        "name": raw["name"],
        "allowed_tools": list(raw["allowed_tools"]),
        "denied_tools": list(raw.get("denied_tools", [])),
        "sensitive_tools": list(raw.get("sensitive_tools", [])),
        # per-agent budget; set above the trace size so T1 measures coverage of
        # an allow-all policy, not rate-limiting (rate-limit probes are later)
        "max_tool_calls": int(raw.get("max_tool_calls", 1000)),
        "blocked_patterns": list(raw.get("blocked_patterns", [])),
    }


class JsonlAuditSink:
    """MCPAuditSink: one AuditEntry dict per line, stdout + decisions.jsonl."""

    def __init__(self, log_dir: Path) -> None:
        self.path = log_dir / "decisions.jsonl"

    def record(self, entry: dict) -> None:
        line = json.dumps(entry, separators=(",", ":"))
        print(line, flush=True)
        try:
            if self.path.parent.is_dir():
                with open(self.path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
        except OSError:
            pass  # logging must never break enforcement


def build_gateway(policy_kwargs: dict):
    """Instantiate the AGT MCPGateway (imported lazily so the pure helpers
    above stay testable outside the container)."""
    from agent_os.integrations.base import GovernancePolicy
    from agent_os.mcp_gateway import MCPGateway

    # Allow-list from policy.yaml (the three trace tool names, T1 allow-all);
    # the denial path stays reachable in later designs via denied/sensitive tools.
    policy = GovernancePolicy(
        name=policy_kwargs["name"],
        allowed_tools=policy_kwargs["allowed_tools"],
        blocked_patterns=policy_kwargs["blocked_patterns"],
        max_tool_calls=policy_kwargs["max_tool_calls"],
    )
    return MCPGateway(
        policy,
        denied_tools=policy_kwargs["denied_tools"],
        sensitive_tools=policy_kwargs["sensitive_tools"],
        audit_sink=JsonlAuditSink(LOG_DIR),
    )


def forward(msg: dict, upstream: str | None = None, timeout: float = 15.0) -> dict:
    req = urllib.request.Request(upstream or UPSTREAM, data=json.dumps(msg).encode(),
                                 method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def route_upstream(tool_name: str) -> str:
    """T3: fs tools -> the fs upstream; everything else -> the primary."""
    return UPSTREAM_FS if (UPSTREAM_FS and tool_name in FS_TOOLS) else UPSTREAM


def merged_tools_list(msg: dict) -> dict:
    """tools/list across both upstreams (T3): union of the tool lists."""
    tools: list[dict] = []
    for upstream in ([UPSTREAM, UPSTREAM_FS] if UPSTREAM_FS else [UPSTREAM]):
        try:
            tools.extend(forward(msg, upstream).get("result", {}).get("tools", []))
        except OSError:
            pass  # a down upstream contributes no tools; enforcement is unaffected
    return {"jsonrpc": "2.0", "id": msg.get("id"), "result": {"tools": tools}}


# --- HTTP endpoint -----------------------------------------------------------

class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_POST(self) -> None:
        gateway = self.server.gateway  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b""

        def respond(code: int, payload: bytes) -> None:
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def jsonrpc_err(id_, code, message):
            return {"jsonrpc": "2.0", "id": id_, "error": {"code": code, "message": message}}

        try:
            msg = json.loads(raw)
        except json.JSONDecodeError as exc:
            respond(400, json.dumps(jsonrpc_err(None, -32700, f"parse error: {exc}")).encode())
            return

        method = msg.get("method", "")
        if method == "notifications/initialized":
            respond(202, b"")
            return
        if method == "tools/call":
            self._handle_tool_call(gateway, msg, respond, jsonrpc_err)
            return
        if method in FORWARDED:
            # initialize / ping / tools/list: proxy untouched (tools/list is
            # merged across upstreams in T3 multi-upstream mode)
            try:
                if method == "tools/list" and UPSTREAM_FS:
                    respond(200, json.dumps(merged_tools_list(msg),
                                            separators=(",", ":")).encode())
                else:
                    respond(200, json.dumps(forward(msg), separators=(",", ":")).encode())
            except OSError as exc:
                respond(502, json.dumps(jsonrpc_err(msg.get("id"), -32000,
                                                    f"upstream unreachable: {exc}")).encode())
            return
        respond(200, json.dumps(jsonrpc_err(msg.get("id"), -32601,
                                            f"method not found: {method}")).encode())

    def _handle_tool_call(self, gateway, msg: dict, respond, jsonrpc_err) -> None:
        # --- tools/call: the enforcement point ------------------------------
        params = msg.get("params") or {}
        tool_name = params.get("name", "")
        arguments = params.get("arguments") or {}
        # returns (allowed, reason); SDK records the AuditEntry via audit_sink
        allowed, reason = gateway.intercept_tool_call(AGENT_ID, tool_name, arguments)
        if not allowed:
            respond(200, json.dumps(jsonrpc_err(
                msg.get("id"), -32001, f"gateway denied {tool_name!r}: {reason}")).encode())
            return
        try:
            respond(200, json.dumps(forward(msg, route_upstream(tool_name)),
                                    separators=(",", ":")).encode())
        except OSError as exc:
            respond(502, json.dumps(jsonrpc_err(msg.get("id"), -32000,
                                                f"upstream unreachable: {exc}")).encode())

    def log_message(self, fmt, *args):  # silence default stderr access log
        pass


def main() -> None:
    policy_kwargs = load_policy_yaml(POLICY_PATH)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    gateway = build_gateway(policy_kwargs)
    print(json.dumps({"ts": "start", "gateway": "agt-mcp-security-gateway",
                      "port": PORT, "upstream": UPSTREAM,
                      "agent_id": AGENT_ID, "policy": policy_kwargs}), flush=True)
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.gateway = gateway  # type: ignore[attr-defined]
    server.serve_forever()


if __name__ == "__main__":
    main()
