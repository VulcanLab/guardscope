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

import hashlib
import json
import os
import sys
import threading
import time
import urllib.request
from datetime import datetime, timezone
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


# --- native decision-record stream (decision-record/1, M2a) --------------------
#
# Alongside the v0 AuditEntry stream (unchanged; the C1-C4 pipeline and the
# v0 reader-side mapping depend on it), every tools/call decision is also
# emitted as a second, native stream decision-records.jsonl with
# producer.record_source "native" (DESIGN.md 3: the gateway is the emitter
# of its own decisions, not a shim over a vendor log).
#
# DELIBERATE DUPLICATION: the field mapping below mirrors framework/records.py
# audit_entry_to_decision_record. The gateway runs in a container without the
# framework package, so the mapping cannot be imported; the two copies must
# be kept in sync by hand when the schema moves.
#
# Id echo (DESIGN.md 5): action_id/attempt are read from the tools/call
# params._meta namespaced keys (carrier 1) or, absent those, from the
# x-inspection-action-id / x-inspection-attempt headers (carrier 2), and
# echoed verbatim. A control never mints ids (echo only): no carrier means
# a null id, never an invented one.

META_ACTION_ID = "io.inspection/action_id"
META_ATTEMPT = "io.inspection/attempt"
HEADER_ACTION_ID = "x-inspection-action-id"
HEADER_ATTEMPT = "x-inspection-attempt"

# run/stream identity for the native stream. The gateway container is
# long-lived across runs, so a per-run id reaches it only through the
# deployment env (compose wiring may set INSPECTION_RUN_ID; the default marks
# the records unattributed and the reader scopes by the measurement window).
NATIVE_RUN_ID = os.environ.get("INSPECTION_RUN_ID", "unattributed")
NATIVE_STREAM_ID = os.environ.get("INSPECTION_STREAM_ID", "gateway")
NATIVE_PRODUCT = os.environ.get("GATEWAY_PRODUCT",
                                "agent-governance-gateway")
NATIVE_PRODUCT_VERSION = os.environ.get("GATEWAY_PACKAGE_VERSION", "unknown")
NATIVE_PLUGIN = os.environ.get("GATEWAY_PLUGIN", "agt-gateway")
NATIVE_PLUGIN_VERSION = os.environ.get("GATEWAY_PLUGIN_VERSION", "unknown")

# tool name -> (method, path): mirrors framework/reconcile.py
# GATEWAY_TOOL_ROUTES (kept in sync by hand; see the duplication note above).
NATIVE_TOOL_ROUTES = {
    "post_hook": ("POST", "/hook"),
    "get_health": ("GET", "/health"),
    "put_state": ("PUT", "/state"),
}

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid() -> str:
    """26-char ULID (48-bit ms + 80 random bits). Duplicate of
    framework/records.py new_ulid (see the duplication note above)."""
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms << 80) | rand
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(out))


def _now_rfc3339_ms() -> str:
    """RFC3339 ms (the ts format, DESIGN.md 4). Duplicate of
    framework/records.py now_rfc3339_ms."""
    dt = datetime.now(timezone.utc)
    return (dt.strftime("%Y-%m-%dT%H:%M:%S.") +
            f"{dt.microsecond // 1000:03d}Z")


def _parameters_digest(parameters: dict) -> str:
    """sha256 over the canonical JSON form. Duplicate of framework/records.py
    parameters_digest."""
    return hashlib.sha256(
        json.dumps(parameters, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")).hexdigest()


def _native_action_class(tool_name: str) -> str:
    """Tool name -> six-class taxonomy, the same routing-table derivation as
    framework/records.py _v0_action_class (see the duplication note)."""
    if tool_name in NATIVE_TOOL_ROUTES:
        return "http_tool_call"
    if tool_name in FS_TOOLS:
        return "stdio_tool_call"
    return "http_tool_call"


def extract_carriers(params: dict, headers=None) -> dict:
    """Read the correlation carriers off one tools/call (DESIGN.md 5): the
    params._meta namespaced keys first (carrier 1), the HTTP headers second
    (carrier 2). Returns {action_id, attempt, correlation_transport}; absent
    carriers -> (None, 0, "none") — echoed as null, never invented."""
    meta = (params or {}).get("_meta") or {}
    action_id = meta.get(META_ACTION_ID)
    attempt = meta.get(META_ATTEMPT)
    transport = "none"
    if isinstance(action_id, str) and action_id:
        transport = "mcp_meta"
    else:
        action_id = None
        if headers is not None:
            header_id = headers.get(HEADER_ACTION_ID)
            if isinstance(header_id, str) and header_id:
                action_id = header_id
                transport = "http_header"
                try:
                    attempt = int(headers.get(HEADER_ATTEMPT, "0"))
                except (TypeError, ValueError):
                    attempt = 0
    if isinstance(attempt, bool) or not isinstance(attempt, int):
        try:
            attempt = int(attempt)
        except (TypeError, ValueError):
            attempt = 0
    return {"action_id": action_id, "attempt": attempt,
            "correlation_transport": transport}


def native_decision_record(*, tool_name, arguments, allowed, reason=None,
                           action_id=None, attempt=0,
                           correlation_transport="none", seq=0, ts=None,
                           record_id=None, run_id=None, stream_id=None,
                           slot_id="gateway", policy=None) -> dict:
    """Build one decision-record/1 dict for a gateway decision. The JSON
    shape mirrors framework/records.py audit_entry_to_decision_record (the
    deliberate duplication note above): same required fields, but
    producer.record_source "native" and the id carriers echoed (DESIGN.md 5).
    protocol is "mcp": every decision here is a JSON-RPC tools/call over
    HTTP POST /mcp (the v0 reader-side mapping of the same decision says
    "http"; the native emitter names the protocol envelope)."""
    if not isinstance(tool_name, str) or not tool_name:
        raise ValueError("tool_name is required")
    fields = {
        "schema": 1,   # bare stamp (DESIGN.md 4: no type names in data files)
        "record_id": record_id or _ulid(),
        "run_id": run_id or NATIVE_RUN_ID,
        "stream_id": stream_id or NATIVE_STREAM_ID,
        "seq": int(seq),
        "ts": ts or _now_rfc3339_ms(),
        "enforcement_point": {"slot_id": slot_id, "product": NATIVE_PRODUCT,
                              "product_version": NATIVE_PRODUCT_VERSION},
        "producer": {"plugin": NATIVE_PLUGIN,
                     "plugin_version": NATIVE_PLUGIN_VERSION,
                     "record_source": "native"},
        "action_class": _native_action_class(tool_name),
        "protocol": "mcp",
        "tool": tool_name,
        "target": {"kind": "unknown",
                   "note": "gateway-native v1: no structured target"},
        "parameters_digest": _parameters_digest(arguments or {}),
        "action_id": action_id,
        "attempt": int(attempt),
        "correlation_transport": correlation_transport,
        "decision": "allow" if allowed else "deny",
        "policy": dict(policy or {"policy_id": "unknown",
                                  "policy_version": "unknown",
                                  "policy_hash": "unknown"}),
        "parameters": dict(arguments or {}),
        "evidence": [{"kind": "gateway-audit-entry",
                      "locator": {"source": "decisions.jsonl"}}],
    }
    if reason is not None:
        fields["decision_detail"] = str(reason)
    if tool_name in NATIVE_TOOL_ROUTES:
        method, path = NATIVE_TOOL_ROUTES[tool_name]
        fields["method"] = method
        fields["path"] = path
    return fields


class NativeRecordSink:
    """Appends one decision-record/1 line per decision to
    <log_dir>/decision-records.jsonl, with per-stream monotonic seq. Never
    raises into the enforcement path (logging must never break enforcement)."""

    def __init__(self, log_dir: Path) -> None:
        self.path = log_dir / "decision-records.jsonl"
        self._lock = threading.Lock()
        self._seq = 0

    def record(self, **decision) -> None:
        with self._lock:
            seq = self._seq
            self._seq += 1
        rec = native_decision_record(seq=seq, **decision)
        line = json.dumps(rec, separators=(",", ":"))
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
        # native decision-record/1 stream (M2a; see the duplication note at
        # the NATIVE_* constants above). Echo-only ids (DESIGN.md 5); the
        # emission sees the same internal decision the AuditEntry path sees
        # and must never break enforcement.
        native_sink = getattr(self.server, "native_sink", None)
        if native_sink is not None:
            try:
                native_sink.record(
                    tool_name=tool_name, arguments=arguments,
                    allowed=allowed, reason=reason,
                    policy=getattr(self.server, "policy_info", None),
                    **extract_carriers(params, self.headers))
            except Exception:
                pass  # logging must never break enforcement
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
    # the native decision-record stream (M2a) + the policy identity its
    # records carry (DESIGN.md 4 policy block; the v0 AuditEntry carries no
    # policy identity, which is why the reader-side mapping says "unmapped")
    server.native_sink = NativeRecordSink(LOG_DIR)  # type: ignore[attr-defined]
    server.policy_info = {  # type: ignore[attr-defined]
        "policy_id": policy_kwargs["name"],
        "policy_version": os.environ.get("GATEWAY_POLICY_VERSION", "unknown"),
        "policy_hash": hashlib.sha256(POLICY_PATH.read_bytes()).hexdigest(),
    }
    server.serve_forever()


if __name__ == "__main__":
    main()
