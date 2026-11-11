"""Originators: one deterministic OS-level performer per canonical action.

The mock harness's action surface is the canonical trace spec
(trace/traces/baseline.yaml) — the SINGLE SOURCE OF TRUTH for the action
list, order, and arguments; this module hardcodes no action ids. The driver
compiles each spec action through the harness compiler
(trace/compile/pi/compile.py) and dispatches it to exactly one originator
function resolved by (class, op):

  stdio_tool_call   -> the inspected pair of the harness's own T0-T2
                       transport: one MCP stdio session per run (the fs tool
                       server as a mock-harness child), NDJSON JSON-RPC
                       initialize + tools/call over pipes; T3 plan route
                       (routes.stdio=gateway): one MCP tools/call JSON-RPC
                       POST to the gateway per action instead (the harness's
                       GATEWAY_FS route — the stdio transport eliminated,
                       no local server child)
  http_tool_call    -> raw route: plain HTTP request to the trace's own
                       endpoint (the T0 fetch shape); gateway route: MCP
                       tools/call JSON-RPC POST to the gateway /mcp endpoint
                       (the T1+ harness route; plan-selectable)
  direct_network    -> raw socket: tcp connect+send+recv / udp sendto to
                       the net-peer target (unwatched channels)
  process_spawn     -> fork + execve with the canonical argv; three plan-
                       selectable variants: ordinary (pipe-captured stdout,
                       waited), outliving (no wait; the record completes at
                       submission), daemon (double-fork + setsid, worker
                       reparented to init)
  file_write        -> direct open/write from this process (O_TRUNC|O_APPEND)
  credential_access -> direct O_RDONLY read of the seeded secret file

Policy-blind: no originator checks, classifies, allows, or denies anything.
Errors (connection refused, ENOENT, nonzero exit) are returned as data to
the driver's record — the mock harness executes the FULL surface
unconditionally and never self-reports whether an action was "caught".

Determinism: fixed request shapes, fixed payloads (from the spec), no LLM,
no wall-clock-dependent branching; timestamps are recorded, never consulted.

All OS effects go through mock_harness.syscalls (see that module for why).
"""

from __future__ import annotations

import json
import os
import shutil
from urllib.parse import urlsplit

from mock_harness import MOCK_HARNESS_VERSION, syscalls
from framework.version import __version__

MCP_PROTOCOL_VERSION = "2025-06-18"
# the client is the mock harness, shipped with the framework, so its
# client version is the framework package version (framework/version.py,
# the single source of truth)
MCP_CLIENT_INFO = {"name": "inspection-mock-harness", "version": __version__}

# Correlation carriers (DESIGN.md 5; mirrors harnesses/pi/adapter/replay.ts):
# the driver is the id authority on the workload side and stamps the canonical
# trace action ids onto the tool-call transports. Carrier 1: the tools/call
# params._meta namespaced keys; carrier 2: the x-inspection-* HTTP headers on
# raw (non-MCP) http requests. The mock harness sets them wherever the pairs
# build a request, exactly like the real adapter (the ids are trace-derived
# strings; the originators stay policy-blind — carriers are provenance, never
# a policy check).
META_ACTION_ID = "io.inspection/action_id"
META_ATTEMPT = "io.inspection/attempt"
HEADER_ACTION_ID = "x-inspection-action-id"
HEADER_ATTEMPT = "x-inspection-attempt"

# (method, path) -> gateway tool for the http pairs under the gateway route.
# Mirrors targets/mcp-http TOOL_ROUTES and the adapters' GATEWAY_TOOL_ROUTES
# (one route can serve several spec instances: a011 and a014 share POST
# /hook / post_hook — same shape as the coverage loader's routing).
GATEWAY_TOOL_ROUTES = {
    ("POST", "/hook"): "post_hook",
    ("GET", "/health"): "get_health",
    ("PUT", "/state"): "put_state",
}

# T3: the gateway routes the fs tools by their BARE names (gateway/server.py
# FS_TOOLS — write_file/read_file/list_directory, the names policy-t3.yaml
# allows). The compiled stdio actions carry the bare op as the tool name
# (trace/compile/pi/compile.py), but a namespaced form (mcp__<server>__<tool>,
# the pi adapter's stdio tool names) maps to the same bare tool.
def gateway_tool_name(tool: str) -> str:
    return tool.split("__")[-1] if tool.startswith("mcp__") else tool

SPAWN_VARIANTS = ("ordinary", "outliving", "daemon")
DEFAULT_STDIO_SERVER_CMD = [
    "python3", "-u",
    str(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "targets", "mcp-stdio", "server.py")),
]


class SpawnError(Exception):
    """A spawn variant failed (exec error, nonzero exit)."""


class GatewaySession:
    """One streamable-HTTP MCP session against the gateway — the mock
    driver's gateway-route transport (the shared client of BOTH pairs'
    gateway routes). Speaks the MCP streamable-HTTP wire protocol:

    - `Accept: application/json, text/event-stream` on every POST (the
      MCP spec's required negotiation; agentgateway v1.5.0 enforces it,
      the v0 AGT gateway ignores it);
    - stateful: initialize once, then carry the `Mcp-Session-Id` the
      initialize response returned on every request (agentgateway
      requires it; the v0 gateway ignores it);
    - the response may arrive SSE-framed (`text/event-stream` with
      `data:` frames) or as plain JSON — decoded by Content-Type.

    One session per run (the same multiplicity as the stdio pair's
    StdioSession), started lazily on the first gateway-routed action. A
    gateway denial surfaces as data: a non-2xx status or a JSON-RPC error
    object is returned to the caller (the originator raises SpawnError
    with it — a denial is a decision the run records, never a transport
    error)."""

    def __init__(self, url: str):
        self.url = url.rstrip("/") + "/mcp"
        self.session_id: str | None = None
        self._rpc_id = 0

    def start(self) -> None:
        _status, init = self._request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": MCP_CLIENT_INFO,
        })
        if not init.get("result"):
            raise SpawnError(f"MCP initialize failed: {json.dumps(init)}")
        self._notify("notifications/initialized")

    def _request(self, method: str, params: object) -> tuple[int, dict]:
        self._rpc_id += 1
        return self._post({"jsonrpc": "2.0", "id": self._rpc_id,
                           "method": method, "params": params})

    def _notify(self, method: str) -> None:
        status, _row = self._post({"jsonrpc": "2.0", "method": method})
        if status >= 400:
            raise SpawnError(f"MCP {method} rejected: HTTP {status}")

    def _post(self, msg: dict) -> tuple[int, dict]:
        headers = {"Content-Type": "application/json",
                  # the MCP streamable-HTTP negotiation: the server may
                  # answer either shape, so both must be acceptable
                  "Accept": "application/json, text/event-stream"}
        if self.session_id is not None:
            headers["Mcp-Session-Id"] = self.session_id
        status, resp_headers, body = syscalls.http_request_full(
            "POST", self.url, json.dumps(msg, separators=(",", ":")),
            headers)
        session = resp_headers.get("mcp-session-id")
        if session:
            self.session_id = session
        if msg.get("id") is None:
            # a notification: the server answers 202 with no JSON-RPC body
            if status >= 400:
                raise SpawnError(f"MCP {msg.get('method')} rejected: "
                                 f"HTTP {status}")
            return status, {}
        if status >= 400:
            # a denial (or a rejected request) is data, never a transport
            # error: surfaced as an error row the caller records
            return status, {"error": {"code": status,
                                       "message": body.decode(
                                           "utf-8", "replace")}}
        row = _decode_sse_or_json(body, resp_headers.get("content-type", ""),
                                  msg["id"])
        return status, row

    def tools_call(self, tool: str, arguments: dict,
                   meta: dict | None = None) -> tuple[int, dict]:
        """One tools/call request; `meta` is the params._meta correlation
        carrier block (DESIGN.md 5) when given."""
        params = {"name": tool, "arguments": arguments}
        if meta is not None:
            params["_meta"] = dict(meta)
        return self._request("tools/call", params)

    def close(self) -> None:
        # stateless client side: the server-side session ends at its idle
        # TTL; nothing to tear down (the same asymmetry as the raw http
        # originator, which closes nothing but the socket per request)
        pass


def _decode_sse_or_json(body: bytes, content_type: str,
                        expected_id=None) -> dict:
    """Decode one MCP JSON-RPC response from a streamable-HTTP body: plain
    JSON (`application/json`) or SSE-framed (`text/event-stream`, the
    `data:` frames of the response messages). `expected_id` (the request's
    JSON-RPC id) selects the correlated response frame out of the stream
    (SSE bodies may carry unrelated frames; the pre-guardscope probe's
    decodeRpc rule); None accepts the first frame carrying an id."""
    text = body.decode("utf-8", "replace")
    if "text/event-stream" not in content_type:
        row = json.loads(text)
        if expected_id is not None and row.get("id") != expected_id:
            raise SpawnError("gateway MCP response id mismatch "
                             f"({row.get('id')!r} != {expected_id!r})")
        return row
    for frame in text.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(line[5:].lstrip()
                         for line in frame.split("\n")
                         if line.startswith("data:"))
        if not data:
            continue
        row = json.loads(data)
        if not isinstance(row, dict) or "id" not in row:
            continue
        if expected_id is None or row.get("id") == expected_id:
            return row
    raise SpawnError("no correlated MCP JSON-RPC response "
                     f"(id {expected_id!r}) in the SSE stream")


def gateway_tools_call(ctx: "RunContext", tool: str,
                       arguments: dict) -> tuple[int, dict]:
    """One MCP tools/call through the run's gateway session (the shared
    request path for BOTH pairs' gateway routes: the http pair's T1+
    route and the stdio pair's T3 route; UPSTREAM_FS_URL) with the
    io.inspection carriers in params._meta (carrier 1, DESIGN.md 5).
    A route without a gateway_url is an error raised to the driver
    (recorded as data, never a run failure)."""
    if not ctx.gateway_url:
        raise SpawnError("gateway route selected but no gateway_url (plan "
                         "routes.gateway_url or env GATEWAY_URL)")
    status, row = ctx.gateway().tools_call(
        tool, arguments, meta={META_ACTION_ID: ctx.action_id,
                               META_ATTEMPT: 0})
    if row.get("error"):
        raise SpawnError(f"gateway returned a json-rpc error response "
                         f"for {tool}: {json.dumps(row['error'])}")
    return status, row


# --- child-side helpers ------------------------------------------------------

def _exec_child(argv: list[str], stdin_fd: int | None = None,
                stdout_fd: int | None = None,
                close_fds: tuple[int, ...] = (), devnull: bool = False) -> None:
    """Child-side wiring + execve. NEVER returns: any failure exits 127
    immediately (os._exit skips buffer flushes, so a failed exec can never
    fall back into the parent's run loop). Kept as its own function so the
    attempted syscall sequence is unit-testable without a real fork.

    argv[0] without a slash is resolved through PATH first (execv(2) does
    not search PATH; the harness's node spawn does — same observable
    shape: execve of the resolved pathname, original argv).
    """
    try:
        for fd in close_fds:
            syscalls.close_fd(fd)
        if devnull:
            null_fd = syscalls.open_devnull_rw()
            syscalls.dup2(null_fd, 0)
            syscalls.dup2(null_fd, 1)
            syscalls.dup2(null_fd, 2)
            if null_fd > 2:
                syscalls.close_fd(null_fd)
        else:
            if stdin_fd is not None:
                syscalls.dup2(stdin_fd, 0)
                syscalls.close_fd(stdin_fd)
            if stdout_fd is not None:
                syscalls.dup2(stdout_fd, 1)
                syscalls.close_fd(stdout_fd)
        path = argv[0] if "/" in argv[0] else (shutil.which(argv[0]) or argv[0])
        syscalls.execv(path, list(argv))
    except BaseException:  # noqa: BLE001 — the child must never propagate back
        pass
    syscalls.exit_child(127)


# --- MCP stdio session (the stdio pairs' transport) ---------------------------

class StdioSession:
    """One MCP stdio session per run over pipes to a tool-server child —
    the same wire protocol and child topology as the harness's McpSession
    (targets/mcp-stdio/server.py as a child process, NDJSON JSON-RPC 2.0)."""

    def __init__(self, cmd: list[str]):
        self.cmd = list(cmd)
        self.pid: int | None = None
        self._stdin_w: int | None = None
        self._stdout_r: int | None = None
        self._next_id = 0

    def start(self) -> None:
        stdin_r, stdin_w = syscalls.pipe()
        stdout_r, stdout_w = syscalls.pipe()
        pid = syscalls.fork()
        if pid == 0:
            _exec_child(self.cmd, stdin_fd=stdin_r, stdout_fd=stdout_w,
                        close_fds=(stdin_w, stdout_r))
        syscalls.close_fd(stdin_r)
        syscalls.close_fd(stdout_w)
        self._stdin_w, self._stdout_r, self.pid = stdin_w, stdout_r, pid
        init = self._request("initialize", {
            "protocolVersion": MCP_PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": MCP_CLIENT_INFO,
        })
        if not init.get("result"):
            raise SpawnError(f"MCP initialize failed: {json.dumps(init)}")
        self._notify("notifications/initialized")

    def _send(self, obj: dict) -> None:
        frame = json.dumps(obj, separators=(",", ":")) + "\n"
        syscalls.write_fd(self._stdin_w, frame.encode("utf-8"))

    def _recv(self) -> dict:
        line = syscalls.read_line(self._stdout_r)
        if line is None:
            raise SpawnError("MCP server closed the pipe (EOF before a response)")
        return json.loads(line.decode("utf-8"))

    def _request(self, method: str, params: object) -> dict:
        self._next_id += 1
        self._send({"jsonrpc": "2.0", "id": self._next_id,
                    "method": method, "params": params})
        return self._recv()

    def _notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def call(self, tool: str, arguments: dict, meta: dict | None = None) -> dict:
        """One tools/call request; `meta` is the params._meta correlation
        carrier block (DESIGN.md 5) when given, mirroring the harness's
        McpSession call shape."""
        params = {"name": tool, "arguments": arguments}
        if meta is not None:
            params["_meta"] = dict(meta)
        return self._request("tools/call", params)

    def close(self) -> None:
        """End the session: stdin EOF (the server exits), reap the child."""
        if self._stdin_w is not None:
            syscalls.close_fd(self._stdin_w)
            self._stdin_w = None
        if self.pid is not None:
            syscalls.waitpid(self.pid)
            self.pid = None
        if self._stdout_r is not None:
            syscalls.close_fd(self._stdout_r)
            self._stdout_r = None


# --- spawn variants ------------------------------------------------------------

def _spawn_ordinary(argv: list[str], ctx: "RunContext") -> dict:
    """fork + execve, pipe-captured stdout (dispatch-free output
    consumption), parent waits for the exit code."""
    read_fd, write_fd = syscalls.pipe()
    pid = syscalls.fork()
    if pid == 0:
        _exec_child(argv, stdout_fd=write_fd, close_fds=(read_fd,))
    syscalls.close_fd(write_fd)
    stdout = syscalls.read_all(read_fd)
    syscalls.close_fd(read_fd)
    _, status = syscalls.waitpid(pid)
    code = syscalls.exit_code(status)
    detail = {
        "argv": list(argv),
        "pid": pid,
        "exit_code": code,
        "stdout": stdout.decode("utf-8", "replace"),
        "waited": True,
    }
    if code != 0:
        raise SpawnError(f"{argv[0]} exited {code} (argv={argv})")
    return detail


def _spawn_outliving(argv: list[str], ctx: "RunContext") -> dict:
    """fork + execve with NO capture and NO wait: the record completes at
    submission; the child's execve/effect occur after the record's end (the
    outliving-processes escape). The driver joins before process exit."""
    pid = syscalls.fork()
    if pid == 0:
        _exec_child(argv)   # stdout inherited: no capture, no consumption
    ctx.defer(pid, "outliving")
    return {
        "argv": list(argv),
        "submitted_pid": pid,
        "waited": False,
        "stdout": "(not consumed: outliving submission)",
    }


def _daemonize_intermediate(argv: list[str], pid_r: int, pid_w: int) -> None:
    """Intermediate child of the daemon variant: new session (setsid),
    fork the worker (which execve's the canonical argv and never returns),
    report the worker pid over the pipe, then exit. NEVER returns to the
    caller — a failure can never propagate back into the parent's run loop."""
    try:
        syscalls.setsid()
        worker_pid = syscalls.fork()
        if worker_pid == 0:
            _exec_child(argv, close_fds=(pid_r, pid_w), devnull=True)
        syscalls.close_fd(pid_r)
        syscalls.write_fd(pid_w, f"{worker_pid}\n".encode())
        syscalls.close_fd(pid_w)
    except BaseException:  # noqa: BLE001 — the intermediate must never propagate back
        pass
    syscalls.exit_child(0)


def _spawn_daemon(argv: list[str], ctx: "RunContext") -> dict:
    """Double-fork + setsid + execve: the intermediate child starts a new
    session, forks the worker, reports its pid over a pipe, and exits; the
    worker is reparented to init, stdio to /devnull (the daemon-submissions
    escape)."""
    pid_r, pid_w = syscalls.pipe()
    pid = syscalls.fork()
    if pid == 0:
        _daemonize_intermediate(argv, pid_r, pid_w)
    syscalls.close_fd(pid_w)
    line = syscalls.read_line(pid_r)
    syscalls.close_fd(pid_r)
    _, status = syscalls.waitpid(pid)   # reap the intermediate
    if line is None:
        raise SpawnError("daemonize: no worker pid came back over the pipe")
    worker_pid = int(line)
    ctx.defer(worker_pid, "daemon")
    return {
        "argv": list(argv),
        "submitted_pid": worker_pid,
        "intermediate_pid": pid,
        "setsid": True,
        "waited": False,
    }


# --- per-class originators ------------------------------------------------------

def stdio_tool_call(rec: dict, ctx: "RunContext", variant: str = "default") -> dict:
    """The inspected pair, plan-routed (routes.stdio, DESIGN.md 8):

    local (default)   the harness's own T0-T2 transport — tools/call over
                      the run's MCP stdio session to a local server child
    gateway (T3)      the harness's GATEWAY_FS route — the stdio transport
                      is ELIMINATED and the fs tools are proxied behind the
                      gateway: one MCP tools/call over HTTP per action, no
                      local server child (compose/t3.yaml)
    """
    arguments = rec.get("arguments") or {}
    # the gateway routes the fs tools by their bare names (FS_TOOLS); the
    # compiled tool name is the bare op already, namespaced forms map to it
    tool = gateway_tool_name(rec["tool"])
    if ctx.stdio_route == "gateway":
        status, resp = gateway_tools_call(ctx, tool, arguments)
        text = resp["result"]["content"][0]["text"]
        return {
            "server": rec["server"],
            "tool": rec["tool"],
            "arguments": arguments,
            "via": "gateway",
            "gateway_tool": tool,
            "gateway_url": ctx.gateway_url,
            "http_status": status,
            "response_bytes": len(text.encode("utf-8")),
        }
    session = ctx.stdio()
    # carrier 1 (DESIGN.md 5): the tools/call params._meta namespaced keys —
    # the same carrier the pi adapter injects on every stdio tools/call
    resp = session.call(rec["tool"], arguments,
                        meta={META_ACTION_ID: ctx.action_id, META_ATTEMPT: 0})
    if resp.get("error"):
        raise SpawnError(f"mcp {rec['tool']}: {json.dumps(resp['error'])}")
    text = resp["result"]["content"][0]["text"]
    return {
        "server": rec["server"],
        "tool": rec["tool"],
        "arguments": arguments,
        "response_bytes": len(text.encode("utf-8")),
    }


def http_tool_call(rec: dict, ctx: "RunContext", variant: str = "default") -> dict:
    """The inspected pair, plan-routed: raw fetch to the trace's own endpoint
    (T0 shape) or MCP tools/call JSON-RPC POST to the gateway (T1+ shape)."""
    if ctx.http_route == "gateway":
        url_path = urlsplit(rec["url"]).path or "/"
        tool = GATEWAY_TOOL_ROUTES.get((rec["op"], url_path))
        if tool is None:
            raise SpawnError(f"no gateway tool route for {rec['op']} {url_path}")
        arguments = {}
        if rec.get("body") is not None:
            arguments["body"] = rec["body"]
        # the shared gateway request builder (same JSON-RPC POST + _meta
        # carriers as the stdio pair's gateway route)
        status, _data = gateway_tools_call(ctx, tool, arguments)
        return {
            "via": "gateway",
            "tool": tool,
            "arguments": arguments,
            "gateway_url": ctx.gateway_url,
            "http_status": status,
        }
    body = rec.get("body")
    # carrier 2 (DESIGN.md 5): the x-inspection-* headers on the raw fetch
    # (the same header carrier the pi adapter sends on raw http tool calls)
    status, _ = syscalls.http_request(
        rec["op"], rec["url"], body,
        headers={HEADER_ACTION_ID: str(ctx.action_id), HEADER_ATTEMPT: "0"})
    return {
        "via": "raw",
        "method": rec["op"],
        "url": rec["url"],
        "http_status": status,
    }


def direct_network_tcp(rec: dict, ctx: "RunContext", variant: str = "default") -> dict:
    """Raw socket: connect to the net-peer target, send the payload, read
    the ack, close (the unwatched-channels escape)."""
    sock = syscalls.tcp_socket()
    try:
        syscalls.connect(sock, rec["host"], rec["port"])
        payload = (rec.get("payload") or "").encode("utf-8")
        syscalls.sendall(sock, payload)
        received = syscalls.recv(sock)
    finally:
        syscalls.close_socket(sock)
    return {
        "host": rec["host"],
        "port": rec["port"],
        "payload_bytes": len(payload),
        "received_bytes": len(received or b""),
    }


def direct_network_udp(rec: dict, ctx: "RunContext", variant: str = "default") -> dict:
    """Raw unconnected datagram: one sendto to the net-peer target (the
    unwatched-channels escape)."""
    sock = syscalls.udp_socket()
    try:
        payload = (rec.get("payload") or "").encode("utf-8")
        syscalls.sendto(sock, payload, rec["host"], rec["port"])
    finally:
        syscalls.close_socket(sock)
    return {
        "host": rec["host"],
        "port": rec["port"],
        "payload_bytes": len(payload),
    }


def process_spawn_exec(rec: dict, ctx: "RunContext", variant: str = "ordinary") -> dict:
    """fork + execve with the canonical compiled argv; the plan's variant
    selects the process-lifetime escape shape (ordinary/outliving/daemon)."""
    argv = [str(part) for part in rec["cmd"]]
    if variant == "ordinary":
        detail = _spawn_ordinary(argv, ctx)
    elif variant == "outliving":
        detail = _spawn_outliving(argv, ctx)
    elif variant == "daemon":
        detail = _spawn_daemon(argv, ctx)
    else:
        raise ValueError(f"{ctx.action_id}: unknown spawn variant {variant!r}")
    detail["deferred"] = variant in ("outliving", "daemon")
    return detail


def file_write(rec: dict, ctx: "RunContext", variant: str = "default") -> dict:
    """Direct write from this process (the direct-origin escape); the
    harness adapter mkdirs the parent first — same shape here."""
    parent = os.path.dirname(rec["path"])
    if parent:
        syscalls.mkdir_p(parent)
    info = syscalls.write_file(rec["path"],
                               rec.get("data", "").encode("utf-8"),
                               append=bool(rec.get("append")))
    return {**info}


def credential_read(rec: dict, ctx: "RunContext", variant: str = "default") -> dict:
    """Direct O_RDONLY read of the seeded secret file (the direct-origin
    escape). Only the byte count enters the record, never the content."""
    data = syscalls.read_file(rec["path"])
    return {"path": rec["path"], "bytes": len(data)}


# --- dispatch ----------------------------------------------------------------

_BY_CLASS = {
    "stdio_tool_call": stdio_tool_call,
    "http_tool_call": http_tool_call,
    "process_spawn": process_spawn_exec,
    "file_write": file_write,
    "credential_access": credential_read,
}
_BY_DIRECT_NETWORK_OP = {
    "tcp_connect": direct_network_tcp,
    "udp_send": direct_network_udp,
}


def resolve_originator(action: dict):
    """Canonical action -> its single originator function.

    Dispatch is keyed by (class, op) — never by action id — so the trace
    spec stays the single source of the action list. Every canonical id
    (a001..a052) resolves to exactly one deterministic function.
    """
    cls, op = action["class"], action["op"]
    if cls == "direct_network":
        fn = _BY_DIRECT_NETWORK_OP.get(op)
    else:
        fn = _BY_CLASS.get(cls)
    if fn is None:
        raise ValueError(f"{action.get('id')}: no originator for "
                         f"class {cls!r} op {op!r}")
    return fn


def default_variant(action: dict) -> str:
    return "ordinary" if action["class"] == "process_spawn" else "default"


# Deterministic origin-channel labels: origin_channel() returns exactly
# the manifest's per-path origin_channel declarations (the drift guard
# cross-checks records against the manifest), and origin_channel_detail()
# carries the variant/routing detail.
_SPAWN_CHANNEL_DETAILS = {
    "ordinary": "fork+execve (pipe-captured stdout; parent waits)",
    "outliving": "fork+execve (no wait; record completes before the child's effect)",
    "daemon": "double-fork+setsid+execve (reparented worker, /devnull stdio)",
}


def origin_channel(fn, variant: str, ctx: "RunContext") -> str:
    """The OS channel this originator performs its action through — known
    BEFORE execution (it is a property of the resolved originator + plan),
    so error records carry it too. Must equal the manifest's origin_channel
    for the action, EXCEPT the stdio pair under the T3 gateway route: the
    route eliminates the local stdio child (the manifest's canonical
    mcp-stdio-child-pipe) and performs the tools/call as an HTTP connect to
    the gateway — the same pooled origin as the http pair, which is the t3
    finding itself (kernel sees one pooled connect per tool call)."""
    if fn is stdio_tool_call:
        return ("http-connect" if ctx.stdio_route == "gateway"
                else "mcp-stdio-child-pipe")
    if fn is http_tool_call:
        return "http-connect"
    if fn is direct_network_tcp:
        return "raw-socket-tcp"
    if fn is direct_network_udp:
        return "raw-socket-udp"
    if fn is process_spawn_exec:
        return "fork+execve"
    if fn is file_write:
        return "direct-file-write"
    if fn is credential_read:
        return "direct-file-read"
    raise ValueError(f"unknown originator {fn!r}")


def origin_channel_detail(fn, variant: str, ctx: "RunContext") -> str:
    """Human-readable variant/routing detail for the record (the manifest's
    origin_channel_detail carries the same content per path)."""
    if fn is stdio_tool_call and ctx.stdio_route == "gateway":
        return ("MCP tools/call JSON-RPC POST via the gateway (fs tool "
                "proxied; no local stdio server child)")
    if fn is http_tool_call:
        return ("MCP tools/call JSON-RPC POST via the gateway"
                if ctx.http_route == "gateway"
                else "raw fetch to the trace's own endpoint")
    if fn is process_spawn_exec:
        return _SPAWN_CHANNEL_DETAILS[variant]
    return origin_channel(fn, variant, ctx)


# --- per-run context -----------------------------------------------------------

class RunContext:
    """Per-run state shared by the originators: the plan, the single MCP
    stdio session (one per run, matching the harness replay's session
    multiplicity), the single gateway HTTP session (one per run: the
    streamable-HTTP MCP session both gateway-routed pairs share, opened
    lazily so the session handshake happens inside the run, exactly like
    the stdio pair's first call), the JSON-RPC id counters, and the
    deferred-children registry the driver joins before exiting."""

    def __init__(self, run_id: str, plan: dict):
        self.run_id = run_id
        self.plan = plan
        self.action_id: str | None = None
        self.deferred: list[dict] = []
        routes = plan.get("routes") or {}
        self.http_route = routes.get("http", "raw")
        self.stdio_route = routes.get("stdio", "local")
        self.gateway_url = routes.get("gateway_url") or os.environ.get("GATEWAY_URL")
        cmd = plan.get("stdio_server_cmd") or os.environ.get("MCP_SERVER_CMD")
        self.stdio_server_cmd = (json.loads(cmd) if isinstance(cmd, str)
                                 else cmd) or DEFAULT_STDIO_SERVER_CMD
        self._stdio: StdioSession | None = None
        self._gateway: GatewaySession | None = None
        self._rpc_id = 0

    def next_rpc_id(self) -> int:
        self._rpc_id += 1
        return self._rpc_id

    def stdio(self) -> StdioSession:
        if self._stdio is None:
            self._stdio = StdioSession(self.stdio_server_cmd)
            self._stdio.start()
        return self._stdio

    def gateway(self) -> GatewaySession:
        if self._gateway is None:
            self._gateway = GatewaySession(self.gateway_url)
            self._gateway.start()
        return self._gateway

    def defer(self, pid: int, kind: str) -> None:
        self.deferred.append({"id": self.action_id, "pid": pid, "kind": kind})

    def close(self) -> None:
        if self._stdio is not None:
            self._stdio.close()
            self._stdio = None
        if self._gateway is not None:
            self._gateway.close()
            self._gateway = None


def originator_version() -> str:
    return MOCK_HARNESS_VERSION
