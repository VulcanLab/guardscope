"""C4 side-effect target tests (M2 acceptance).

Exercises every target locally (no Docker): MCP stdio round trip, HTTP
endpoint, TCP/UDP net-peer, credential/workspace seeding — and checks each
target emits the structured served-action logs reconciliation (M6) relies on.

Run from experiments/mediation/:  python3 -m pytest tests/test_targets.py -v
"""

import json
import os
import socket
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest
import yaml

INSPECTION_ROOT = Path(__file__).resolve().parent.parent
TARGETS = INSPECTION_ROOT / "targets"
BASELINE_PATH = INSPECTION_ROOT / "trace" / "traces" / "baseline.yaml"
COMPOSE_PATH = INSPECTION_ROOT / "compose" / "t0.yaml"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def wait_until(fn, timeout=10.0, interval=0.1):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if fn():
                return True
        except Exception:
            pass
        time.sleep(interval)
    return False


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def run_target(script: Path, log_dir: Path, **env) -> subprocess.Popen:
    e = {**os.environ, "TARGET_LOG_DIR": str(log_dir), **{k: str(v) for k, v in env.items()}}
    return subprocess.Popen([sys.executable, "-u", str(script)],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=e)


# --- MCP stdio tool server -------------------------------------------------

class McpClient:
    """Minimal MCP stdio client: newline-delimited JSON-RPC."""

    def __init__(self, log_dir: Path):
        self.proc = subprocess.Popen(
            [sys.executable, "-u", str(TARGETS / "mcp-stdio" / "server.py")],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={**os.environ, "TARGET_LOG_DIR": str(log_dir)},
        )
        self._next_id = 0

    def request(self, method: str, params: dict | None = None) -> dict:
        self._next_id += 1
        msg = {"jsonrpc": "2.0", "id": self._next_id, "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)
        while True:
            resp = self._recv()
            if resp is not None and resp.get("id") == self._next_id:
                return resp
        # (responses to other ids would loop; none expected in this toy flow)

    def notify(self, method: str, params: dict | None = None) -> None:
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self._send(msg)

    def _send(self, msg: dict) -> None:
        self.proc.stdin.write((json.dumps(msg) + "\n").encode())
        self.proc.stdin.flush()

    def _recv(self) -> dict | None:
        line = self.proc.stdout.readline()
        if not line:
            return None
        return json.loads(line)


@pytest.fixture()
def mcp(tmp_path):
    client = McpClient(tmp_path)
    yield client
    client.proc.terminate()


def test_mcp_initialize_and_tools_list(mcp):
    resp = mcp.request("initialize", {
        "protocolVersion": "2025-06-18",
        "capabilities": {},
        "clientInfo": {"name": "test", "version": "0"},
    })
    assert resp["result"]["protocolVersion"] == "2025-06-18"
    assert resp["result"]["serverInfo"]["name"] == "toy-mcp-fs"
    mcp.notify("notifications/initialized")
    tools = mcp.request("tools/list")["result"]["tools"]
    assert {t["name"] for t in tools} == {"write_file", "read_file", "list_directory"}


def test_mcp_fs_tool_roundtrip(mcp, tmp_path):
    mcp.request("initialize", {"protocolVersion": "2025-06-18"})
    mcp.notify("notifications/initialized")
    path = tmp_path / "out" / "a.txt"

    out = mcp.request("tools/call", {
        "name": "write_file", "arguments": {"path": str(path), "data": "hello"}})
    assert "wrote 5 bytes" in out["result"]["content"][0]["text"]
    assert path.read_text() == "hello"

    out = mcp.request("tools/call", {"name": "read_file", "arguments": {"path": str(path)}})
    assert out["result"]["content"][0]["text"] == "hello"

    out = mcp.request("tools/call", {"name": "list_directory",
                                     "arguments": {"path": str(tmp_path / "out")}})
    assert "a.txt" in out["result"]["content"][0]["text"]


def test_mcp_serves_logged(tmp_path):
    """Acceptance: the MCP target observably logs what it serves (stderr + file)."""
    client = McpClient(tmp_path)
    try:
        client.request("initialize", {"protocolVersion": "2025-06-18"})
        client.notify("notifications/initialized")
        f = tmp_path / "x.txt"
        client.request("tools/call", {"name": "write_file",
                                      "arguments": {"path": str(f), "data": "logme"}})
        time.sleep(0.2)
        lines = read_jsonl(tmp_path / "toy-mcp-fs.log")
        calls = [l for l in lines if l["event"] == "tool_call"]
        assert any(l["op"] == "write_file" and l["path"] == str(f) for l in calls)
        # stderr (captured after termination) must also carry the log lines,
        # and stdout must contain ONLY JSON-RPC messages (MCP stdio rule).
    finally:
        client.proc.terminate()
        _, stderr = client.proc.communicate(timeout=5)
        stderr_events = [json.loads(l) for l in stderr.decode().splitlines() if l.startswith("{")]
        assert any(e["event"] == "tool_call" and e["op"] == "write_file"
                   for e in stderr_events)


def test_mcp_unknown_tool_is_error(mcp):
    mcp.request("initialize", {"protocolVersion": "2025-06-18"})
    resp = mcp.request("tools/call", {"name": "nope", "arguments": {}})
    assert resp["error"]["code"] == -32602


# --- HTTP endpoint -----------------------------------------------------------

def test_http_endpoint_logs_served_requests(tmp_path):
    port = free_port()
    proc = run_target(TARGETS / "http-endpoint" / "server.py", tmp_path, HTTP_PORT=port)
    try:
        base = f"http://127.0.0.1:{port}"
        wait_until(lambda: urllib.request.urlopen(f"{base}/health", timeout=1).status == 200)

        assert json.load(urllib.request.urlopen(f"{base}/health")) == {"status": "ok"}
        req = urllib.request.Request(f"{base}/hook", data=b"tool-call payload", method="POST")
        assert json.load(urllib.request.urlopen(req)) == {"accepted": True}
        req = urllib.request.Request(f"{base}/state", data=b"k=v", method="PUT")
        assert json.load(urllib.request.urlopen(req)) == {"accepted": True}
        try:
            urllib.request.urlopen(f"{base}/nope")
            raise AssertionError("404 expected")
        except urllib.error.HTTPError as e:
            assert e.code == 404

        time.sleep(0.2)
        events = [e for e in read_jsonl(tmp_path / "http-endpoint.log") if e["event"] == "request"]
        by_path = {e["path"]: e for e in events}
        assert by_path["/hook"]["method"] == "POST" and by_path["/hook"]["body_text"] == "tool-call payload"
        assert by_path["/state"]["method"] == "PUT"
        assert by_path["/health"]["method"] == "GET"
        assert by_path["/nope"]  # even 404s are logged for reconciliation debugging
    finally:
        proc.terminate()
        proc.wait(timeout=5)


# --- net-peer ---------------------------------------------------------------

def test_net_peer_logs_tcp_and_udp(tmp_path):
    tcp_port, udp_port = free_port(), free_port()
    proc = run_target(TARGETS / "net-peer" / "server.py", tmp_path,
                      NET_TCP_PORT=tcp_port, NET_UDP_PORT=udp_port)
    try:
        # TCP: connect, send, expect ack
        def tcp_ok():
            with socket.create_connection(("127.0.0.1", tcp_port), timeout=1) as s:
                s.sendall(b"direct tcp")
                return s.recv(16) == b"ack\n"
        wait_until(tcp_ok)

        # UDP: datagram (no ack; verify via the target's log)
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.sendto(b"direct udp", ("127.0.0.1", udp_port))
        time.sleep(0.5)

        events = [e for e in read_jsonl(tmp_path / "net-peer.log") if e["event"] == "received"]
        transports = {e["transport"]: e["payload"] for e in events}
        assert transports.get("tcp") == "direct tcp"
        assert transports.get("udp") == "direct udp"
    finally:
        proc.terminate()
        proc.wait(timeout=5)


# --- credentials + fs seed scripts -------------------------------------------

def test_credentials_seed(tmp_path):
    script = TARGETS / "credentials" / "seed.sh"
    subprocess.run(["bash", str(script)], check=True,
                   env={**os.environ, "SECRETS_DIR": str(tmp_path)},
                   capture_output=True)
    token, db = tmp_path / "token", tmp_path / "db_password"
    assert token.read_text() == "baseline-token-0f3a\n"
    assert db.read_text() == "baseline-db-password-9c2e\n"
    assert stat.S_IMODE(token.stat().st_mode) == 0o400
    assert stat.S_IMODE(db.stat().st_mode) == 0o400


def test_fs_setup(tmp_path):
    script = TARGETS / "fs" / "setup.sh"
    subprocess.run(["bash", str(script)], check=True,
                   env={**os.environ, "WORKSPACE_DIR": str(tmp_path)},
                   capture_output=True)
    assert (tmp_path / "out").is_dir()


# --- compose topology matches the canonical trace spec -----------------------

def test_compose_services_match_baseline_targets():
    baseline = yaml.safe_load(BASELINE_PATH.read_text())
    compose = yaml.safe_load(COMPOSE_PATH.read_text())
    services = set(compose["services"])
    host_targets = set()
    for action in baseline["actions"]:
        target = action["target"]
        if target.startswith("http://"):
            host_targets.add(target.split("//")[1].split(":")[0])
        elif "://" not in target and ":" in target:
            host_targets.add(target.split(":")[0])  # bare host:port (net-peer)
    assert host_targets == {"http-endpoint", "net-peer"}  # per baseline.yaml
    assert host_targets <= services
    # every deployed-topology service sits on t0net; the Tracee sensor must NOT
    # (it is the measurement instrument, outside the topology per main.tex)
    tracee_img = compose["services"]["tracee"]["image"]
    deployed = {n: c for n, c in compose["services"].items()
                if c.get("image") != tracee_img}
    assert {c["networks"][0] for c in deployed.values()} == {"t0net"}
    tracee = compose["services"]["tracee"]
    assert "t0net" not in (tracee.get("networks") or [])
    assert tracee.get("privileged") is True and tracee.get("pid") == "host"
    assert all("target-logs:/var/log/targets" in c["volumes"]
               for c in deployed.values())  # shared served-action log sink