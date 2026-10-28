"""Mapping-layer tests (C6, M3 acceptance).

Feeds synthetic Tracee NDJSON events (0.24 JSON format) through
sensor/mapping/map_events.py and asserts each of the six action classes is
mapped correctly, exclusions hold, and unmapped events are retained.

Run from experiments/mediation/:  python3 -m pytest tests/test_mapping.py -v
"""

import importlib.util
import json
from pathlib import Path

import pytest

INSPECTION_ROOT = Path(__file__).resolve().parent.parent
RULES_PATH = INSPECTION_ROOT / "sensor" / "mapping" / "rules.yaml"
MAPPER_PATH = INSPECTION_ROOT / "sensor" / "mapping" / "map_events.py"

SIX_CLASSES = {
    "stdio_tool_call", "http_tool_call", "direct_network",
    "process_spawn", "file_write", "credential_access",
}


def _load_module():
    spec = importlib.util.spec_from_file_location("map_events", MAPPER_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def me():
    return _load_module()


@pytest.fixture()
def mapper(me):
    """Fresh Mapper per test: the stdio rule is stateful across the stream."""
    return me.Mapper(me.load_rules(RULES_PATH))


def tracee_event(name, ts=1000, pid=42, container="c0ffee", **args):
    return {
        "timestamp": ts, "processId": pid, "containerId": container,
        "processName": "workload", "eventName": name,
        "args": [{"name": k, "type": "auto", "value": v} for k, v in args.items()],
    }


def map_one(mapper, ev):
    return mapper.map_event(ev, 0)


# --- six-class happy path ---------------------------------------------------

def test_process_spawn_execve(mapper):
    r = map_one(mapper, tracee_event("execve", pathname="/bin/sh",
                                     argv=["sh", "-c", "echo hi"]))
    assert r["class"] == "process_spawn"
    assert r["detail"]["target"] == "/bin/sh"
    assert r["detail"]["cmd"] == ["sh", "-c", "echo hi"]


def test_http_tool_call_connect_8080(mapper):
    r = map_one(mapper, tracee_event("connect",
                                     addr={"sa_family": "AF_INET",
                                           "sin_addr": "10.0.0.5", "sin_port": 8080}))
    assert r["class"] == "http_tool_call"
    assert r["detail"]["transport"] == "tcp"


def test_http_tool_call_connect_gateway_8090_v6(mapper):
    """rules v6 (T1-5): the harness's HTTP tool call crosses the MCP Security
    Gateway on port 8090 — that connect is the inspected tool call's kernel
    evidence in the harness container."""
    r = map_one(mapper, tracee_event("connect",
                                     addr={"sa_family": "AF_INET",
                                           "sin_addr": "10.0.0.7", "sin_port": 8090}))
    assert r["class"] == "http_tool_call"
    assert r["detail"]["transport"] == "tcp"


def test_direct_network_tcp_and_udp(mapper):
    tcp = map_one(mapper, tracee_event("connect",
                                       addr={"sa_family": "AF_INET",
                                             "sin_addr": "10.0.0.6", "sin_port": 9000}))
    udp = map_one(mapper, tracee_event("sendto",
                                       dest_addr={"sa_family": "AF_INET",
                                                  "sin_addr": "10.0.0.6", "sin_port": 9001}))
    assert tcp["class"] == udp["class"] == "direct_network"
    assert tcp["detail"]["transport"] == "tcp"
    assert udp["detail"]["transport"] == "udp"


def test_credential_access_read(mapper):
    r = map_one(mapper, tracee_event("security_file_open",
                                     pathname="/run/secrets/token", flags="O_RDONLY|O_CLOEXEC"))
    assert r["class"] == "credential_access"
    assert r["detail"]["target"] == "file:///run/secrets/token"


def test_file_write_open(mapper):
    r = map_one(mapper, tracee_event("security_file_open",
                                     pathname="/workspace/out/b.txt",
                                     flags="O_WRONLY|O_CREAT|O_TRUNC"))
    assert r["class"] == "file_write"


def test_stdio_response_unmapped_for_other_procs(mapper):
    """A JSON-RPC response on a pipe from an unregistered process stays unmapped."""
    r = map_one(mapper, tracee_event(
        "write", fd=1, count=64,
        buf='{"jsonrpc":"2.0","id":1,"result":{"content":[]}}'))
    assert r["class"] == "unmapped"


def test_stdio_script_open_by_other_container_isolated(mapper):
    """Script-open registration is scoped to (container, pid)."""
    mapper.map_event(tracee_event("security_file_open",
                                  pathname="/opt/inspection/mcp-fs/server.py",
                                  flags="O_RDONLY", pid=7, container="cA"), 0)
    assert mapper.map_event(tracee_event("write", fd=1, count=10, pid=7,
                                         container="cB"), 1)["class"] == "unmapped"


# --- precedence and disambiguation -------------------------------------------

def test_credential_read_wins_over_file_write(mapper):
    """Order: credential_access is evaluated before file_write."""
    r = map_one(mapper, tracee_event("security_file_open",
                                     pathname="/run/secrets/token", flags="O_RDONLY"))
    assert r["class"] == "credential_access"


def test_file_write_flags_as_int(mapper):
    """Unparsed Tracee output renders flags as ints; must still classify."""
    import os
    r = map_one(mapper, tracee_event("security_file_open",
                                     pathname="/workspace/out/x.txt",
                                     flags=os.O_WRONLY | os.O_CREAT))
    assert r["class"] == "file_write"


def test_credential_read_wrong_flags_not_credential_access(mapper):
    """Opening a secret for WRITING is a file write, not a credential access."""
    r = map_one(mapper, tracee_event("security_file_open",
                                     pathname="/run/secrets/token", flags="O_WRONLY|O_CREAT"))
    assert r is not None and r["class"] == "file_write"


def test_target_log_noise_excluded(mapper):
    """M2 served-action logs are instrumentation, not file_write actions."""
    r = map_one(mapper, tracee_event("security_file_open",
                                     pathname="/var/log/targets/toy-mcp-fs.log",
                                     flags="O_WRONLY|O_APPEND|O_CREAT"))
    assert r["class"] == "unmapped"


def test_unknown_port_stays_unmapped(mapper):
    r = map_one(mapper, tracee_event("connect",
                                     addr={"sa_family": "AF_INET",
                                           "sin_addr": "127.0.0.11", "sin_port": 53}))
    assert r["class"] == "unmapped"
    assert r["detail"]["port"] == 53


def test_port_as_string_sockaddr(mapper):
    """Defensive: sockaddr ports rendered as strings still classify."""
    r = map_one(mapper, tracee_event("connect", addr="sin_port: 9000"))
    assert r["class"] == "direct_network"


def test_sendto_dest_addr_field(mapper):
    """Tracee 0.24: sendto carries the destination in `dest_addr`."""
    r = map_one(mapper, tracee_event("sendto", buf=281474414273064, len=10,
                                     dest_addr={"sa_family": "AF_INET",
                                                "sin_addr": "10.0.0.6", "sin_port": "9001"},
                                     flags=0, addrlen=16))
    assert r["class"] == "direct_network" and r["detail"]["transport"] == "udp"


def test_sendto_null_dest_unmapped(mapper):
    r = map_one(mapper, tracee_event("sendto", dest_addr={"sa_family": "AF_UNSPEC"}))
    assert r["class"] == "unmapped"


def test_stdio_tool_call_via_server_process(mapper):
    """execve of the MCP server registers its pid; its fd-1 write maps."""
    sid = tracee_event("execve", pathname="/usr/local/bin/python3.12",
                       argv=["python3", "-u", "/app/targets/mcp-stdio/server.py"], pid=7)
    spawn = mapper.map_event(sid, 0)  # the execve itself maps as process_spawn...
    assert spawn["class"] == "process_spawn"
    r = mapper.map_event(tracee_event("write", fd=1, count=64, pid=7), 1)
    assert r["class"] == "stdio_tool_call" and r["detail"]["fd"] == 1


def test_stdio_registration_via_script_open(mapper):
    """Tracee 0.24 can report execve with EMPTY argv; the script-open of the
    server file is the reliable registration marker."""
    sid = tracee_event("execve", pathname="/usr/local/bin/python3", argv=[], pid=7)
    spawn = mapper.map_event(sid, 0)
    assert spawn["class"] == "process_spawn"
    # argv empty -> not yet registered
    assert mapper.map_event(tracee_event("write", fd=1, count=64, pid=7), 1)["class"] == "unmapped"
    # opening the server script registers the pid
    open_ev = tracee_event("security_file_open",
                           pathname="/opt/inspection/mcp-fs/server.py",
                           flags="O_RDONLY", pid=7)
    assert mapper.map_event(open_ev, 2)["class"] == "unmapped"  # read-mode script open: not file_write
    r = mapper.map_event(tracee_event("write", fd=1, count=64, pid=7), 3)
    assert r["class"] == "stdio_tool_call" and r["detail"]["fd"] == 1


def test_stdio_other_fd_not_counted(mapper):
    mapper.map_event(tracee_event("execve", argv=["python3", "/app/mcp-stdio/server.py"], pid=7), 0)
    # fd 2 (stderr logging) and fd 3 (log file) are not the stdio pipe
    for fd in (2, 3):
        assert mapper.map_event(tracee_event("write", fd=fd, count=10, pid=7), 1)["class"] == "unmapped"


def test_stdio_other_process_not_counted(mapper):
    mapper.map_event(tracee_event("execve", argv=["python3", "/app/mcp-stdio/server.py"], pid=7), 0)
    assert mapper.map_event(tracee_event("write", fd=1, count=10, pid=99), 1)["class"] == "unmapped"


def test_stdio_server_in_other_container_isolated(mapper):
    mapper.map_event(tracee_event("execve", argv=["/app/mcp-stdio/server.py"], pid=7,
                                  container="cA"), 0)
    assert mapper.map_event(tracee_event("write", fd=1, count=10, pid=7,
                                         container="cB"), 1)["class"] == "unmapped"


# --- stream handling -----------------------------------------------------------

def test_iter_events_skips_noise(me):
    stream = [
        "INFO: startup warning (not json)",
        '{"eventName": "execve", "args": []}',
        "not json at all",
        '{"no_event_name": true}',
        "",
    ]
    events = list(me.iter_events(stream))
    assert len(events) == 1
    assert events[0]["eventName"] == "execve"


def test_rules_version_pinned(me):
    rules = me.load_rules(RULES_PATH)
    assert isinstance(rules["version"], int) and rules["version"] >= 1


def test_all_six_classes_declared(me):
    rules = me.load_rules(RULES_PATH)
    assert set(rules["classes"]) == SIX_CLASSES


def test_rules_invalid_version_rejected(me, tmp_path):
    bad = tmp_path / "rules.yaml"
    bad.write_text("version: draft\nclasses: {}\n")
    with pytest.raises(ValueError):
        me.load_rules(bad)


def test_full_stream_end_to_end(me, mapper, tmp_path):
    """Acceptance-shaped check: a raw NDJSON stream yields all six classes."""
    events = [
        tracee_event("execve", pathname="/bin/sh", argv=["sh", "-c", "echo hi"], ts=1),
        tracee_event("security_file_open", pathname="/run/secrets/token",
                     flags="O_RDONLY", ts=2),
        tracee_event("connect", addr={"sa_family": "AF_INET",
                                      "sin_addr": "10.0.0.5", "sin_port": 8080}, ts=3),
        tracee_event("connect", addr={"sa_family": "AF_INET",
                                      "sin_addr": "10.0.0.6", "sin_port": 9000}, ts=4),
        tracee_event("sendto", dest_addr={"sa_family": "AF_INET",
                                          "sin_addr": "10.0.0.6", "sin_port": "9001"}, ts=5),
        tracee_event("execve", pathname="/usr/local/bin/python3.12",
                     argv=["python3", "-u", "/app/targets/mcp-stdio/server.py"], ts=6),
        tracee_event("write", fd=1, count=128, ts=7),  # server stdout -> stdio_tool_call
        tracee_event("security_file_open", pathname="/workspace/out/b.txt",
                     flags="O_WRONLY|O_CREAT|O_TRUNC", ts=8),
        tracee_event("security_file_open", pathname="/var/log/targets/x.log",
                     flags="O_WRONLY|O_APPEND|O_CREAT", ts=9),  # excluded noise
        tracee_event("connect", addr={"sa_family": "AF_INET",
                                          "sin_addr": "127.0.0.11", "sin_port": 53}, ts=9),
    ]
    raw = tmp_path / "tracee.jsonl"
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    stream = me.iter_events(raw.open())
    mapped = [mapper.map_event(e, i) for i, e in enumerate(stream)]
    classes = {r["class"] for r in mapped} - {"unmapped"}
    assert classes == SIX_CLASSES
    # provenance round-trip: every record points at a real raw index
    by_class = {r["class"]: r for r in mapped if r}
    for r in by_class.values():
        assert 0 <= r["provenance"]["raw_index"] < len(events)

def test_net_packet_udp_maps_direct_network(mapper):
    """Tracee network events: node's dgram UDP arrives via net_packet_udp with
    a parsed dst_port (raw sendmsg does not expose the destination)."""
    r = map_one(mapper, tracee_event(
        "net_packet_udp", src="172.20.0.2", dst="172.20.0.4",
        src_port=47987, dst_port=9001,
        proto_udp={"srcPort": 47987, "dstPort": 9001, "length": 17}))
    assert r["class"] == "direct_network" and r["detail"]["transport"] == "udp"
    assert r["detail"]["target_port"] == 9001


def test_net_packet_udp_other_port_unmapped(mapper):
    r = map_one(mapper, tracee_event(
        "net_packet_udp", src="172.20.0.2", dst="8.8.8.8",
        src_port=50000, dst_port=53))
    assert r["class"] == "unmapped"


# --- M6 reconciliation envelope (retval provenance, unmapped detail) ----------

def test_mapped_record_carries_retval_provenance(mapper):
    """Spawn PATH-probe dedupe in M6 reconciliation needs the syscall retval
    (a top-level Tracee field, not an arg)."""
    ok = tracee_event("execve", pathname="/bin/sh", argv=["sh", "-c", "echo hi"])
    ok["retval"] = 0
    assert map_one(mapper, ok)["provenance"]["retval"] == 0
    probe = tracee_event("execve", pathname="/bin/nope", argv=["nope"])
    probe["retval"] = -2
    f = map_one(mapper, probe)
    assert f["provenance"]["retval"] == -2 and f["class"] == "process_spawn"


def test_unmapped_record_keeps_full_envelope(me, tmp_path):
    """M6: unmapped records carry ts/container/pid/process + best-effort
    detail (path/port/flags/argv) so noise allowlists work without the raw
    stream."""
    events = [
        tracee_event("security_file_open", pathname="/workspace/out/a.txt",
                     flags="O_RDONLY", ts=123, pid=5, container="cX"),
        tracee_event("connect", addr={"sa_family": "AF_INET",
                                      "sin_addr": "127.0.0.11", "sin_port": 53},
                     ts=124, pid=5, container="cX"),
        tracee_event("execve", pathname="/bin/probe", argv=["probe", "x"],
                     ts=125, pid=5, container="cX"),
    ]
    events[2]["retval"] = -2
    raw = tmp_path / "tracee.jsonl"
    raw.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    out = tmp_path / "mapped.jsonl"
    import subprocess, sys
    subprocess.run([sys.executable, str(MAPPER_PATH), "--rules", str(RULES_PATH),
                    "--in", str(raw), "--out", str(out)], check=True)
    records = [json.loads(l) for l in out.read_text().splitlines()]
    # events 0/1 stay unmapped and keep the full envelope; event 2 (execve)
    # still maps as process_spawn regardless of retval (classification is
    # unchanged; reconciliation does the probe dedupe)
    assert records[0]["class"] == "unmapped"
    assert records[1]["class"] == "unmapped"
    assert records[2]["class"] == "process_spawn"
    for r in records:
        assert r["container"] == "cX" and r["pid"] == 5 and r["ts"]
    assert records[0]["detail"] == {"path": "/workspace/out/a.txt", "flags": "O_RDONLY"}
    assert records[1]["detail"] == {"port": 53}
    assert records[2]["provenance"]["retval"] == -2
    assert records[2]["detail"]["cmd"] == ["probe", "x"]
