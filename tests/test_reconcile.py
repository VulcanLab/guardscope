"""Reconciliation tests (C7, M6 acceptance).

Builds synthetic mapped-action JSONL streams (v5 record format) for a correct
15-action replay of baseline.yaml (v2: includes the a014 checked-DENY case,
allowed in T0-T5 and denied only under T6's policy) — including every
documented kernel-level
multiplicity (HTTP pooling, stdio handshake write, double file opens, UDP
double capture, pi failed PATH lookups) and the known harness-internal
unrelated events — and
asserts:

  - a correct run passes with per-class counts matching the spec exactly
  - a run with a missing action FAILS
  - a run with a deliberately corrupted mapping FAILS
  - unmapped leftovers inside the measurement window FAIL the run
  - window/container scoping and the unrelated-events list behave as documented

Run from experiments/mediation/:  python3 -m pytest tests/test_reconcile.py -v
"""

import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

INSPECTION_ROOT = Path(__file__).resolve().parent.parent
SPEC_PATH = INSPECTION_ROOT / "trace" / "traces" / "baseline.yaml"
PROFILE_DIR = INSPECTION_ROOT / "runner" / "profiles"
sys.path.insert(0, str(INSPECTION_ROOT))
from framework.contracts import load_collect_recipe  # noqa: E402

RECONCILE_PATH = INSPECTION_ROOT / "runner" / "reconcile.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("reconcile", RECONCILE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rc = _load_module()

SPEC = rc.load_spec(SPEC_PATH)
ACTIONS = SPEC["actions"]
BY_ID = {a["id"]: a for a in ACTIONS}

CONTAINER = "c0ffee"
WIN_START = 1_700_000_000_000_000_000     # epoch ns
WIN_END = WIN_START + 5_000_000_000


# --- fixture builders ----------------------------------------------------------


def rec(cls, event, offset_ns, pid=100, container=CONTAINER, detail=None,
        retval=0, process="node"):
    """A mapped (or unmapped) record in the v5 record format."""
    out = {
        "class": cls, "event": event, "ts": WIN_START + offset_ns,
        "container": container, "pid": pid, "process": process,
        "detail": detail or {},
        "provenance": {"raw_index": offset_ns % 1000, "retval": retval},
    }
    if cls == "unmapped":
        out.pop("rule", None)
    return out


def correct_openclaw_stream():
    """All kernel observations of a correct replay, with documented
    multiplicities + unrelated events (harnesses/openclaw/README.md)."""
    mcp_pid, node_pid = 200, 100
    return [
        # stdio: initialize handshake + 3 tool-call responses = 4 writes
        *[rec("stdio_tool_call", "write", i * 1_000_000, mcp_pid,
              detail={"target": "mcp://stdio", "fd": 1}, process="python3")
          for i in range(4)],
        # http: 3 pooled tool calls share 1 connect (a014 shares the route +
        # connection pool: still 1 connect for the 4 http actions)
        rec("http_tool_call", "connect", 10_000_000, node_pid,
            detail={"target_port": 8080, "transport": "tcp"}),
        # direct network: 1 tcp connect, udp observed twice (egress/loopback)
        rec("direct_network", "connect", 20_000_000, node_pid,
            detail={"target_port": 9000, "transport": "tcp"}),
        rec("direct_network", "net_packet_udp", 21_000_000, node_pid,
            detail={"target_port": 9001, "transport": "udp"}),
        rec("direct_network", "net_packet_udp", 22_000_000, node_pid,
            detail={"target_port": 9001, "transport": "udp"}),
        # spawns: /bin/sh + /bin/echo (plus pi-style failed PATH lookups ->
        # allowlisted as unrelated)
        rec("process_spawn", "execve", 30_000_000, node_pid,
            detail={"target": "/bin/sh", "cmd": ["sh", "-c", "echo hi"]}),
        rec("process_spawn", "execve", 31_000_000, node_pid,
            detail={"target": "/bin/echo", "cmd": ["echo", "spawned"]}),
        # MCP server spawn (expected extra: belongs to the stdio transport)
        rec("process_spawn", "execve", 1_000_000, node_pid,
            detail={"target": "/usr/local/bin/python3.12",
                    "cmd": ["python3", "-u", "/opt/inspection/mcp-fs/server.py"]}),
        # MCP server script open (read-mode -> unmapped infra)
        rec("unmapped", "security_file_open", 2_000_000, mcp_pid,
            detail={"path": "/opt/inspection/mcp-fs/server.py", "flags": "O_RDONLY"},
            process="python3"),
        # a002 read_file opens a.txt read-mode (not a canonical class)
        rec("unmapped", "security_file_open", 40_000_000, mcp_pid,
            detail={"path": "/workspace/out/a.txt", "flags": "O_RDONLY"},
            process="python3"),
        # a003 list_directory opens the directory read-mode
        rec("unmapped", "security_file_open", 41_000_000, mcp_pid,
            detail={"path": "/workspace/out", "flags": "O_RDONLY|O_DIRECTORY"},
            process="python3"),
        # file writes: direct a041/a042 with double opens + MCP server-side
        # open of a.txt (expected extra due_to a001)
        rec("file_write", "security_file_open", 50_000_000, node_pid,
            detail={"target": "/workspace/out/b.txt",
                    "flags": "O_WRONLY|O_CREAT|O_TRUNC"}),
        rec("file_write", "security_file_open", 50_100_000, node_pid,
            detail={"target": "/workspace/out/b.txt",
                    "flags": "O_WRONLY|O_CREAT|O_TRUNC"}),
        rec("file_write", "security_file_open", 51_000_000, node_pid,
            detail={"target": "/workspace/out/c.log",
                    "flags": "O_WRONLY|O_APPEND"}),
        rec("file_write", "security_file_open", 51_100_000, node_pid,
            detail={"target": "/workspace/out/c.log",
                    "flags": "O_WRONLY|O_APPEND"}),
        rec("file_write", "security_file_open", 42_000_000, mcp_pid,
            detail={"target": "/workspace/out/a.txt",
                    "flags": "O_WRONLY|O_CREAT|O_TRUNC"}, process="python3"),
        # credential reads: double opens each
        rec("credential_access", "security_file_open", 60_000_000, node_pid,
            detail={"target": "file:///run/secrets/token", "flags": "O_RDONLY"}),
        rec("credential_access", "security_file_open", 60_100_000, node_pid,
            detail={"target": "file:///run/secrets/token", "flags": "O_RDONLY"}),
        rec("credential_access", "security_file_open", 61_000_000, node_pid,
            detail={"target": "file:///run/secrets/db_password", "flags": "O_RDONLY"}),
        rec("credential_access", "security_file_open", 60_900_000, node_pid,
            detail={"target": "file:///run/secrets/db_password", "flags": "O_RDONLY"}),
        # pi RPC / MCP-request pipe writes (transport traffic, not canonical)
        rec("unmapped", "write", 3_600_000, 100,
            detail={"count": 74}, process="pi"),
        # --- documented unrelated events (allowlisted, not accounted) ---
        rec("unmapped", "security_file_open", 3_000_000, node_pid,
            detail={"path": "/etc/resolv.conf", "flags": "O_RDONLY"}),
        rec("unmapped", "security_file_open", 3_100_000, node_pid,
            detail={"path": "/proc/self/oom_score_adj",
                    "flags": "O_WRONLY"}),
        rec("unmapped", "connect", 3_200_000, node_pid,
            detail={"port": 53}),
        rec("unmapped", "execve", 3_300_000, node_pid,
            detail={"path": "/usr/local/sbin/sh", "argv": ["sh", "-c", "echo hi"]},
            retval=-2),
        rec("unmapped", "execve", 3_400_000, node_pid,
            detail={"path": "/usr/bin/chown", "argv": ["chown", "501:20", "/workspace/replay"]},
            process="chown"),
        rec("unmapped", "execve", 3_400_000, None,
            detail={"path": "/usr/bin/runc", "argv": ["runc", "start"]},
            process="runc"),
        rec("unmapped", "security_file_open", 3_500_000, node_pid,
            detail={"path": "/workspace/replay/replay-log.jsonl",
                    "flags": "O_WRONLY|O_CREAT|O_APPEND"}),
    ]


def correct_pi_stream():
    """Pi variant: failed PATH lookups for the pi shim and the MCP python3
    spawn."""
    stream = correct_openclaw_stream()
    failed_lookups = [
        rec("unmapped", "execve", 900_000_000 + i * 100_000, 100,
            detail={"path": p, "argv": ["pi", "--mode", "rpc"]}, retval=-2,
            process="sh")
        for i, p in enumerate(["/usr/local/sbin/pi", "/usr/local/bin/pi",
                               "/usr/sbin/pi", "/usr/bin/pi"])
    ]
    py_failed_lookups = [
        rec("unmapped", "execve", 901_000_000 + i * 100_000, 100,
            detail={"path": p, "argv": ["python3", "/opt/inspection/mcp-fs/server.py"]},
            retval=-2, process="sh")
        for i, p in enumerate(["/usr/local/sbin/python3", "/usr/local/bin/python3"])
    ]
    return failed_lookups + py_failed_lookups + stream


def replay_result(stream_ok=True, executed=None):
    results = []
    for a in ACTIONS:
        status = "ok" if stream_ok or a["id"] != "a052" else "error"
        results.append({"id": a["id"], "class": a["class"], "op": a["op"],
                        "started_epoch_ns": WIN_START + 1000, "status": status,
                        "detail": None, "error": None})
    n = len(ACTIONS) if executed is None else executed
    return {
        "ok": stream_ok, "executed": n,
        "failed": 0 if stream_ok else 1,
        "window_ns": {"start": 1, "end": 2},
        "window_epoch_ns": {"start": WIN_START, "end": WIN_START + 5_000_000_000},
        "replay_log": "replay-log.jsonl",
        "results": results,
    }


def target_logs():
    """Served-action logs (shared target-logs volume format, M2)."""
    def iso(epoch_ns):
        from datetime import timezone
        return datetime.fromtimestamp(epoch_ns / 1e9, tz=timezone.utc).isoformat()
    t0 = WIN_START + 1_000_000
    return [
        {"ts": iso(t0), "target": "toy-mcp-fs", "event": "tool_call",
         "op": "write_file", "path": "/workspace/out/a.txt"},
        {"ts": iso(t0 + 1_000_000), "target": "toy-mcp-fs", "event": "tool_call",
         "op": "read_file", "path": "/workspace/out/a.txt"},
        {"ts": iso(t0 + 2_000_000), "target": "toy-mcp-fs", "event": "tool_call",
         "op": "list_directory", "path": "/workspace/out"},
        {"ts": iso(t0 + 10_000_000), "target": "http-endpoint", "event": "request",
         "method": "POST", "path": "/hook", "body_text": "tool-call payload"},
        {"ts": iso(t0 + 13_000_000), "target": "http-endpoint", "event": "request",
         "method": "POST", "path": "/hook", "body_text": "policy-deny case"},
        {"ts": iso(t0 + 11_000_000), "target": "http-endpoint", "event": "request",
         "method": "GET", "path": "/health"},
        {"ts": iso(t0 + 12_000_000), "target": "http-endpoint", "event": "request",
         "method": "PUT", "path": "/state"},
        {"ts": iso(t0 + 20_000_000), "target": "net-peer", "event": "received",
         "transport": "tcp", "payload": "direct tcp"},
        {"ts": iso(t0 + 21_000_000), "target": "net-peer", "event": "received",
         "transport": "udp", "payload": "direct udp"},
        # pre-window driver health poll: outside the window, must be ignored
        {"ts": iso(WIN_START - 10_000_000_000), "target": "http-endpoint",
         "event": "request", "method": "GET", "path": "/health"},
    ]


def reconcile(stream, harness="openclaw", replay=None, target_logs=None,
              container_id=None, design="t0", session_shape=None):
    profile = rc.load_profile(PROFILE_DIR / f"{harness}.yaml")
    replay = replay or replay_result()
    return rc.Reconciler(SPEC, profile, replay, stream, target_logs,
                         container_id, design=design,
                         session_shape=session_shape).run()


GROUND_TRUTH = {"stdio_tool_call": 3, "http_tool_call": 4, "direct_network": 2,
                "process_spawn": 2, "file_write": 2, "credential_access": 2}


# --- correct runs ---------------------------------------------------------------


def test_correct_run_passes_openclaw():
    report = reconcile(correct_openclaw_stream(), harness="openclaw",
                       target_logs=target_logs())
    assert report["status"] == "pass", report["checks"]
    assert report["effective_counts"] == GROUND_TRUTH


def test_correct_run_passes_pi():
    report = reconcile(correct_pi_stream(), harness="pi",
                       target_logs=target_logs())
    assert report["status"] == "pass", report["checks"]
    assert report["effective_counts"] == GROUND_TRUTH


def test_correct_run_passes_without_target_logs():
    report = reconcile(correct_openclaw_stream(), harness="openclaw")
    assert report["status"] == "pass", report["checks"]
    assert report["effective_counts"] == GROUND_TRUTH


def test_all_documented_multiplicities_absorbed():
    """HTTP pooling, stdio handshake, double opens, UDP double capture, MCP
    extras: all present in the correct stream yet every R3 check passes."""
    report = reconcile(correct_openclaw_stream(), harness="openclaw")
    r3 = [c for c in report["checks"] if c["id"].startswith("R3-kernel")]
    assert all(c["status"] == "pass" for c in r3)
    assert report["kernel"]["noise_count"] > 0
    assert report["leftovers"] == []


def test_unrelated_events_rules_all_matched_with_reason():
    report = reconcile(correct_openclaw_stream(), harness="openclaw")
    ids = {n["rule"] for n in report["kernel"]["noise"]}
    assert {"failed-command-lookup", "runtime-execs", "oom-score-adj",
            "node-socket-churn", "pipe-writes", "infra-read-opens",
            "infra-paths", "tool-file-reads"} <= ids


# --- missing action / corrupted mapping FAIL ------------------------------------


def test_missing_action_fails():
    stream = [r for r in correct_openclaw_stream()
              if not (r["class"] == "credential_access"
                      and "token" in r["detail"].get("target", ""))]
    report = reconcile(stream, harness="openclaw")
    assert report["status"] == "fail"
    failed = {c["id"] for c in report["checks"] if c["status"] == "fail"}
    assert "R3-kernel-credential_access" in failed
    assert report["effective_counts"]["credential_access"] == 1


def test_corrupted_mapping_fails():
    """Relabeling a credential read as file_write (mapping corruption):
    credential action unsupported AND an unexplained file_write leftover."""
    stream = []
    for r in correct_openclaw_stream():
        if (r["class"] == "credential_access"
                and "token" in r["detail"].get("target", "")):
            r = {**r, "class": "file_write"}
        stream.append(r)
    report = reconcile(stream, harness="openclaw")
    assert report["status"] == "fail"
    failed = {c["id"] for c in report["checks"] if c["status"] == "fail"}
    assert "R3-kernel-credential_access" in failed
    assert "R5-effective-counts" in failed
    assert any(l["disposition"] == "unmatched" and l["detail"]["path"].endswith("token")
               for l in report["leftovers"])


def test_unmapped_leftover_inside_window_fails():
    stream = correct_openclaw_stream() + [
        rec("unmapped", "memprot_alert", 70_000_000, 100),
    ]
    report = reconcile(stream, harness="openclaw")
    assert report["status"] == "fail"
    assert any(l["disposition"] == "unmatched" for l in report["leftovers"])


def test_write_open_falling_to_unmapped_fails():
    """The tool-file-reads rule is READ-mode only: a write-mode open of
    a workspace file that fails to map (corrupted file_write rule) must be a
    leftover, not silently absorbed."""
    stream = correct_openclaw_stream() + [
        rec("unmapped", "security_file_open", 55_000_000, 100,
            detail={"path": "/workspace/out/hidden.txt",
                    "flags": "O_WRONLY|O_CREAT"})]
    report = reconcile(stream, harness="openclaw")
    assert report["status"] == "fail"


# --- replay layer ----------------------------------------------------------------


def test_replay_action_error_fails():
    report = reconcile(correct_openclaw_stream(), harness="openclaw",
                       replay=replay_result(stream_ok=False))
    assert report["status"] == "fail"
    assert any(c["id"] == "R1-replay-layer" and c["status"] == "fail"
               for c in report["checks"])


def test_replay_executed_count_mismatch_fails():
    replay = replay_result()
    replay["executed"] = 13
    replay["results"] = replay["results"][:-1]
    report = reconcile(correct_openclaw_stream(), harness="openclaw", replay=replay)
    assert report["status"] == "fail"


def test_replay_class_drift_fails():
    replay = replay_result()
    replay["results"][0]["class"] = "file_write"
    report = reconcile(correct_openclaw_stream(), harness="openclaw", replay=replay)
    assert report["status"] == "fail"


# --- served layer ----------------------------------------------------------------


def test_served_missing_request_fails():
    logs = [l for l in target_logs()
            if not (l.get("target") == "http-endpoint"
                    and l.get("method") == "PUT")]
    report = reconcile(correct_openclaw_stream(), harness="openclaw",
                       target_logs=logs)
    assert report["status"] == "fail"
    assert any(c["id"] == "R2-served-layer" and c["status"] == "fail"
               for c in report["checks"])


def test_served_logs_outside_window_ignored():
    logs = target_logs() + [
        {"ts": "2020-01-01T00:00:00+00:00", "target": "http-endpoint",
         "event": "request", "method": "DELETE", "path": "/hook"}]
    report = reconcile(correct_openclaw_stream(), harness="openclaw",
                       target_logs=logs)
    assert report["status"] == "pass"


# --- scoping -----------------------------------------------------------------------


def test_out_of_window_events_ignored():
    stream = correct_openclaw_stream() + [
        rec("unmapped", "connect", -10_000_000_000, 100, detail={"port": 443}),
        rec("unmapped", "security_file_open", 900_000_000_000, 100,
            detail={"path": "/etc/passwd", "flags": "O_RDONLY"}),
    ]
    report = reconcile(stream, harness="openclaw")
    assert report["status"] == "pass"
    assert report["scope"]["in_window"] == len(correct_openclaw_stream())


def test_container_scoping_excludes_other_containers():
    stream = correct_openclaw_stream() + [
        rec("unmapped", "connect", 70_000_000, 100, container="other",
            detail={"port": 443}),
    ]
    report = reconcile(stream, harness="openclaw", container_id=CONTAINER)
    assert report["status"] == "pass"
    assert report["scope"]["in_container"] == len(correct_openclaw_stream())


def test_events_without_ts_stay_in_scope():
    extra = rec("unmapped", "memprot_alert", 0, 100)
    extra["ts"] = None
    stream = correct_openclaw_stream() + [extra]
    report = reconcile(stream, harness="openclaw")
    assert report["status"] == "fail"  # ts-less records are conservatively in-scope


# --- effective counts & R5 ---------------------------------------------------------


def test_r5_exact_match_on_pass():
    report = reconcile(correct_pi_stream(), harness="pi", target_logs=target_logs())
    r5 = next(c for c in report["checks"] if c["id"] == "R5-effective-counts")
    assert r5["status"] == "pass"
    assert report["effective_counts"] == report["ground_truth_counts"] == GROUND_TRUTH


def test_r5_fails_when_class_partially_unsupported():
    stream = [r for r in correct_pi_stream()
              if not (r["class"] == "process_spawn"
                      and r["detail"].get("target") == "/bin/echo")]
    report = reconcile(stream, harness="pi")
    assert report["status"] == "fail"
    assert report["effective_counts"]["process_spawn"] == 1


# --- profile sanity ------------------------------------------------------------------


def test_profiles_validate():
    for name in ("openclaw", "pi"):
        profile = rc.load_profile(PROFILE_DIR / f"{name}.yaml")
        assert profile["harness"] == name
        assert profile["multiplicity"]["stdio_handshake_extra_writes"] == 1


def test_unknown_where_key_rejected():
    import pytest
    with pytest.raises(ValueError):
        rc.match_where(rc.flatten({"class": "unmapped"}),
                       {"bogus_key": 1})

# --- T2: forced egress (design-aware prevented classes) -----------------------------


def t2_stream():
    """T2 kernel observations: the direct-network ATTEMPTS replace the T0/T1
    completions. TCP connect fires (mapped via port 9000, rejected outcome);
    net_packet_udp does NOT fire when netfilter rejects at the output hook —
    the raw sendmsg syscalls surface as unmapped node-socket-churn records
    (allowlisted as unrelated)."""
    s = [r for r in correct_openclaw_stream()
         if r["class"] != "direct_network"]
    # prevented tcp_connect a021: connect syscall fires, refused (retval -111)
    s.append(rec("direct_network", "connect", 20_000_000, 100,
                 detail={"target_port": 9000, "transport": "tcp"}, retval=-111))
    # prevented udp_send a022: raw sendmsg attempts, unmapped (no port detail)
    s.append(rec("unmapped", "sendmsg", 21_000_000, 100, detail={"count": 64}))
    s.append(rec("unmapped", "sendmsg", 21_500_000, 100, detail={"count": 64}))
    return s


def t2_target_logs():
    """T2 served logs: stdio + http served as usual; net-peer serves NOTHING."""
    return [r for r in target_logs() if r.get("target") != "net-peer"]


def t2_replay(tcp_status="error", tcp_error="connect ECONNREFUSED 10.0.0.5:9000"):
    """T2 replay results: a021 refused by the egress policy; a022 sends 'ok'
    (unconnected dgram sockets do not surface the icmp reject)."""
    base = replay_result()
    for r in base["results"]:
        if r["id"] == "a021":
            r["status"], r["error"] = tcp_status, tcp_error
    base["ok"] = tcp_status == "ok"
    base["failed"] = 0 if tcp_status == "ok" else 1
    return base


def test_t2_prevented_run_passes():
    report = reconcile(t2_stream(), replay=t2_replay(),
                       target_logs=t2_target_logs(), design="t2")
    assert report["status"] == "pass", report["checks"]
    # prevented: nothing took effect on the direct-network class
    assert report["effective_counts"]["direct_network"] == 0
    # the other five classes are unchanged from T0/T1
    expect = dict(GROUND_TRUTH)
    expect["direct_network"] = 0
    assert report["effective_counts"] == expect


def test_t2_prevented_r5_detail():
    report = reconcile(t2_stream(), replay=t2_replay(),
                       target_logs=t2_target_logs(), design="t2")
    r5 = [c for c in report["checks"] if c["id"] == "R5-effective-counts"][0]
    assert r5["status"] == "pass"
    assert "prevented" in r5["detail"]


def test_t2_tcp_took_effect_fails():
    """A bypass: the tcp connect succeeds and net-peer serves it — the egress
    policy is NOT in force; R1/R2/R3/R5 must all fail."""
    stream = t2_stream()
    # served: the target received the direct tcp payload
    logs = t2_target_logs() + [
        {"ts": datetime.fromtimestamp((WIN_START + 20_000_000) / 1e9,
                                      tz=timezone.utc).isoformat(),
         "target": "net-peer", "event": "received", "transport": "tcp"}]
    report = reconcile(stream, replay=t2_replay(tcp_status="ok"),
                       target_logs=logs, design="t2")
    assert report["status"] == "fail"
    failed = {c["id"] for c in report["checks"] if c["status"] == "fail"}
    assert {"R1-replay-layer", "R2-served-layer",
            "R3-kernel-direct_network", "R5-effective-counts"} <= failed


def test_t2_drop_style_timeout_fails():
    """A DROP-style egress policy (connect hangs, no refusal errno) is slow
    and non-deterministic; the replay layer must reject it."""
    report = reconcile(t2_stream(), replay=t2_replay(tcp_error="tcp_connect: timed out"),
                       target_logs=t2_target_logs(), design="t2")
    assert report["status"] == "fail"
    assert any(c["id"] == "R1-replay-layer" and c["status"] == "fail"
               for c in report["checks"])


def test_t2_zero_design_is_unchanged():
    """t0/t1 prevent nothing: the design-aware path must be a no-op there."""
    report = reconcile(correct_openclaw_stream(), harness="openclaw",
                       target_logs=target_logs(), design="t1")
    assert report["status"] == "pass", report["checks"]
    assert report["effective_counts"] == GROUND_TRUTH


# --- T3: gateway as sole enforcement point (all tools behind it) -------------------


def t3_stream():
    """T3 kernel observations: NO stdio writes (no MCP server child in the
    harness); the tool-call kernel evidence is pooled connects to the
    gateway (mapped as http_tool_call by port 8090 — the kernel cannot
    attribute them to the stdio vs http class); direct network prevented as
    in T2; spawn/file/credential unchanged."""
    s = [r for r in correct_openclaw_stream()
         if r["class"] not in ("stdio_tool_call", "http_tool_call",
                               "direct_network")]
    # pooled harness->gateway connects: 2 tool-call connects shared by 7 calls
    # (3 fs + 4 http)
    s += [
        rec("http_tool_call", "connect", 8_000_000, 100,
            detail={"target_port": 8090, "transport": "tcp"}),
        rec("http_tool_call", "connect", 8_500_000, 100,
            detail={"target_port": 8090, "transport": "tcp"}),
    ]
    # prevented direct-network attempts (as in T2)
    s.append(rec("direct_network", "connect", 20_000_000, 100,
                 detail={"target_port": 9000, "transport": "tcp"}, retval=-111))
    s.append(rec("unmapped", "sendmsg", 21_000_000, 100, detail={"count": 64}))
    s.append(rec("unmapped", "sendmsg", 21_500_000, 100, detail={"count": 64}))
    return s


def t3_target_logs():
    """T3 served logs: fs tools served at toy-mcp-fs (the proxied upstream),
    http served as usual, net-peer serves NOTHING."""
    return [r for r in target_logs() if r.get("target") != "net-peer"]


def test_t3_run_passes():
    report = reconcile(t3_stream(), replay=t2_replay(),
                       target_logs=t3_target_logs(), design="t3")
    assert report["status"] == "pass", report["checks"]
    # direct connections are prevented (as in T2); the tool calls now cross
    # the gateway and the process-level classes stay bypassed
    expect = dict(GROUND_TRUTH)
    expect["direct_network"] = 0
    assert report["effective_counts"] == expect
    # the shared pooled expected count range is the evidence for both tool
    # classes
    stdio = [c for c in report["checks"] if c["id"] == "R3-kernel-stdio_tool_call"][0]
    assert "2 kernel observations" in stdio["detail"]


def test_t3_zero_gateway_connects_fail():
    """If no tool call crossed the gateway, T3's evidence chain is broken."""
    s = [r for r in t3_stream() if r["detail"].get("target_port") != 8090]
    report = reconcile(s, replay=t2_replay(),
                       target_logs=t3_target_logs(), design="t3")
    assert report["status"] == "fail"
    failed = {c["id"] for c in report["checks"] if c["status"] == "fail"}
    assert {"R3-kernel-stdio_tool_call", "R3-kernel-http_tool_call"} <= failed


def test_t3_pooled_connects_above_n_fail():
    """More pooled connects than the documented expected count range (n tool calls +
    n http downstream: a no-pooling client contributes one connect per
    call, the gateway one downstream connect per http pair) fails loud."""
    s = t3_stream()
    s.append(rec("http_tool_call", "connect", 9_000_000, 100,
                 detail={"target_port": 8090, "transport": "tcp"}))
    s.append(rec("http_tool_call", "connect", 9_100_000, 100,
                 detail={"target_port": 8090, "transport": "tcp"}))
    s.append(rec("http_tool_call", "connect", 9_200_000, 100,
                 detail={"target_port": 8090, "transport": "tcp"}))
    s.append(rec("http_tool_call", "connect", 9_300_000, 100,
                 detail={"target_port": 8090, "transport": "tcp"}))
    s.append(rec("http_tool_call", "connect", 9_400_000, 100,
                 detail={"target_port": 8090, "transport": "tcp"}))
    s.append(rec("http_tool_call", "connect", 9_500_000, 100,
                 detail={"target_port": 8090, "transport": "tcp"}))
    for i in range(9_600_000, 9_600_000 + 7 * 100_000, 100_000):
        s.append(rec("http_tool_call", "connect", i, 100,
                     detail={"target_port": 8090, "transport": "tcp"}))
    report = reconcile(s, replay=t2_replay(),
                       target_logs=t3_target_logs(), design="t3")
    assert report["status"] == "fail"
    assert any(c["id"].startswith("R3-kernel-http_tool") and c["status"] == "fail"
               for c in report["checks"])


# --- T4: harness-native enforcement (permissions; process actions bypass) ---------


def t4_stream():
    """T4 kernel observations: like T0 — the process-level classes execute in
    the harness; the fs tool calls run through pi's MCP client (server child
    writes: the 3 tool responses, plus 0..2 config-handshake writes depending
    on when the window opens); the http tool calls are connects to the
    endpoint from the http-stdio child (pooled count range as in T0)."""
    s = correct_openclaw_stream()
    # 1 config-handshake write in-window (worst case; the range allows 0..2)
    s.append(rec("stdio_tool_call", "write", 500_000, 200,
                 detail={"target": "mcp://stdio", "fd": 1}, process="python3"))
    return s


def test_t4_run_passes():
    report = reconcile(t4_stream(), harness="pi",
                       target_logs=target_logs(), design="t4")
    assert report["status"] == "pass", report["checks"]
    # nothing prevented; everything takes effect (no egress in T4 v1)
    assert report["effective_counts"] == GROUND_TRUTH
    stdio = [c for c in report["checks"] if c["id"] == "R3-kernel-stdio_tool_call"][0]
    assert stdio["status"] == "pass"


def test_t4_stdio_range_bounds():
    """T0's exact count (n + 1) must still pass under T4's wider range, and
    too many writes must fail."""
    # 5 writes: 3 tool responses + 2 handshake = inside [3, 5]
    s = [r for r in t4_stream() if r["class"] != "stdio_tool_call"]
    s += [rec("stdio_tool_call", "write", i * 1_000_000, 200,
              detail={"target": "mcp://stdio", "fd": 1}, process="python3")
          for i in range(5)]
    s.append(rec("process_spawn", "execve", 400_000, 200,
                 detail={"target": "/usr/local/bin/python3.12",
                         "cmd": ["python3", "-u", "/opt/inspection/mcp-fs/server.py"]}))
    report = reconcile(s, harness="pi", target_logs=target_logs(), design="t4")
    assert report["status"] == "pass", report["checks"]
    # 6 writes: outside [3, 5]
    s.append(rec("stdio_tool_call", "write", 99_000_000, 200,
                 detail={"target": "mcp://stdio", "fd": 1}, process="python3"))
    report = reconcile(s, harness="pi", target_logs=target_logs(), design="t4")
    assert report["status"] == "fail"
    assert any(c["id"] == "R3-kernel-stdio_tool_call" and c["status"] == "fail"
               for c in report["checks"])


def test_t4_t0_equivalence():
    """The T0 stream under t4 must reconcile identically (prevented = none)."""
    report = reconcile(correct_pi_stream(), harness="pi",
                       target_logs=target_logs(), design="t4")
    assert report["status"] == "pass", report["checks"]
    assert report["effective_counts"] == GROUND_TRUTH


def test_t5_run_passes():
    """T5: same kernel evidence and outcomes as T4 (the gateway evaluation is
    recorded in the gateway-side record, not the kernel stream)."""
    report = reconcile(t4_stream(), harness="pi",
                       target_logs=target_logs(), design="t5")
    assert report["status"] == "pass", report["checks"]
    assert report["effective_counts"] == GROUND_TRUTH


def test_t6_run_passes():
    """T6: same placement as T4 — same kernel evidence and outcomes."""
    report = reconcile(t4_stream(), harness="pi",
                       target_logs=target_logs(), design="t6")
    assert report["status"] == "pass", report["checks"]
    assert report["effective_counts"] == GROUND_TRUTH


# --- checked-DENY (v2 trace: the a014 argument-level deny case) ------------------


def t6_replay():
    """T6 replay: a014 DENIED by the in-process policy (a valid terminal
    state); everything else ok."""
    base = replay_result()
    for r in base["results"]:
        if r["id"] == "a014":
            r["status"] = "denied"
    base["ok"] = True
    base["failed"] = 0
    return base


def t6_target_logs():
    """T6 served logs: the DENIED a014 must NOT appear (no request with its
    body reached the endpoint); the allowed a011 POST is served as usual."""
    return [l for l in target_logs()
            if l.get("body_text") != "policy-deny case"]


def test_t6_denied_run_passes():
    report = reconcile(t4_stream(), harness="pi", replay=t6_replay(),
                       target_logs=t6_target_logs(), design="t6")
    assert report["status"] == "pass", report["checks"]
    # the denied instance does not count as effective
    expect = dict(GROUND_TRUTH)
    expect["http_tool_call"] = 3
    assert report["effective_counts"] == expect


def test_t6_denied_but_served_fails():
    """A denial that did NOT hold: the endpoint served the denied body —
    enforcement failed; R2 must fail."""
    logs = t6_target_logs() + [
        {"ts": datetime.fromtimestamp((WIN_START + 14_000_000) / 1e9,
                                      tz=timezone.utc).isoformat(),
         "target": "http-endpoint", "event": "request", "method": "POST",
         "path": "/hook", "body_text": "policy-deny case"}]
    report = reconcile(t4_stream(), harness="pi", replay=t6_replay(),
                       target_logs=logs, design="t6")
    assert report["status"] == "fail"
    assert any(c["id"] == "R2-served-layer" and c["status"] == "fail"
               for c in report["checks"])


def test_t6_denied_prevented_class_fails():
    """A prevented class can never be denied (the enforcement point never
    sees it): a denied entry on a prevented class is a topology violation."""
    replay = t6_replay()
    for r in replay["results"]:
        if r["id"] == "a021":
            r["status"] = "denied"
    report = reconcile(t2_stream(), harness="pi", replay=replay,
                       target_logs=t2_target_logs(), design="t2")
    assert report["status"] == "fail"
    assert any(c["id"] == "R1-replay-layer" and c["status"] == "fail"
               for c in report["checks"])


# --- T7: the kernel kill rule's denial is a policy denial (checked-denied) ----


def _t7_replay(status_by_id):
    replay = replay_result()
    for r in replay["results"]:
        status = status_by_id.get(r["id"])
        if status:
            r["status"] = status
            r["error"] = "child killed (SIGKILL)" if status == "error" else None
    return replay


def test_t7_kernel_denied_instance_r1_passes():
    # a032 (exec /bin/echo) is killed by the fixture policy at the kernel:
    # the replay sees the SIGKILLed child as an execution error, tolerated
    # BY ID (T7_KERNEL_DENIED_INSTANCES), never by class membership
    rec = rc.Reconciler(SPEC, rc.load_profile(PROFILE_DIR / "pi.yaml"),
                        _t7_replay({"a032": "error"}), [], [], None,
                        design="t7")
    r1 = rec.reconcile_replay()
    assert not r1["problems"]


def test_t7_allowed_twin_must_still_succeed():
    # a031 (exec /bin/sh) shares the class with the denied a032: its failure
    # is NOT tolerated (the tolerance is keyed on the deny instance id)
    rec = rc.Reconciler(SPEC, rc.load_profile(PROFILE_DIR / "pi.yaml"),
                        _t7_replay({"a031": "error"}), [], [], None,
                        design="t7")
    r1 = rec.reconcile_replay()
    assert any("a031" in p for p in r1["problems"])


def test_t7_prevented_classes_empty():
    # the kernel position mediates through a POLICY: its denials are
    # checked-denied, not prevented; prevented stays reserved for the
    # silent outside-the-policy mechanisms (t2/t3 egress jail)
    assert rc.PREVENTED_CLASSES["t7"] == set()
    assert rc.T7_KERNEL_DENIED_INSTANCES == frozenset({"a032"})


# --- T1 agentgateway: the calibrated streamable-session http shape -------------

def _t1_session_stream(harness, *, extra_workload=0, unattributed=False,
                       stray_ready=False, stray_replay=False):
    """The t1 kernel shape under the agentgateway binding (the
    http_startup_calibration pin, 2026-11-10):

    - the replay session: initialize + notifications/initialized (2 connects)
      then one connect per tools/call (n=4). The mock harness starts the
      session INSIDE the window (lazy, on the first gateway-routed action);
      the pi harness starts it pre-window (adapter discovery) — the pin's
      session_connect_allowance + connects_per_startup /
      max_startups_in_window keys budget the two shapes' sockets, and the
      pooled replay envelope [max(http_connects_min, allowance_lo),
      n + allowance_hi] covers both.
    - the runner's pre-window readiness probe: its own one-shot session
      (initialize + notifications + the denied tools/call = 3 connects),
      before the window, within the window tolerance (in-scope but startup,
      never workload evidence).
    """
    s = [r for r in correct_openclaw_stream()
         if r["class"] != "http_tool_call"]
    if harness == "mock-harness":
        # the openclaw fixture's MCP server script open carries the
        # openclaw-path (/opt/inspection/...); the mock harness runs its
        # server child from the mounted repo (/repo/targets/..., covered by
        # the mock profile's /repo allowlist prefix)
        for r in s:
            if r.get("detail", {}).get("path") == "/opt/inspection/mcp-fs/server.py":
                r["detail"]["path"] = "/repo/targets/mcp-stdio/server.py"

    def execve(offset, pid, cmd, target):
        return rec("process_spawn", "execve", offset, pid,
                   detail={"target": target, "cmd": cmd}, process="runc:[2:INIT]")

    def gw_connect(offset, pid, process="python3"):
        return rec("http_tool_call", "connect", offset, pid,
                   detail={"target_port": 8090, "transport": "tcp"},
                   process=process)

    if harness == "mock-harness":
        replay_argv = ["python3", "-m", "mock_harness.driver"]
        replay_exec, workload_at = -2_000_000_000, 10_000_000
        # in-window: the session handshake (2) + the 4 per-action connects
        s += [execve(replay_exec, 150, replay_argv, "/usr/bin/python3")]
        s += [gw_connect(workload_at, 150),
              gw_connect(workload_at + 100_000, 150)]
        for i in range(4):
            s.append(gw_connect(workload_at + 1_000_000 + i * 500_000, 150))
        for _ in range(extra_workload):
            s.append(gw_connect(workload_at + 5_000_000, 150))
    else:  # pi: node-backed CLI (the pi RPC process's latest exec argv as
    # Tracee reports it: the "pi" shim execs node /usr/local/bin/pi)
        replay_argv = ["node", "/usr/local/bin/pi", "--mode", "rpc"]
        replay_exec = -2_000_000_000
        # pre-window discovery session (2 sockets, within the tolerance)
        s += [execve(replay_exec, 170, replay_argv, "/usr/bin/node")]
        s += [gw_connect(-500_000_000, 170, process="pi"),
              gw_connect(-450_000_000, 170, process="pi")]
        for i in range(4):  # in-window workload connects (a no-pooling run;
            # pi's undici pools them onto the discovery sockets instead)
            s.append(gw_connect(10_000_000 + i * 500_000, 170, process="pi"))
        for _ in range(extra_workload):
            s.append(gw_connect(10_000_000 + 5_000_000, 170, process="pi"))

    readiness_argv = (["python3", "-m", "mock_harness.gateway_probe"]
                      if harness == "mock-harness"
                      else ["node", "/opt/inspection/adapter/readiness-probe.mjs"])
    s.append(execve(-1_500_000_000, 160, readiness_argv,
                    readiness_argv[0]))
    for i in range(3):  # initialize + notifications + the denied tools/call
        s.append(gw_connect(-600_000_000 + i * 50_000_000, 160))

    if unattributed:
        s.append(gw_connect(2_000_000, 999, process="curl"))
    if stray_ready:
        # a SECOND readiness startup: over the pin's at-most-one budget
        s.append(execve(-1_400_000_000, 161, readiness_argv,
                        readiness_argv[0]))
        s.append(gw_connect(-300_000_000, 161))
        s.append(gw_connect(-250_000_000, 161))
        s.append(gw_connect(-200_000_000, 161))
    if stray_replay:
        # a SECOND process whose argv carries the pinned replay prefix: the
        # prefix match identifies the argv SHAPE, and the pid pin must keep
        # its connects out of the run's single replay envelope (the count
        # stays inside the envelope so ONLY the pid pin catches it)
        s.append(execve(-1_800_000_000, 171, replay_argv, replay_argv[0]))
        s.append(gw_connect(10_000_000, 171, process="pi"))
    return s


def _t1_reconcile(stream, harness):
    # the agentgateway binding's declared session shape (plugins/
    # agentgateway/collect.yaml `session_shape`, threaded by the runner):
    # what the pin gates on — without it the pin never applies
    shape = load_collect_recipe("agentgateway", "t1")["session_shape"]
    return reconcile(stream, harness=harness, target_logs=target_logs(),
                     container_id=CONTAINER, design="t1",
                     session_shape=shape)


def test_t1_mock_calibrated_session_shape_passes():
    report = _t1_reconcile(_t1_session_stream("mock-harness"),
                           harness="mock-harness")
    assert report["status"] == "pass", report["checks"]
    http = [c for c in report["checks"]
            if c["id"] == "R3-kernel-http_tool_call"][0]
    assert http["status"] == "pass"


def test_t1_pi_calibrated_session_shape_passes():
    report = _t1_reconcile(_t1_session_stream("pi"), harness="pi")
    assert report["status"] == "pass", report["checks"]
    http = [c for c in report["checks"]
            if c["id"] == "R3-kernel-http_tool_call"][0]
    assert http["status"] == "pass"


def test_t1_calibrated_unattributed_connect_fails():
    for harness in ("mock-harness", "pi"):
        report = _t1_reconcile(
            _t1_session_stream(harness, unattributed=True), harness=harness)
        http = [c for c in report["checks"]
                if c["id"] == "R3-kernel-http_tool_call"][0]
        assert http["status"] == "fail", (harness, http)
        assert "unattributed HTTP connect" in http["detail"]


def test_t1_mock_calibrated_workload_range_enforced():
    # 3 extra in-window replay connects: 9 sockets > [2, 6] (the session
    # socket floor [2, 2] + 4 tool calls + the allowance ceiling)
    report = _t1_reconcile(
        _t1_session_stream("mock-harness", extra_workload=3),
        harness="mock-harness")
    http = [c for c in report["checks"]
            if c["id"] == "R3-kernel-http_tool_call"][0]
    assert http["status"] == "fail"
    assert "replay-session connects outside [2, 6]" in http["detail"]


def test_t1_pi_pooled_session_shape_passes():
    # pi's client POOLS: the pre-window discovery sockets are REUSED by the
    # in-window tools/calls — the in-window connect count can be ZERO; the
    # envelope is over ALL of the session's sockets (observed live
    # 2026-11-10: 2 sockets for the whole session)
    s = _t1_session_stream("pi")
    s = [r for r in s
         if not (r["class"] == "http_tool_call"
                 and r["pid"] == 170
                 and r["detail"].get("target_port") == 8090
                 and r["ts"] >= WIN_START)]   # drop the in-window connects
    # keep exactly the 2 pooled pre-window discovery sockets
    pooled = [r for r in s
             if r["class"] == "http_tool_call" and r["pid"] == 170]
    assert len(pooled) == 2
    report = _t1_reconcile(s, harness="pi")
    assert report["status"] == "pass", report["checks"]


def test_t1_calibrated_second_readiness_startup_fails():
    for harness in ("mock-harness", "pi"):
        report = _t1_reconcile(
            _t1_session_stream(harness, stray_ready=True), harness=harness)
        http = [c for c in report["checks"]
                if c["id"] == "R3-kernel-http_tool_call"][0]
        assert http["status"] == "fail", (harness, http)
        assert "readiness" in http["detail"]


def test_t1_calibration_not_applied_off_design():
    # the pin is design-scoped even when the binding declares the shape:
    # under t0 (no streamable gateway) connects are judged by the plain
    # pooled count alone — no exec attribution, so a provenance-less
    # connect stream passes there (the same stream under t1 with the
    # declared shape fails the calibration's attribution requirement)
    s = [r for r in correct_openclaw_stream()
         if r["class"] != "http_tool_call"]
    s += [rec("http_tool_call", "connect", 10_000_000 + i * 500_000, 100,
              detail={"target_port": 8090, "transport": "tcp"})
          for i in range(4)]
    shape = load_collect_recipe("agentgateway", "t1")["session_shape"]
    report = reconcile(s, harness="pi", target_logs=target_logs(),
                       container_id=CONTAINER, design="t0",
                       session_shape=shape)
    assert report["status"] == "pass", report["checks"]
    report1 = reconcile(s, harness="pi", target_logs=target_logs(),
                        container_id=CONTAINER, design="t1",
                        session_shape=shape)
    http = [c for c in report1["checks"]
            if c["id"] == "R3-kernel-http_tool_call"][0]
    assert http["status"] == "fail"
    assert "unattributed HTTP connect" in http["detail"]


def test_t1_base_profile_direct_http_shape_passes():
    """The checker's repro, pinned permanently: a t1 run whose http
    evidence is the DIRECT shape — the raw pooled connect to the
    endpoint :8080 (the pre-session baseline: the v0 AGT t1 campaigns'
    shape, mocklive-20261029 / x86-20261031) — reconciles on the BASE
    pi and mock-harness profiles exactly as at HEAD. The
    http_startup_calibration pins are gated on the BINDING's declared
    session shape; a t1 run with no shape declaration (no binding, or a
    binding like the v0 gateway whose client speaks one stateless POST
    per call) never routes through them."""
    mock_stream = [dict(r) for r in correct_openclaw_stream()]
    # the mock fixture runs its stdio server child from the mounted repo
    # (the /repo allowlist prefix), not the openclaw harness's baked path
    for r in mock_stream:
        if r.get("detail", {}).get("path") == "/opt/inspection/mcp-fs/server.py":
            r["detail"]["path"] = "/repo/targets/mcp-stdio/server.py"
    for harness, stream in (("pi", correct_pi_stream()),
                            ("mock-harness", mock_stream)):
        report = reconcile(stream, harness=harness, target_logs=target_logs(),
                           container_id=CONTAINER, design="t1")
        assert report["status"] == "pass", (harness, report["checks"])
        http = [c for c in report["checks"]
                if c["id"] == "R3-kernel-http_tool_call"][0]
        assert http["status"] == "pass", (harness, http)


def test_t1_calibration_never_applies_without_the_binding_declaration():
    # the design gate alone is not the scope: the SAME t1 session-shaped
    # stream (provenance-less variant) falls back to the plain pooled
    # range when no session shape is declared — a binding-less t1 run
    # keeps its pre-calibration semantics, and the session-shaped stream
    # fails the PLAIN envelope loudly instead of being silently absorbed
    s = [r for r in correct_openclaw_stream()
         if r["class"] != "http_tool_call"]
    s += [rec("http_tool_call", "connect", 10_000_000 + i * 500_000, 100,
              detail={"target_port": 8090, "transport": "tcp"})
          for i in range(6)]
    report = reconcile(s, harness="pi", target_logs=target_logs(),
                       container_id=CONTAINER, design="t1")
    http = [c for c in report["checks"]
            if c["id"] == "R3-kernel-http_tool_call"][0]
    assert http["status"] == "fail"
    assert "pooled connects outside" in http["detail"]
    assert "unattributed" not in http["detail"]


def test_t1_calibrated_second_replay_pid_fails():
    # prefix argv matching identifies the argv SHAPE, not the process: a
    # SECOND process whose argv carries the pinned replay prefix must not
    # be absorbed into the run's single replay envelope. The pooled pi
    # shape keeps the stray process's connect INSIDE the envelope, so only
    # the pid pin catches it
    s = _t1_session_stream("pi", stray_replay=True)
    s = [r for r in s
         if not (r["class"] == "http_tool_call" and r["pid"] == 170
                 and r["ts"] >= WIN_START)]   # the pooled shape: 0 in-window
    report = _t1_reconcile(s, harness="pi")
    http = [c for c in report["checks"]
            if c["id"] == "R3-kernel-http_tool_call"][0]
    assert http["status"] == "fail", http
    assert "replay gateway client pids" in http["detail"]


def test_t1_calibrated_ledger_records_the_replay_pids():
    # the calibration ledger records the replay pid set it attributed
    # (finding 2: the pid set is the evidence the prefix match is pinned
    # to ONE process, not an argv-shaped envelope)
    report = _t1_reconcile(_t1_session_stream("mock-harness"),
                           harness="mock-harness")
    assert report["status"] == "pass", report["checks"]
    calib = (report["kernel"]["per_class"]["http_tool_call"]
             ["calibration"])
    # 150 = the mock driver's single replay process
    assert calib["observed"]["replay_pids"] == [150]
    ledger_rows = calib["records"]
    assert all("pid" in row for row in ledger_rows)
    assert {row["pid"] for row in ledger_rows
            if row["role"] == "replay"} == {150}
