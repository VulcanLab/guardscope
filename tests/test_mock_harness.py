"""Mock harness tests (path-originator fixture v1).

Covers the v1 acceptance surface: the pinned path manifest (schema + hash),
the plan schema, the driver's per-action records (ids/classes in trace
order), originator determinism (identical digests across runs, timing/pid
fields excluded), the escape-class originators' attempted syscalls (via a
substituted syscalls layer — NO real network or child processes in unit
tests), real-fs behavior of the file/credential originators, and the
policy-blindness guard (no inspection-layer imports, no classification
logic, no self-reported outcomes).

Run from code/:  python3 -m pytest tests/test_mock_harness.py -v
"""

import ast
import json
import re
import subprocess
import sys
from collections import deque
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from mock_harness import driver as drv  # noqa: E402
from mock_harness import originators as org  # noqa: E402
from mock_harness import syscalls as sc  # noqa: E402
from mock_harness import trace_spec as tspec  # noqa: E402

BASELINE = ROOT / "trace" / "traces" / "baseline.yaml"
MANIFEST_PATH = ROOT / "mock_harness" / "manifest.yaml"
MANIFEST_SCHEMA = ROOT / "mock_harness" / "manifest.schema.json"
PLAN_SCHEMA = ROOT / "mock_harness" / "plan-schema.json"
RECORD_SCHEMA = ROOT / "mock_harness" / "record.schema.json"
HASH_TOOL = ROOT / "trace" / "hash_spec.py"

SPEC_IDS = [f"a{n:03d}" for n in (1, 2, 3, 11, 12, 13, 14, 21, 22, 31, 32, 41, 42, 51, 52)]
ESCAPE_NAMES = {
    "direct-origin-operations", "unwatched-channels", "daemon-submissions",
    "outliving-processes", "dispatch-free-output-consumption",
}


# --------------------------------------------------------------------------- fakes

class FakeSocket:
    def __init__(self, kind):
        self.kind = kind
        self.connected = None
        self.closed = False


class FakeSyscalls:
    """Drop-in replacement for mock_harness.syscalls: records every attempted
    effect, never touches the OS (no network, no children, no files)."""

    def __init__(self):
        self.calls = []
        self.rpc_lines = deque()    # MCP responses auto-queued from request frames
        self.seeded_lines = deque() # explicit read_line lines (e.g. daemon pid report)
        self.next_pid = 4242
        self.next_fd = 10

    def tcp_socket(self):
        self.calls.append(("tcp_socket",))
        return FakeSocket("tcp")

    def udp_socket(self):
        self.calls.append(("udp_socket",))
        return FakeSocket("udp")

    def connect(self, sock, host, port):
        self.calls.append(("connect", sock.kind, host, int(port)))
        sock.connected = (host, int(port))

    def sendall(self, sock, data):
        self.calls.append(("sendall", sock.kind, bytes(data)))

    def recv(self, sock):
        self.calls.append(("recv", sock.kind))
        return b"ack\n"

    def sendto(self, sock, data, host, port):
        self.calls.append(("sendto", bytes(data), host, int(port)))

    def close_socket(self, sock):
        self.calls.append(("close_socket", sock.kind))
        sock.closed = True

    def http_request(self, method, url, body=None, headers=None):
        self.calls.append(("http_request", method, url, body,
                           dict(headers) if headers else None))
        if body and '"tools/call"' in body:
            frame = json.loads(body)
            result = {"jsonrpc": "2.0", "id": frame["id"],
                      "result": {"content": [{"type": "text", "text": "ok"}]}}
            return 200, json.dumps(result).encode()
        return 200, b'{"accepted": true}'

    def pipe(self):
        r, w = self.next_fd, self.next_fd + 1
        self.next_fd += 2
        self.calls.append(("pipe", r, w))
        return r, w

    def fork(self):
        self.next_pid += 1
        pid = self.next_pid
        self.calls.append(("fork", pid))
        return pid  # never 0: the fake simulates the parent side only

    def setsid(self):
        self.calls.append(("setsid",))

    def execv(self, path, argv):
        self.calls.append(("execv", path, tuple(argv)))
        return None  # real execv never returns; the child exits 127 after

    def exit_child(self, code):
        self.calls.append(("exit_child", code))
        raise SystemExit(code)

    def dup2(self, old_fd, new_fd):
        self.calls.append(("dup2", old_fd, new_fd))

    def close_fd(self, fd):
        self.calls.append(("close_fd", fd))

    def write_fd(self, fd, data):
        data = bytes(data)
        self.calls.append(("write_fd", fd, data))
        try:
            frame = json.loads(data.decode())
        except (ValueError, UnicodeDecodeError):
            return len(data)
        if frame.get("method") == "initialize":
            self.rpc_lines.append(json.dumps({
                "jsonrpc": "2.0", "id": frame["id"],
                "result": {"protocolVersion": "2025-06-18", "capabilities": {},
                           "serverInfo": {"name": "toy-mcp-fs", "version": "0.1.0"}},
            }))
        elif frame.get("method") == "tools/call":
            self.rpc_lines.append(json.dumps({
                "jsonrpc": "2.0", "id": frame["id"],
                "result": {"content": [{"type": "text", "text": "ok"}]},
            }))
        return len(data)

    def read_line(self, fd):
        self.calls.append(("read_line", fd))
        if self.rpc_lines:
            return self.rpc_lines.popleft().encode()
        if self.seeded_lines:
            return self.seeded_lines.popleft().encode()
        return None

    def read_all(self, fd):
        self.calls.append(("read_all", fd))
        return b"hi\n"

    def open_devnull_rw(self):
        self.calls.append(("open_devnull_rw",))
        return 99

    def waitpid(self, pid):
        self.calls.append(("waitpid", pid))
        return pid, 0

    def exit_code(self, status):
        return 0

    def child_exit_state(self, pid):
        self.calls.append(("child_exit_state", pid))
        return ("exited", 0)

    def alive(self, pid):
        self.calls.append(("alive", pid))
        return False

    def mkdir_p(self, path):
        self.calls.append(("mkdir_p", path))

    def write_file(self, path, data, append=False):
        self.calls.append(("write_file", path, bytes(data), append))
        return {"path": path,
                "flags": "O_WRONLY|O_CREAT|" + ("O_APPEND" if append else "O_TRUNC"),
                "bytes": len(data)}

    def read_file(self, path):
        self.calls.append(("read_file", path))
        return b"fake-secret"


def install_fake(monkeypatch, fake):
    """Substitute the mock harness's syscall layer wholesale."""
    for name in dir(fake):
        if name.startswith("_"):
            continue
        attr = getattr(fake, name)
        if callable(attr):
            monkeypatch.setattr(sc, name, attr)
    return fake


def names(fake):
    return [c[0] for c in fake.calls]


# ------------------------------------------------------------------- fixtures

@pytest.fixture()
def spec():
    return tspec.load_spec(BASELINE)


@pytest.fixture()
def manifest():
    return drv.load_path_manifest()


@pytest.fixture()
def plan_validator():
    schema = json.loads(PLAN_SCHEMA.read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


@pytest.fixture()
def record_validator():
    schema = json.loads(RECORD_SCHEMA.read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


def run_driver(monkeypatch, out_dir, **kwargs):
    """Execute a full driver run against the substituted syscall layer."""
    fake = install_fake(monkeypatch, FakeSyscalls())
    run_manifest = drv.execute(BASELINE, dict(drv.DEFAULT_PLAN), out_dir, **kwargs)
    records = [json.loads(line)
               for line in (out_dir / "action-log.jsonl").read_text().splitlines()]
    return fake, run_manifest, records


# ------------------------------------------------------- pinned path manifest

def test_manifest_schema_validates(manifest):
    schema = json.loads(MANIFEST_SCHEMA.read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(manifest)


def test_manifest_hash_verifies():
    proc = subprocess.run(
        [sys.executable, str(HASH_TOOL), "--check", str(MANIFEST_PATH) + ".sha256",
         str(MANIFEST_PATH)], capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr


def test_manifest_hash_tamper_detected(tmp_path):
    manifest = yaml.safe_load(MANIFEST_PATH.read_text())
    manifest["paths"][0]["operation"] = "tampered"
    bad = tmp_path / "manifest.yaml"
    bad.write_text(yaml.safe_dump(manifest))
    sidecar = tmp_path / "manifest.yaml.sha256"
    sidecar.write_text((MANIFEST_PATH.parent / "manifest.yaml.sha256").read_text())
    proc = subprocess.run(
        [sys.executable, str(HASH_TOOL), "--check", str(sidecar), str(bad)],
        capture_output=True, text=True)
    assert proc.returncode != 0


def test_manifest_covers_every_spec_action(manifest, spec):
    assert [p["id"] for p in manifest["paths"]] == [a["id"] for a in spec["actions"]]
    assert drv.check_manifest_matches_spec(manifest, spec) == []


def test_manifest_declares_the_five_escape_paths(manifest):
    assert {p["name"] for p in manifest["escape_paths"]} == ESCAPE_NAMES
    by_class = {}
    for path in manifest["paths"]:
        by_class.setdefault(path["class"], set()).update(path["escape_categories"])
    assert "unwatched-channels" in by_class["direct_network"]
    assert "direct-origin-operations" in by_class["file_write"]
    assert "direct-origin-operations" in by_class["credential_access"]
    assert "direct-origin-operations" in by_class["process_spawn"]


def test_manifest_inspection_expectations(manifest):
    paths = {p["id"]: p for p in manifest["paths"]}
    # forced-egress designs prevent the raw network attempts
    assert paths["a021"]["inspection_expectation"]["t2"]["disposition"] == "prevented"
    assert paths["a022"]["inspection_expectation"]["t3"]["disposition"] == "prevented"
    # no v1 design inspects the direct-origin / spawn paths
    for aid in ("a031", "a032", "a041", "a042", "a051", "a052"):
        for design in ("t1", "t2", "t3", "t4", "t5", "t6"):
            assert paths[aid]["inspection_expectation"][design]["disposition"] == "bypassed", \
                (aid, design)
    # t0 has no enforcement point anywhere
    for path in manifest["paths"]:
        assert path["inspection_expectation"]["t0"]["disposition"] == "none"
    # http pairs cross the network-level gateway under the gateway route
    for aid in ("a011", "a012", "a013", "a014"):
        assert paths[aid]["inspection_expectation"]["t1"]["disposition"] == "checked"
    # stdio pairs keep the t0 child transport: never gateway-inspected
    for aid in ("a001", "a002", "a003"):
        assert paths[aid]["inspection_expectation"]["t1"]["disposition"] == "bypassed"


def test_manifest_gateway_routes_match_originators(manifest):
    declared = {tool: tuple(route)
                for tool, route in manifest["http_gateway_tools"].items()}
    expected = {tool: (method, path)
               for (method, path), tool in org.GATEWAY_TOOL_ROUTES.items()}
    assert declared == expected


def test_manifest_kernel_signatures_match_mapping_observables(manifest):
    """The manifest is an independent declaration, but its kernel
    signatures must agree with the mapper's observable attributes."""
    rules = yaml.safe_load((ROOT / "sensor" / "mapping" / "rules.yaml").read_text())
    classes = rules["classes"]
    by_id = {p["id"]: p for p in manifest["paths"]}
    # direct network signatures name the mapped ports
    assert by_id["a021"]["kernel_signature"]["attributes"]["connect"]["dst_port"] \
        in classes["direct_network"]["tcp_ports"]
    assert by_id["a022"]["kernel_signature"]["attributes"]["send"]["dst_port"] \
        in classes["direct_network"]["udp_ports"]
    # http pair signature names the endpoint port (8080 raw / 8090 gateway)
    assert {"raw", "gateway"}.issubset(
        by_id["a011"]["kernel_signature"]["attributes"])
    # credential signature names the seeded prefix + read flag
    assert by_id["a051"]["kernel_signature"]["attributes"]["open"]["path"] \
        .startswith(classes["credential_access"]["path_prefixes"][0])
    assert "O_RDONLY" in by_id["a051"]["kernel_signature"]["attributes"]["open"]["flags"]


# ------------------------------------------------------------------ plan schema

def test_default_plan_validates(plan_validator):
    plan_validator.validate(drv.DEFAULT_PLAN)


def test_plan_schema_rejects_bad_plans(plan_validator):
    bad = [
        {**drv.DEFAULT_PLAN, "inter_action_delay_s": -1},          # negative delay
        {**drv.DEFAULT_PLAN, "actions": {"a031": {"variant": "ghost"}}},  # unknown variant
        {**drv.DEFAULT_PLAN, "actions": {"a031": {}}, "schema": "mock-harness-plan/1"},  # no variant
        {**drv.DEFAULT_PLAN, "routes": {"http": "gateway"}},        # gateway without url
        {**drv.DEFAULT_PLAN, "routes": {"http": "carrier-pigeon"}}, # unknown route
        {**drv.DEFAULT_PLAN, "routes": {"stdio": "gateway"}},       # stdio gateway without url
        {**drv.DEFAULT_PLAN, "routes": {"stdio": "carrier-pigeon"}}, # unknown stdio route
        {**drv.DEFAULT_PLAN, "schema": "mock-harness-plan/9"},         # wrong schema const
    ]
    for plan in bad:
        with pytest.raises(jsonschema.ValidationError):
            plan_validator.validate(plan)


def test_gateway_route_requires_url_in_schema(plan_validator):
    plan = {**drv.DEFAULT_PLAN, "routes": {"http": "gateway",
                                           "gateway_url": "http://gateway:8090"}}
    plan_validator.validate(plan)
    # the stdio gateway route (t3) carries the same requirement
    plan = {**drv.DEFAULT_PLAN, "routes": {"stdio": "gateway",
                                           "gateway_url": "http://gateway:8090"}}
    plan_validator.validate(plan)


def test_driver_rejects_plan_drift(spec):
    # variant on a non-spawn action
    plan = {**drv.DEFAULT_PLAN, "actions": {"a041": {"variant": "daemon"}}}
    assert any("a041" in p for p in drv.check_plan_against_spec(plan, spec))
    # unknown action id
    plan = {**drv.DEFAULT_PLAN, "actions": {"a999": {"variant": "daemon"}}}
    assert any("a999" in p for p in drv.check_plan_against_spec(plan, spec))
    # gateway route without a url
    plan = {**drv.DEFAULT_PLAN, "routes": {"http": "gateway"}}
    assert any("gateway_url" in p for p in drv.check_plan_against_spec(plan, spec))
    # stdio gateway route (t3) without a url
    plan = {**drv.DEFAULT_PLAN, "routes": {"stdio": "gateway"}}
    assert any("stdio=gateway" in p for p in drv.check_plan_against_spec(plan, spec))


# ------------------------------------------------------------------- driver runs

def test_driver_emits_one_record_per_action(monkeypatch, tmp_path, spec,
                                             record_validator):
    fake, run_manifest, records = run_driver(monkeypatch, tmp_path)
    assert [r["id"] for r in records] == SPEC_IDS
    assert [(r["class"], r["op"]) for r in records] == \
        [(a["class"], a["op"]) for a in spec["actions"]]
    assert all(r["status"] == "ok" for r in records), [r["error"] for r in records]
    for record in records:
        record_validator.validate(record)


def test_driver_run_manifest_validates_and_pins(monkeypatch, tmp_path,
                                                 record_validator):
    _, run_manifest, records = run_driver(monkeypatch, tmp_path)
    schema = json.loads(RECORD_SCHEMA.read_text())
    jsonschema.Draft202012Validator(
        {"$ref": "#/$defs/run_manifest", "$defs": schema["$defs"]}
    ).validate(run_manifest)
    assert run_manifest["trace"]["canonical_sha256"] == \
        tspec.canonical_sha256(BASELINE)
    assert run_manifest["trace"]["sidecar_verified"] is True
    assert run_manifest["path_manifest"]["sidecar_verified"] is True
    assert run_manifest["action_log"]["records"] == len(records)
    assert run_manifest["summary"]["ok"] is True


def test_every_record_carries_provenance(monkeypatch, tmp_path):
    _, _, records = run_driver(monkeypatch, tmp_path)
    for record in records:
        assert record["provenance"] == "mock-harness"
        assert record["originator"]["mock_harness_version"]
        assert record["originator"]["action_index"] >= 0
        assert record["run_id"]


def test_run_manifest_placement_placeholder(monkeypatch, tmp_path):
    _, run_manifest, _ = run_driver(monkeypatch, tmp_path)
    assert run_manifest["placement"]["descriptor"] is None
    assert run_manifest["placement"]["attached"] is False
    assert "PLACEHOLDER" in run_manifest["placement"]["note"]


def test_placement_descriptor_attaches(monkeypatch, tmp_path):
    descriptor = {"runtime": "docker", "container_id": "abc", "netns": "t7net",
                  "uid": 0, "attached_by": "placement-wrapper-v1"}
    _, run_manifest, _ = run_driver(monkeypatch, tmp_path, placement=descriptor)
    assert run_manifest["placement"]["descriptor"] == descriptor
    assert run_manifest["placement"]["attached"] is True


def test_mode_presets_and_select(monkeypatch, tmp_path, spec):
    escape_classes = {"direct_network", "process_spawn", "file_write",
                      "credential_access"}
    twin_classes = {"stdio_tool_call", "http_tool_call"}
    _, rm_escape, escape_records = run_driver(monkeypatch, tmp_path / "esc",
                                              mode="escape")
    assert len(escape_records) == 8
    assert {r["class"] for r in escape_records} == escape_classes
    _, _, twin_records = run_driver(monkeypatch, tmp_path / "pair", mode="pairs")
    assert len(twin_records) == 7
    assert {r["class"] for r in twin_records} == twin_classes
    # --select preserves spec order even when given out of order
    _, _, selected = run_driver(monkeypatch, tmp_path / "sel",
                                select=["a032", "a031"])
    assert [r["id"] for r in selected] == ["a031", "a032"]


def test_select_unknown_id_rejected(monkeypatch, tmp_path):
    fake = install_fake(monkeypatch, FakeSyscalls())
    with pytest.raises(ValueError, match="unknown action ids"):
        drv.execute(BASELINE, dict(drv.DEFAULT_PLAN), tmp_path,
                    select=["a031", "nope"])


def test_manifest_drift_refuses_to_run(monkeypatch, tmp_path, manifest):
    install_fake(monkeypatch, FakeSyscalls())
    tampered = json.loads(json.dumps(manifest))
    tampered["paths"][0]["class"] = "file_write"
    with pytest.raises(ValueError, match="drift|validation failed"):
        drv.execute(BASELINE, dict(drv.DEFAULT_PLAN), tmp_path,
                    manifest=tampered)


# ------------------------------------------------------------- determinism

def test_originators_deterministic_same_digest(monkeypatch, tmp_path):
    _, rm1, recs1 = run_driver(monkeypatch, tmp_path / "r1")
    _, rm2, recs2 = run_driver(monkeypatch, tmp_path / "r2")
    assert rm1["action_log"]["digest"] == rm2["action_log"]["digest"]
    # normalized records are byte-identical across runs
    assert [drv.normalize_record(r) for r in recs1] == \
        [drv.normalize_record(r) for r in recs2]
    # and the digest really covers the on-disk log records
    assert rm1["action_log"]["digest"] == drv.log_digest(recs1)


def test_digest_excludes_only_timing_and_pid_fields():
    base = {"id": "a031", "detail": {"submitted_pid": 1, "stdout": "hi\n"},
            "started_epoch_ns": 1, "ended_epoch_ns": 2}
    other = {"id": "a031", "detail": {"submitted_pid": 999, "stdout": "hi\n"},
             "started_epoch_ns": 77, "ended_epoch_ns": 88}
    assert drv.normalize_record(base) == drv.normalize_record(other)
    different = {**base, "detail": {"submitted_pid": 1, "stdout": "bye\n"}}
    assert drv.normalize_record(base) != drv.normalize_record(different)


# ------------------------------------------------- escape-class originators

def compiled(action_id, spec):
    return tspec.compile_action({a["id"]: a for a in spec["actions"]}[action_id])


def ctx_for(plan=None):
    return org.RunContext("test-run", plan or dict(drv.DEFAULT_PLAN))


def test_tcp_originator_attempts_documented_syscalls(monkeypatch, spec):
    fake = install_fake(monkeypatch, FakeSyscalls())
    detail = org.direct_network_tcp(compiled("a021", spec), ctx_for())
    assert ("connect", "tcp", "net-peer", 9000) in fake.calls
    assert ("sendall", "tcp", b"direct tcp") in fake.calls
    assert "recv" in names(fake) and "close_socket" in names(fake)
    assert org.origin_channel(org.direct_network_tcp, "default", ctx_for()) \
        == "raw-socket-tcp"
    assert detail["port"] == 9000 and detail["payload_bytes"] == len(b"direct tcp")


def test_udp_originator_attempts_documented_syscalls(monkeypatch, spec):
    fake = install_fake(monkeypatch, FakeSyscalls())
    detail = org.direct_network_udp(compiled("a022", spec), ctx_for())
    assert ("sendto", b"direct udp", "net-peer", 9001) in fake.calls
    assert ("udp_socket",) in fake.calls
    assert ("close_socket", "udp") in fake.calls
    assert org.origin_channel(org.direct_network_udp, "default", ctx_for()) \
        == "raw-socket-udp"


def test_spawn_ordinary_uses_canonical_argv_and_joins(monkeypatch, spec):
    fake = install_fake(monkeypatch, FakeSyscalls())
    detail = org.process_spawn_exec(compiled("a031", spec), ctx_for(),
                                    variant="ordinary")
    # child-side wiring + exec attempt (unit-tested directly below covers the
    # child branch; here the parent flow): canonical argv + wait + capture
    assert detail["argv"] == ["/bin/sh", "-c", "echo hi"]
    assert detail["waited"] is True
    assert detail["stdout"] == "hi\n"
    assert ("waitpid", 4243) in fake.calls   # joined direct child
    assert detail["deferred"] is False


def test_spawn_outliving_records_at_submission(monkeypatch, spec):
    fake = install_fake(monkeypatch, FakeSyscalls())
    ctx = ctx_for()
    ctx.action_id = "a031"
    detail = org.process_spawn_exec(compiled("a031", spec), ctx,
                                    variant="outliving")
    assert detail["argv"] == ["/bin/sh", "-c", "echo hi"]
    assert detail["waited"] is False
    assert detail["submitted_pid"] == 4243
    assert detail["deferred"] is True
    # no pipe capture, no wait: the record completes before the child's effect
    assert "read_all" not in names(fake)
    assert "waitpid" not in names(fake)
    assert ctx.deferred == [{"id": "a031", "pid": 4243, "kind": "outliving"}]


def test_spawn_daemon_parent_flow(monkeypatch, spec):
    fake = install_fake(monkeypatch, FakeSyscalls())
    fake.seeded_lines.append("4244\n")   # the worker-pid pipe report
    ctx = ctx_for()
    ctx.action_id = "a032"
    detail = org.process_spawn_exec(compiled("a032", spec), ctx, variant="daemon")
    assert detail["argv"] == ["/bin/echo", "spawned", "directly"]
    assert detail["submitted_pid"] == 4244
    assert detail["setsid"] is True
    assert detail["deferred"] is True
    # the intermediate is reaped; the (reparented) worker never is
    assert ("waitpid", 4243) in fake.calls
    waited = [c[1] for c in fake.calls if c[0] == "waitpid"]
    assert 4244 not in waited
    assert ctx.deferred == [{"id": "a032", "pid": 4244, "kind": "daemon"}]


def test_daemonize_intermediate_attempts_documented_syscalls(monkeypatch):
    """The daemon submission's child-side sequence: setsid, fork the worker
    (which execve's — unit-tested separately), report the pid, exit 0."""
    fake = install_fake(monkeypatch, FakeSyscalls())
    with pytest.raises(SystemExit):
        org._daemonize_intermediate(["/bin/echo", "spawned", "directly"], 10, 11)
    assert fake.calls.count(("setsid",)) == 1
    assert names(fake).count("fork") == 1          # the worker fork
    assert ("close_fd", 10) in fake.calls
    assert any(c[0] == "write_fd" and c[2] == b"4243\n" for c in fake.calls)
    assert ("exit_child", 0) in fake.calls


def test_exec_child_attempts_execve_and_never_returns(monkeypatch):
    """The child-side helper: dup2 wiring, execve attempt, exit 127 when exec
    cannot happen. Directly callable because no real fork is involved."""
    fake = install_fake(monkeypatch, FakeSyscalls())
    with pytest.raises(SystemExit):
        org._exec_child(["/bin/echo", "spawned", "directly"],
                        stdout_fd=7, close_fds=(5,))
    assert ("close_fd", 5) in fake.calls
    assert ("dup2", 7, 1) in fake.calls
    assert ("execv", "/bin/echo", ("/bin/echo", "spawned", "directly")) in fake.calls
    assert ("exit_child", 127) in fake.calls


def test_exec_child_devnull_wiring(monkeypatch):
    fake = install_fake(monkeypatch, FakeSyscalls())
    with pytest.raises(SystemExit):
        org._exec_child(["/bin/echo", "x"], close_fds=(5, 6), devnull=True)
    assert ("dup2", 99, 1) in fake.calls and ("dup2", 99, 2) in fake.calls
    assert ("close_fd", 5) in fake.calls and ("close_fd", 6) in fake.calls
    assert ("execv", "/bin/echo", ("/bin/echo", "x")) in fake.calls


def test_spawn_variants_keep_execve_signature(monkeypatch, spec):
    """argv stays the canonical compiled shape in every variant — only the
    wait/session/reparent relationship changes."""
    install_fake(monkeypatch, FakeSyscalls())
    rec = compiled("a031", spec)
    for variant in ("ordinary", "outliving"):
        detail = org.process_spawn_exec(rec, ctx_for(), variant=variant)
        assert detail["argv"] == rec["cmd"]


def test_file_write_originator_real_fs(tmp_path):
    """Real syscall-layer behavior (no network, no children): the direct
    write's open flags match the canonical op semantics."""
    target = tmp_path / "b.txt"
    target.write_text("old content that must be truncated away")
    action = {"id": "a041", "class": "file_write", "target": str(target),
              "op": "write", "args": {"data": "direct write"}}
    detail = org.file_write(tspec.compile_action(action), ctx_for())
    assert target.read_text() == "direct write"
    assert detail["flags"] == "O_WRONLY|O_CREAT|O_TRUNC"

    log = tmp_path / "c.log"
    action = {"id": "a042", "class": "file_write", "target": str(log),
              "op": "append", "args": {"data": "appended line\n"}}
    org.file_write(tspec.compile_action(action), ctx_for())
    org.file_write(tspec.compile_action(action), ctx_for())
    assert log.read_text() == "appended line\nappended line\n"


def test_credential_read_originator_real_fs(tmp_path):
    secret = tmp_path / "token"
    secret.write_text("seed-token-1")
    action = {"id": "a051", "class": "credential_access",
              "target": "file://" + str(secret), "op": "read"}
    detail = org.credential_read(tspec.compile_action(action), ctx_for())
    assert detail["bytes"] == len(b"seed-token-1")
    assert org.origin_channel(org.credential_read, "default", ctx_for()) \
        == "direct-file-read"
    assert "seed-token-1" not in json.dumps(detail)  # content never recorded


def test_syscall_layer_flags_match_manifest(tmp_path):
    """The syscall layer's open flags are the manifest's kernel signature."""
    target = tmp_path / "x.txt"
    sc.write_file(str(target), b"data", append=False)
    # O_TRUNC default (write); O_APPEND for append
    again = tmp_path / "y.txt"
    info = sc.write_file(str(again), b"data", append=True)
    assert "O_APPEND" in info["flags"] and "O_TRUNC" not in info["flags"]


# --------------------------------------------------------------- tool pairs

def test_stdio_twin_speaks_mcp_stdio_protocol(monkeypatch, spec):
    fake = install_fake(monkeypatch, FakeSyscalls())
    ctx = ctx_for()
    org.stdio_tool_call(compiled("a001", spec), ctx)
    frames = [c[2] for c in fake.calls if c[0] == "write_fd"]
    parsed = [json.loads(frame.decode()) for frame in frames]
    assert parsed[0]["method"] == "initialize"
    assert parsed[0]["params"]["protocolVersion"] == "2025-06-18"
    assert parsed[1]["method"] == "notifications/initialized"
    assert parsed[2]["method"] == "tools/call"
    assert parsed[2]["params"]["name"] == "write_file"
    assert parsed[2]["params"]["arguments"] == {"path": "/workspace/out/a.txt",
                                                "data": "hello from mcp fs"}


def test_stdio_twin_session_reused_per_run(monkeypatch, spec):
    fake = install_fake(monkeypatch, FakeSyscalls())
    ctx = ctx_for()
    for aid in ("a001", "a002", "a003"):
        org.stdio_tool_call(compiled(aid, spec), ctx)
    # one initialize handshake for the whole run (the documented multiplicity)
    initialize_frames = [json.loads(c[2].decode()) for c in fake.calls
                        if c[0] == "write_fd"]
    assert sum(1 for f in initialize_frames
               if f.get("method") == "initialize") == 1
    assert len([c for c in fake.calls if c[0] == "fork"]) == 1  # one server child


def test_stdio_twin_gateway_route(monkeypatch, spec):
    """T3 (routes.stdio=gateway): the pair performs ONE MCP tools/call
    JSON-RPC POST to the gateway /mcp endpoint per action — bare fs tool
    name, the action's own arguments, the _meta carriers — and spawns NO
    local server child (the stdio transport is eliminated; the harness
    GATEWAY_FS route)."""
    fake = install_fake(monkeypatch, FakeSyscalls())
    plan = {"schema": "mock-harness-plan/1",
            "routes": {"http": "raw", "stdio": "gateway",
                       "gateway_url": "http://gateway:8090"}}
    ctx = ctx_for(plan)
    ctx.action_id = "a001"
    detail = org.stdio_tool_call(compiled("a001", spec), ctx)
    # no local stdio session on this route
    assert "fork" not in names(fake) and "execv" not in names(fake)
    method, url, body, headers = next(c[1:] for c in fake.calls
                                      if c[0] == "http_request")
    assert method == "POST" and url == "http://gateway:8090/mcp"
    frame = json.loads(body)
    assert frame["method"] == "tools/call"
    assert frame["jsonrpc"] == "2.0"
    # bare fs tool name (the gateway's FS_TOOLS routing), the action's args
    assert frame["params"]["name"] == "write_file"
    assert frame["params"]["arguments"] == {"path": "/workspace/out/a.txt",
                                             "data": "hello from mcp fs"}
    # carrier 1 (DESIGN.md 5): the _meta namespaced keys
    assert frame["params"]["_meta"] == {"io.inspection/action_id": "a001",
                                        "io.inspection/attempt": 0}
    assert detail["via"] == "gateway" and detail["gateway_tool"] == "write_file"
    assert detail["response_bytes"] == 2   # the fake serves content text "ok"
    # the OS channel under the gateway route is the pooled http-connect
    assert org.origin_channel(org.stdio_tool_call, "default", ctx) \
        == "http-connect"
    assert "gateway" in org.origin_channel_detail(org.stdio_tool_call,
                                                   "default", ctx)


def test_stdio_twin_gateway_route_without_url_is_an_error(monkeypatch, spec):
    """A gateway stdio route without a gateway_url (and no env fallback) is
    an error raised to the driver — recorded as data, never a run failure
    — and nothing is attempted on the network."""
    fake = install_fake(monkeypatch, FakeSyscalls())
    monkeypatch.delenv("GATEWAY_URL", raising=False)
    plan = {"schema": "mock-harness-plan/1",
            "routes": {"stdio": "gateway"}}
    ctx = ctx_for(plan)
    ctx.action_id = "a001"
    with pytest.raises(org.SpawnError, match="gateway_url"):
        org.stdio_tool_call(compiled("a001", spec), ctx)
    assert "http_request" not in names(fake)


def test_stdio_twin_namespaced_tool_maps_to_bare_name(monkeypatch, spec):
    """The gateway routes fs tools by their bare names (FS_TOOLS); the
    compiled stdio actions already carry the bare op, and a namespaced
    form (the pi adapter's stdio tool names) maps to the same bare tool."""
    assert org.gateway_tool_name("write_file") == "write_file"
    assert org.gateway_tool_name("mcp__toy-mcp-fs__write_file") == "write_file"
    assert org.gateway_tool_name("mcp__toy-mcp-fs__list_directory") \
        == "list_directory"
    fake = install_fake(monkeypatch, FakeSyscalls())
    plan = {"schema": "mock-harness-plan/1",
            "routes": {"stdio": "gateway",
                       "gateway_url": "http://gateway:8090"}}
    ctx = ctx_for(plan)
    ctx.action_id = "a003"
    rec = compiled("a003", spec)
    rec["tool"] = "mcp__toy-mcp-fs__list_directory"   # the namespaced form
    org.stdio_tool_call(rec, ctx)
    frame = json.loads(next(c[3] for c in fake.calls if c[0] == "http_request"))
    assert frame["params"]["name"] == "list_directory"   # bare name on the wire


def test_stdio_twin_gateway_denial_is_an_error(monkeypatch, spec):
    """A gateway JSON-RPC error response (a denied/failed call) is an error
    raised to the driver — errors-as-data, the pair never self-reports an
    outcome."""

    class DenyingGateway(FakeSyscalls):
        def http_request(self, method, url, body=None, headers=None):
            self.calls.append(("http_request", method, url, body,
                               dict(headers) if headers else None))
            frame = json.loads(body)
            return 200, json.dumps({
                "jsonrpc": "2.0", "id": frame["id"],
                "error": {"code": -32001,
                           "message": "gateway denied 'write_file': not allowed"}}
            ).encode()

    install_fake(monkeypatch, DenyingGateway())
    plan = {"schema": "mock-harness-plan/1",
            "routes": {"stdio": "gateway",
                       "gateway_url": "http://gateway:8090"}}
    ctx = ctx_for(plan)
    ctx.action_id = "a001"
    with pytest.raises(org.SpawnError, match="gateway denied"):
        org.stdio_tool_call(compiled("a001", spec), ctx)


def test_http_twin_raw_route(monkeypatch, spec):
    fake = install_fake(monkeypatch, FakeSyscalls())
    ctx = ctx_for()
    ctx.action_id = "a011"
    detail = org.http_tool_call(compiled("a011", spec), ctx)
    # the raw route's correlation carrier (DESIGN.md 5): the
    # x-inspection-* headers on the request (the driver sets ctx.action_id)
    assert ("http_request", "POST", "http://http-endpoint:8080/hook",
            "tool-call payload",
            {"x-inspection-action-id": "a011",
             "x-inspection-attempt": "0"}) in fake.calls
    assert org.origin_channel(org.http_tool_call, "default", ctx_for()) \
        == "http-connect"
    assert detail["via"] == "raw" and detail["http_status"] == 200


def test_http_twin_gateway_route(monkeypatch, spec):
    fake = install_fake(monkeypatch, FakeSyscalls())
    plan = {"schema": "mock-harness-plan/1",
            "routes": {"http": "gateway", "gateway_url": "http://gateway:8090"}}
    ctx = ctx_for(plan)
    detail = org.http_tool_call(compiled("a011", spec), ctx)
    method, url, body, headers = next(c[1:] for c in fake.calls
                                      if c[0] == "http_request")
    assert method == "POST" and url == "http://gateway:8090/mcp"
    frame = json.loads(body)
    assert frame["method"] == "tools/call"
    assert frame["params"]["name"] == "post_hook"
    assert frame["params"]["arguments"] == {"body": "tool-call payload"}
    assert detail["via"] == "gateway" and detail["tool"] == "post_hook"


def test_http_twin_a014_shares_the_a011_route(monkeypatch, spec):
    """The checked-DENY case uses the same route/tool as a011 with its own
    argument value — identical to the harness route shape."""
    fake = install_fake(monkeypatch, FakeSyscalls())
    plan = {"schema": "mock-harness-plan/1",
            "routes": {"http": "gateway", "gateway_url": "http://gateway:8090"}}
    ctx = ctx_for(plan)
    detail = org.http_tool_call(compiled("a014", spec), ctx)
    frame = json.loads(next(c[3] for c in fake.calls if c[0] == "http_request"))
    assert frame["params"]["name"] == "post_hook"
    assert frame["params"]["arguments"] == {"body": "policy-deny case"}
    assert detail["tool"] == "post_hook"


def test_daemon_and_outliving_join_results(monkeypatch, tmp_path, spec):
    plan = {**drv.DEFAULT_PLAN,
            "actions": {"a031": {"variant": "outliving"},
                        "a032": {"variant": "daemon"}}}
    fake = install_fake(monkeypatch, FakeSyscalls())
    fake.seeded_lines.append("4245\n")  # daemon worker pid report
    run_manifest = drv.execute(BASELINE, plan, tmp_path)
    joined = {e["id"]: e for e in run_manifest["deferred_join"]}
    assert set(joined) == {"a031", "a032"}
    assert joined["a031"]["kind"] == "outliving" and joined["a031"]["joined"]
    assert joined["a032"]["kind"] == "daemon" and joined["a032"]["joined"]
    records = {r["id"]: r for r in
               [json.loads(l) for l in
                (tmp_path / "action-log.jsonl").read_text().splitlines()]}
    assert records["a031"]["originator"]["deferred"] is True
    assert records["a032"]["originator"]["deferred"] is True


# -------------------------------------------------------- deferred join loop

def test_join_deferred_bounded_and_reports_alive(monkeypatch):
    install_fake(monkeypatch, FakeSyscalls())
    ctx = ctx_for()
    ctx.action_id = "a031"
    ctx.defer(9999, "outliving")
    # monkeypatch child_exit_state to keep reporting "running"
    monkeypatch.setattr(sc, "child_exit_state", lambda pid: ("running", None))
    joined = drv.join_deferred(ctx, timeout_s=0.0)
    assert joined == [{"id": "a031", "pid": 9999, "kind": "outliving",
                       "joined": False, "exit_code": None,
                       "note": "still alive at join timeout"}]


# ---------------------------------------------------------- policy-blindness

FORBIDDEN_IMPORT_ROOTS = {"gateway", "sensor", "runner", "probes",
                          "harnesses", "compose"}
FORBIDDEN_SYMBOLS = re.compile(
    r"classif|enforc|permi|polic|(?<!inter)inspect|denied|denies|allow|caught|bypass|verdict|coverage",
    re.IGNORECASE)


def mock_harness_sources():
    return sorted((ROOT / "mock_harness").glob("*.py"))


def test_no_inspection_layer_imports():
    for path in mock_harness_sources():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    assert alias.name.split(".")[0] not in FORBIDDEN_IMPORT_ROOTS, \
                        f"{path.name}: imports {alias.name}"
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                assert module.split(".")[0] not in FORBIDDEN_IMPORT_ROOTS, \
                    f"{path.name}: imports from {module}"


def test_no_classification_or_enforcement_symbols():
    """No function/class in the mock harness package classifies, permits,
    denies, or otherwise evaluates actions — it only performs them."""
    for path in mock_harness_sources():
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                assert not FORBIDDEN_SYMBOLS.search(node.name), \
                    f"{path.name}: symbol {node.name!r}"


def test_records_never_self_report_outcomes(monkeypatch, tmp_path):
    banned = {"outcome", "caught", "inspected", "bypassed", "allowed",
              "denied", "classification", "covered"}
    schema = json.loads(RECORD_SCHEMA.read_text())
    assert banned.isdisjoint(schema["$defs"]["action_record"]["properties"])
    _, _, records = run_driver(monkeypatch, tmp_path)
    for record in records:
        def scan(value):
            if isinstance(value, dict):
                for key, val in value.items():
                    assert key not in banned, f"record {record['id']}: {key}"
                    scan(val)
            elif isinstance(value, list):
                for item in value:
                    scan(item)
        scan(record)


def test_records_carry_origin_channels(monkeypatch, tmp_path):
    _, _, records = run_driver(monkeypatch, tmp_path)
    expected = {
        "a001": "mcp-stdio-child-pipe", "a002": "mcp-stdio-child-pipe",
        "a003": "mcp-stdio-child-pipe",
        "a011": "http-connect", "a012": "http-connect",
        "a013": "http-connect", "a014": "http-connect",
        "a021": "raw-socket-tcp", "a022": "raw-socket-udp",
        "a031": "fork+execve", "a032": "fork+execve",
        "a041": "direct-file-write", "a042": "direct-file-write",
        "a051": "direct-file-read", "a052": "direct-file-read",
    }
    for record in records:
        assert record["origin_channel"] == expected[record["id"]], record["id"]

def test_record_channels_match_manifest(monkeypatch, tmp_path, manifest):
    """Drift guard: every record's origin_channel equals the manifest's
    origin_channel declaration for that path (labels are the manifest's,
    the record carries variant/routing detail separately)."""
    declared = {p["id"]: p["origin_channel"] for p in manifest["paths"]}
    _, _, records = run_driver(monkeypatch, tmp_path)
    for record in records:
        assert record["origin_channel"] == declared[record["id"]], record["id"]
        assert record["origin_channel_detail"], record["id"]


def test_driver_does_not_abort_on_action_errors(monkeypatch, tmp_path):
    """Policy-blind and unconditional: a failing originator (e.g. refused
    connect) is recorded as data and the rest of the surface still runs."""
    fake = install_fake(monkeypatch, FakeSyscalls())

    def refusing_connect(sock, host, port):
        raise OSError(111, "Connection refused")

    monkeypatch.setattr(sc, "connect", refusing_connect)
    run_manifest = drv.execute(BASELINE, dict(drv.DEFAULT_PLAN), tmp_path)
    records = [json.loads(l) for l in
               (tmp_path / "action-log.jsonl").read_text().splitlines()]
    assert len(records) == 15
    refused = [r for r in records if r["status"] == "error"]
    assert {r["id"] for r in refused} == {"a021"}   # only the tcp pair refused
    # the error record still names the channel it attempted (auditability)
    assert refused[0]["origin_channel"] == "raw-socket-tcp"
    assert "Connection refused" in refused[0]["error"]
    assert run_manifest["summary"]["failed"] == 1


# ----------------------------------------------------------------- driver CLI

def test_cli_main(monkeypatch, tmp_path):
    install_fake(monkeypatch, FakeSyscalls())
    rc = drv.main(["--out", str(tmp_path), "--mode", "escape"])
    assert rc == 0
    assert (tmp_path / "action-log.jsonl").is_file()
    assert (tmp_path / "run-manifest.json").is_file()
    run_manifest = json.loads((tmp_path / "run-manifest.json").read_text())
    assert run_manifest["summary"]["executed"] == 8
    assert run_manifest["mock_harness"]["git"]["available"] in (True, False)


def test_cli_bad_plan_exits_two(monkeypatch, tmp_path):
    install_fake(monkeypatch, FakeSyscalls())
    bad_plan = tmp_path / "bad-plan.yaml"
    bad_plan.write_text("schema: mock-harness-plan/9\n")
    assert drv.main(["--out", str(tmp_path), "--plan", str(bad_plan)]) == 2
