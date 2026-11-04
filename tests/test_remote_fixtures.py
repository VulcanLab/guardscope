"""The REMOTE delegation fixtures (F4, F5) + the two-host deployment:
offline tests, same style as tests/test_remaining_fixtures.py.

Covers, offline only (no Docker, no network beyond loopback — the two
hosts are simulated as two separate artifact directories on one
machine):
  - the two trace variants (baseline-f4, -f5) validate against the trace
    schema (the additive optional performed_by field, now with the
    remote fixtures' values) and keep the canonical action surface 1:1
    (same ids/classes/targets/ops as baseline.yaml; only the six
    process-level effect actions are marked);
  - the compiler passes each fixture's performed_by through to the
    compiled plan and the C2 diff stays clean;
  - the workload selection resolves baseline-f4/-f5 to their trace files;
  - F4 (an agent hiding inside a REMOTE tool, over HTTP): the remote
    tool server (targets/mcp-agent/http-server.py), RUN AS A REAL LOCAL
    SUBPROCESS, takes the hand-off (the delegation id on the request
    headers, the http_header carrier), its internal agent performs a
    real file write ON ITS OWN MACHINE beyond the tool's response, its
    acceptance record carries machine "executor" (the frozen
    delegation-record/1 schema), and both machines' records load clean
    and chain; a call without a hand-off is refused, never invented;
  - F5 (a remote agent server, the A2A-style task interface): the remote
    agent server (targets/a2a-agent/server.py), RUN AS A REAL LOCAL
    SUBPROCESS, accepts the task message (the chain ids ride the message
    metadata, the queue_payload carrier), performs a real spawn on its
    own machine, writes its machine "executor" acceptance record, and
    returns the report as the completed task's artifact; a submission
    without a hand-off is refused;
  - the two adapter branches (delegateToRemoteTool, delegateToRemoteAgent)
    run under Node against the real python servers: the network call is a
    real HTTP request to a locally-started server, the sent records say
    machine "origin", the returned report's echo travels in the row detail;
  - the runner's cross-host collection (runner/run.py
    collect_executor_artifacts): the executor host's pulled directory
    (delegation records + the far machine's Tracee events) merges into
    the run's artifacts — the executor records join the origin stream,
    the far machine's kernel observations are retained as SEPARATE
    artifacts, never pooled into the origin host's counts;
  - the two-host compose topology: the executor stack
    (compose/executor.yaml) runs the remote servers + its OWN sensor as
    its own compose project, and the origin overlay
    (compose/t0-remote.yaml) adds ONLY the remote addresses' env to the
    pi service — the single-machine compose bases are untouched.

The TypeScript adapter branches' container loading path (jiti,
/opt/inspection) is not live-tested here — the same not-live-verified
status as the other fixtures' branches.

The rework regression tests (one per checker finding) additionally
cover: the response-echo validation (a wrong/missing echo is a visible
error that keeps the SENT id), the full-cycle action timeout (a stalled
response body cannot outlive the deadline), the gateway routing of the
remote hand-offs (GATEWAY_URL set = a proxied tools/call the gateway
decides on) and their T4 tool-pipeline crossing (real harness tools the
scripted provider selects), the workload-aware origin-host reconciliation
of a remote-fixture run (expected absent, never a failure, with the
unmarked-baseline negative control), run_one's evidence collection on a
replay failure (no abort before the run dir), the run-id selection of
the executor collection, the collect-remote manifest-hash refresh, and
the hop validation on both remote servers.

Run from the repo root:  python3 -m pytest tests/test_remote_fixtures.py -v
"""

import importlib.util
import json
import os
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from framework.delegation import (  # noqa: E402
    ATTRIBUTED, build_chains, load_delegation_records, trace_back,
)
from framework.workloads import (  # noqa: E402
    trace_spec_path,
)
from framework import execute as execute_mod  # noqa: E402

BASELINE = ROOT / "trace" / "traces" / "baseline.yaml"
TRACES = ROOT / "trace" / "traces"
TRACE_SCHEMA = ROOT / "trace" / "schema" / "trace.schema.json"
COMPILE_PY = ROOT / "trace" / "compile" / "pi" / "compile.py"
F4_SERVER = ROOT / "targets" / "mcp-agent" / "http-server.py"
F5_SERVER = ROOT / "targets" / "a2a-agent" / "server.py"
F3_STDIO_SERVER = ROOT / "targets" / "mcp-agent" / "server.py"
COMPOSE = ROOT / "compose"

# the six process-level effect actions every fixture marks
DELEGATED_IDS = {"a021", "a022", "a031", "a032", "a041", "a042"}
# the remote fixtures' performed_by values, one per spec
FIXTURE_SPECS = {
    "baseline-f4": (TRACES / "baseline-f4.yaml", "remote-tool-agent"),
    "baseline-f5": (TRACES / "baseline-f5.yaml", "remote-agent"),
}

# well-formed ULIDs for the synthetic records (delegation-record/1 record_id)
RID1 = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
RID2 = "01ARZ3NDEKTSV4RRFFQ69G5FAW"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _yaml(path):
    return yaml.safe_load(path.read_text())


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_health(url: str, timeout_s: float = 10.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"{url}/health", timeout=1) as r:
                if r.status == 200:
                    return
        except OSError:
            time.sleep(0.1)
    raise AssertionError(f"the remote server at {url} never came up")


def _post(url: str, body: dict, headers: dict | None = None) -> tuple[int, dict]:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


# --- the trace variants --------------------------------------------------------

def test_fixture_specs_validate_against_the_trace_schema():
    schema = json.loads(TRACE_SCHEMA.read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    validator = cls(schema)
    for path, _ in FIXTURE_SPECS.values():
        validator.validate(_yaml(path))


def test_the_schema_enum_admits_the_remote_markings():
    """Additive only: the two new performed_by values join the existing
    enum — the existing markings are untouched."""
    schema = json.loads(TRACE_SCHEMA.read_text())
    enum = (schema["$defs"]["action"]["properties"]["performed_by"]
            ["enum"])
    assert "remote-tool-agent" in enum
    assert "remote-agent" in enum
    for existing in ("child", "grandchild", "role", "tool-agent",
                     "restricted-child", "detached-child"):
        assert existing in enum


def test_fixture_specs_keep_the_canonical_action_surface():
    baseline = {a["id"]: a for a in _yaml(BASELINE)["actions"]}
    for path, mark in FIXTURE_SPECS.values():
        spec = _yaml(path)
        assert {a["id"] for a in spec["actions"]} == set(baseline)
        for a in spec["actions"]:
            sa = baseline[a["id"]]
            for field in ("class", "target", "op"):
                assert a[field] == sa[field], f"{a['id']}: {field} moved"
            assert a.get("args") == sa.get("args")
            if a["id"] in DELEGATED_IDS:
                assert a["performed_by"] == mark
            else:
                assert "performed_by" not in a
        assert spec["meta"]["window"] == _yaml(BASELINE)["meta"]["window"]


def test_fixture_sidecars_match_the_canonical_hash():
    hash_mod = _load_module("hash_spec_remote",
                            ROOT / "trace" / "hash_spec.py")
    for path, _ in FIXTURE_SPECS.values():
        sidecar = Path(str(path) + ".sha256")
        assert sidecar.is_file(), f"{sidecar.name} missing"
        assert sidecar.read_text().split()[0] == hash_mod.canonical_hash(path)


def test_fixture_specs_compile_and_pass_performed_by_through():
    co = _load_module("compile_pi_remote", COMPILE_PY)
    for path, mark in FIXTURE_SPECS.values():
        compiled = co.compile_spec(path)
        by_id = {a["id"]: a for a in compiled["actions"]}
        assert len(compiled["actions"]) == 15
        for aid in DELEGATED_IDS:
            assert by_id[aid]["performed_by"] == mark
        for aid in set(by_id) - DELEGATED_IDS:
            assert "performed_by" not in by_id[aid]
        assert co.diff_compiled(path, compiled) == []
        # deterministic like every compiled trace
        again = co.compile_spec(path)
        assert json.dumps(compiled, sort_keys=True) == \
            json.dumps(again, sort_keys=True)


def test_the_workload_names_resolve_to_their_trace_files():
    for name, (path, _) in FIXTURE_SPECS.items():
        assert trace_spec_path(name) == path
    with pytest.raises(ValueError):
        trace_spec_path("baseline-f99")


# --- the record shapes the fixtures emit ------------------------------------------

def handoff_record(event, rid, did, *, channel, protocol, carrier,
                   from_actor, to_actor, stream_id, run_id="r-remote",
                   machine, hop=1, parent=None):
    """One delegation-record/1 line, parameterized per fixture — the
    machine label is the parameter that moves (the frozen schema's
    "origin" | "executor")."""
    return {"schema": 1, "record_id": rid, "run_id": run_id,
            "stream_id": stream_id, "seq": 0,
            "ts": "2026-11-02T10:00:00.000Z", "event": event,
            "channel": channel, "delegation_id": did,
            "parent_delegation_id": parent,
            "root_delegation_id": did, "hop": hop,
            "from_actor": from_actor, "to_actor": to_actor,
            "task_digest": "0123456789abcdef", "protocol": protocol,
            "machine": machine, "carrier": carrier}


def f4_pair(did):
    """F4's cross-machine record pair: the adapter's sent line on the
    origin machine, the remote server's accepted line on the executor
    machine."""
    return [handoff_record("sent", RID1, did, channel="tool",
                           protocol="http", carrier="http_header",
                           from_actor="pi-root",
                           to_actor="f4-remote-tool-agent",
                           stream_id="pi-root", machine="origin"),
            handoff_record("accepted", RID2, did, channel="tool",
                           protocol="http", carrier="http_header",
                           from_actor="pi-root",
                           to_actor="f4-remote-tool-agent",
                           stream_id="toy-mcp-agent-http-1",
                           machine="executor")]


def f5_pair(did):
    """F5's cross-machine record pair: the study's agent-to-agent boundary
    class (channel network, protocol a2a, carrier queue_payload)."""
    return [handoff_record("sent", RID1, did, channel="network",
                           protocol="a2a", carrier="queue_payload",
                           from_actor="pi-root",
                           to_actor="f5-remote-agent",
                           stream_id="pi-root", machine="origin"),
            handoff_record("accepted", RID2, did, channel="network",
                           protocol="a2a", carrier="queue_payload",
                           from_actor="pi-root",
                           to_actor="f5-remote-agent",
                           stream_id="a2a-agent-1", machine="executor")]


def _records_text(records):
    return "".join(json.dumps(r) + "\n" for r in records)


def _records_path(tmp_path, records):
    path = tmp_path / "records.jsonl"
    path.write_text(_records_text(records))
    return path


@pytest.mark.parametrize("pair", [f4_pair("d-1"), f5_pair("d-1")])
def test_cross_machine_pairs_load_clean_and_chain(tmp_path, pair):
    """The frozen delegation-record/1 schema admits the executor-machine
    acceptance (the machine field exists for exactly this), the chain
    joins across the two machines, and the trace-back attributes through
    the exact echo."""
    records, problems = load_delegation_records(_records_path(tmp_path, pair))
    assert problems == []
    assert {r["machine"] for r in records} == {"origin", "executor"}
    table = build_chains(records)
    assert table.problems == []
    assert table.accepted["d-1"] in ("f4-remote-tool-agent",
                                     "f5-remote-agent")
    res = trace_back([{"ts_epoch_ns": 1, "delegation_id": "d-1"}], table)
    assert res[0]["status"] == ATTRIBUTED
    assert res[0]["method"] == "id-echo"
    assert res[0]["chain"] == ["d-1"]


# --- F4: the remote tool server over HTTP -----------------------------------------

def _start_server(cmd: list[str], port: int, log_dir: Path,
                  port_env: str):
    env = dict(os.environ)
    env.update({"REPLAY_LOG_DIR": str(log_dir),
                port_env: str(port),
                "PYTHONDONTWRITEBYTECODE": "1"})
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                           stderr=subprocess.DEVNULL, env=env)
    url = f"http://127.0.0.1:{port}"
    _wait_health(url)
    return proc, url


def test_f4_remote_tool_server_performs_effects_on_its_own_machine(tmp_path):
    """The remote tool server, run as a REAL local subprocess (the
    network call is a real HTTP request to a locally-started server): the
    task arrives looking like an ordinary HTTP POST (the delegation id
    travels in the request headers), the server's internal agent performs a
    real file write ON ITS OWN MACHINE beyond the tool's response, writes
    its acceptance record with machine "executor", and answers with the
    report as the response body."""
    log_dir = tmp_path / "executor-replay"     # the EXECUTOR host's staging
    target = tmp_path / "executor-out" / "b.txt"
    port = _free_port()
    proc, url = _start_server(
        [sys.executable, "-u", str(F4_SERVER)], port, log_dir,
        "F4_LISTEN_PORT")
    try:
        # the ADAPTER's side of the hand-off first (the sent line the
        # adapter writes on the ORIGIN machine before the POST)
        origin_dir = tmp_path / "origin-replay"
        origin_dir.mkdir(parents=True, exist_ok=True)
        sent = handoff_record("sent", RID1, "d-f4-1", channel="tool",
                              protocol="http", carrier="http_header",
                              from_actor="pi-root",
                              to_actor="f4-remote-tool-agent",
                              stream_id="pi-root", run_id="r-f4-test",
                              machine="origin")
        (origin_dir / "delegation-records.jsonl").write_text(
            _records_text([sent]))

        # the ordinary-looking HTTP tool call: the delegation id travels in the
        # headers (the http_header carrier)
        code, report = _post(f"{url}/task", {
            "steps": [{"id": "a041", "class": "file_write",
                       "kind": "file_write", "path": str(target),
                       "data": "hidden remote write", "append": False}]},
            headers={"x-inspection-delegation-id": "d-f4-1",
                     "x-inspection-root-delegation-id": "d-f4-1",
                     "x-inspection-hop": "1",
                     "x-inspection-run-id": "r-f4-test"})
    finally:
        proc.kill()
        proc.wait()
    assert code == 200

    # the hidden agent's effect really happened — on the EXECUTOR
    # machine's filesystem (this test's tmp_path stands in for the far
    # machine's /workspace), beyond the tool's response
    assert target.read_text() == "hidden remote write"
    # the report IS the response body and echoes the hand-off id
    assert report["status"] == "ok"
    assert report["delegation_id"] == "d-f4-1"
    assert report["actor"] == "f4-remote-tool-agent"
    assert report["machine"] == "executor"
    assert report["results"][0]["id"] == "a041"
    assert report["results"][0]["status"] == "ok"

    # the executor side's acceptance record: machine "executor"
    records, problems = load_delegation_records(
        log_dir / "delegation-records.jsonl")
    assert problems == []
    assert len(records) == 1
    acc = records[0]
    assert acc["event"] == "accepted"
    assert acc["machine"] == "executor"
    assert acc["channel"] == "tool"
    assert acc["protocol"] == "http"
    assert acc["carrier"] == "http_header"
    assert acc["to_actor"] == "f4-remote-tool-agent"
    assert acc["run_id"] == "r-f4-test"   # the request-carried run id

    # the two machines' streams, merged the way the runner's collection
    # does, chain across the boundary
    merged = tmp_path / "merged.jsonl"
    merged.write_text(
        (origin_dir / "delegation-records.jsonl").read_text()
        + (log_dir / "delegation-records.jsonl").read_text())
    records, problems = load_delegation_records(merged)
    assert problems == []
    table = build_chains(records)
    assert table.problems == []
    assert table.accepted["d-f4-1"] == "f4-remote-tool-agent"
    res = trace_back([{"ts_epoch_ns": 1, "delegation_id": "d-f4-1"}],
                     table)
    assert res[0]["status"] == ATTRIBUTED
    assert res[0]["chain"] == ["d-f4-1"]


def test_f4_remote_tool_server_refuses_a_call_without_a_hand_off(tmp_path):
    """No delegation id on the headers means no hand-off happened: the
    remote agent must refuse (never invent one), and nothing is
    performed."""
    log_dir = tmp_path / "executor-replay"
    port = _free_port()
    proc, url = _start_server([sys.executable, "-u", str(F4_SERVER)],
                             port, log_dir, "F4_LISTEN_PORT")
    try:
        code, report = _post(f"{url}/task", {
            "steps": [{"id": "a041", "kind": "file_write",
                       "path": str(tmp_path / "never.txt"),
                       "data": "x"}]})
    finally:
        proc.kill()
        proc.wait()
    assert code == 400
    assert "delegation id" in report["error"]
    assert not (tmp_path / "never.txt").exists()
    assert not (log_dir / "delegation-records.jsonl").exists()


def test_f4_the_stdio_f3_server_is_untouched():
    """The F4 addition is a SIBLING server, additive: the F3 stdio
    hidden-agent server carries no HTTP listener (its file has no
    http.server import — the two transports stay two files)."""
    src = F3_STDIO_SERVER.read_text()
    assert "http.server" not in src
    assert "remote-tool-agent" not in src   # no F4 vocabulary leaked in


# --- F5: the remote agent server (the A2A-style task interface) --------------------

def test_f5_remote_agent_server_performs_effects_on_its_own_machine(tmp_path):
    """The remote agent server, run as a REAL local subprocess: the task
    submission arrives as one ordinary-looking HTTP request (the chain
    ids ride the message metadata, the queue_payload carrier), the far
    agent performs a real spawn ON ITS OWN MACHINE, writes its
    acceptance record with machine "executor", and returns the report as
    the completed task's artifact."""
    log_dir = tmp_path / "executor-replay"
    port = _free_port()
    proc, url = _start_server([sys.executable, "-u", str(F5_SERVER)],
                              port, log_dir, "A2A_LISTEN_PORT")
    try:
        # the ADAPTER's side of the hand-off first (the sent line on the
        # ORIGIN machine, channel network — the agent-to-agent class)
        origin_dir = tmp_path / "origin-replay"
        origin_dir.mkdir(parents=True, exist_ok=True)
        sent = handoff_record("sent", RID1, "d-f5-1", channel="network",
                              protocol="a2a", carrier="queue_payload",
                              from_actor="pi-root",
                              to_actor="f5-remote-agent",
                              stream_id="pi-root", run_id="r-f5-test",
                              machine="origin")
        (origin_dir / "delegation-records.jsonl").write_text(
            _records_text([sent]))

        # the A2A-style task submission (v1 synchronous: the submit IS
        # the get-result round trip)
        code, resp = _post(f"{url}/", {
            "jsonrpc": "2.0", "id": 1, "method": "message/send",
            "params": {"message": {
                "messageId": "d-f5-1",
                "metadata": {
                    "io.inspection/delegation_id": "d-f5-1",
                    "io.inspection/root_delegation_id": "d-f5-1",
                    "io.inspection/hop": 1,
                    "io.inspection/run_id": "r-f5-test"},
                "data": {"steps": [
                    {"id": "a032", "class": "process_spawn",
                     "kind": "spawn",
                     "cmd": ["/bin/echo", "remote agent spawn"]}]}}}})
    finally:
        proc.kill()
        proc.wait()
    assert code == 200
    assert resp["result"]["status"]["state"] == "completed"
    report = resp["result"]["artifacts"][0]["data"]
    assert report["status"] == "ok"
    assert report["delegation_id"] == "d-f5-1"
    assert report["actor"] == "f5-remote-agent"
    assert report["machine"] == "executor"
    assert report["results"][0]["id"] == "a032"
    assert report["results"][0]["status"] == "ok"

    # the executor side's acceptance record: the network channel, the
    # a2a protocol, machine "executor"
    records, problems = load_delegation_records(
        log_dir / "delegation-records.jsonl")
    assert problems == []
    acc = records[0]
    assert acc["event"] == "accepted"
    assert acc["channel"] == "network"
    assert acc["protocol"] == "a2a"
    assert acc["carrier"] == "queue_payload"
    assert acc["machine"] == "executor"
    assert acc["to_actor"] == "f5-remote-agent"
    assert acc["run_id"] == "r-f5-test"

    # the two machines' streams chain across the boundary
    merged = tmp_path / "merged.jsonl"
    merged.write_text(
        (origin_dir / "delegation-records.jsonl").read_text()
        + (log_dir / "delegation-records.jsonl").read_text())
    records, problems = load_delegation_records(merged)
    assert problems == []
    table = build_chains(records)
    assert table.problems == []
    assert table.accepted["d-f5-1"] == "f5-remote-agent"
    res = trace_back([{"ts_epoch_ns": 1, "delegation_id": "d-f5-1"}],
                     table)
    assert res[0]["status"] == ATTRIBUTED
    assert res[0]["chain"] == ["d-f5-1"]


def test_f5_remote_agent_server_refuses_a_task_without_a_hand_off(tmp_path):
    """No delegation id on the message metadata means no hand-off
    happened: the remote agent refuses (never invents one), and nothing
    is performed."""
    log_dir = tmp_path / "executor-replay"
    port = _free_port()
    proc, url = _start_server([sys.executable, "-u", str(F5_SERVER)],
                              port, log_dir, "A2A_LISTEN_PORT")
    try:
        code, resp = _post(f"{url}/", {
            "jsonrpc": "2.0", "id": 2, "method": "message/send",
            "params": {"message": {
                "messageId": "x",
                "data": {"steps": [
                    {"id": "a041", "kind": "file_write",
                     "path": str(tmp_path / "never.txt"),
                     "data": "x"}]}}}})
    finally:
        proc.kill()
        proc.wait()
    assert code == 200   # JSON-RPC carries the refusal as an error result
    assert "delegation id" in resp["error"]["message"]
    assert not (tmp_path / "never.txt").exists()
    assert not (log_dir / "delegation-records.jsonl").exists()


# --- the adapter's remote branches, run under Node ---------------------------------
#
# The same offline verification style as tests/test_remaining_fixtures.py:
# the adapter module loads under node 24 (erasable type annotations are
# stripped natively; the pi-package imports are stripped by the driver),
# and the remote branches make REAL HTTP requests to REAL locally-started
# python servers. The container extension-loading path (jiti,
# /opt/inspection) stays not-live-verified.

def _adapter_driver_source(origin_dir: Path, main_body: str) -> str:
    src = (ROOT / "harnesses" / "pi" / "adapter" / "replay.ts").read_text()
    body = "\n".join(
        line for line in src.splitlines()
        if "@earendil-works" not in line
        and not line.startswith("import type ")
    )
    body = body.replace("export default function (pi: ExtensionAPI) {",
                        "function _entry(pi: any) {")
    return body + f"""

async function main() {{
  const j = (o) => console.log(JSON.stringify(o));
{main_body}
  process.exit(0);
}}
main().catch((e) => {{ console.error("DRIVER FAIL", e); process.exit(1); }});
"""


REMOTE_MAIN = """
  // F4: the remote tool agent — an ordinary-looking HTTP POST, the far
  // server's internal agent performs the effect on its own machine
  // through the dispatcher (the switch the replay loop takes), exactly
  // the path runReplay's execAction hands a remote-marked action to
  j({ case: "f4", detail: await delegateAction({
      id: "a041", class: "file_write", op: "write", kind: "file_write",
      path: {EFFECT!r}, data: "remote tool write",
      append: false, performed_by: "remote-tool-agent" }) });
  // F5: the remote agent — an A2A-style task submission, the far agent
  // performs the effect on its own machine
  j({ case: "f5", detail: await delegateToRemoteAgent({
      id: "a031", class: "process_spawn", op: "exec", kind: "spawn",
      cmd: ["/bin/sh", "-c", "echo remote agent spawn > {EFFECT2}"],
      performed_by: "remote-agent" }) });
"""

UNSET_MAIN = """
  // a remote-marked action with no remote address configured must fail
  // loudly (the error path keeps the echo), never perform in-process
  try {
    j({ case: "unset", detail: await delegateToRemoteTool({
        id: "a041", class: "file_write", op: "write", kind: "file_write",
        path: "/tmp/never-f4.txt", data: "x", append: false,
        performed_by: "remote-tool-agent" }) });
  } catch (e) {
    j({ case: "unset", error: String(e && e.message || e),
        report: e.f2Report ?? null });
  }
"""


def test_adapter_remote_branches_run_under_node(tmp_path):
    """The two remote adapter branches, driven through the REAL module
    under Node against the real python servers: the network calls are
    real HTTP requests, the sent records say machine "origin", the
    reports' echoes ride the row details, and the executor's acceptance
    records (written by the servers into their own staging dir) merge
    into one stream whose chains build across the two machines."""
    node = subprocess.run(["which", "node"], capture_output=True,
                          text=True).stdout.strip()
    if not node:
        pytest.skip("node not available (the adapter is TypeScript)")
    # the two hosts, simulated: the origin's staging dir (the adapter's
    # records), the executor's staging dir (the servers' records), and
    # the far machine's filesystem (where the remote effects occur)
    origin_dir = tmp_path / "origin-replay"
    executor_dir = tmp_path / "executor-replay"
    executor_fx = tmp_path / "executor-fx"
    origin_dir.mkdir(parents=True)
    executor_dir.mkdir(parents=True)

    f4_port, f5_port = _free_port(), _free_port()
    f4_proc, f4_url = _start_server(
        [sys.executable, "-u", str(F4_SERVER)], f4_port, executor_dir,
        "F4_LISTEN_PORT")
    f5_proc, f5_url = _start_server(
        [sys.executable, "-u", str(F5_SERVER)], f5_port, executor_dir,
        "A2A_LISTEN_PORT")
    try:
        driver = tmp_path / "driver.ts"
        driver.write_text(_adapter_driver_source(
            origin_dir, REMOTE_MAIN.replace(
                "{EFFECT!r}",
                repr(str(executor_fx / "f4-effect.txt"))).replace(
                "{EFFECT2}", str(executor_fx / "f5-effect.txt"))))
        env = dict(os.environ)
        env.update({
            "REPLAY_LOG_DIR": str(origin_dir),
            "INSPECTION_RUN_ID": "r-remote-branches",
            "F4_TOOL_SERVER_URL": f4_url,
            "F5_AGENT_SERVER_URL": f5_url,
        })
        proc = subprocess.run(
            [node, "--experimental-strip-types", str(driver)],
            capture_output=True, text=True, timeout=120, env=env)
    finally:
        f4_proc.kill()
        f5_proc.kill()
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cases = [json.loads(line) for line in proc.stdout.splitlines()
             if line.startswith('{"case"')]
    by_case = {c["case"]: c["detail"] for c in cases}

    # F4: the far server's agent performed the effect on ITS machine (the
    # executor-fx dir stands in for the far machine's /workspace) — and
    # the report is the row detail with its echo
    assert (executor_fx / "f4-effect.txt").read_text() == "remote tool write"
    assert by_case["f4"]["actor"] == "f4-remote-tool-agent"
    assert by_case["f4"]["machine"] == "executor"
    assert by_case["f4"]["server"] == "toy-mcp-agent-http"
    assert by_case["f4"]["remote"] is True
    f4_did = by_case["f4"]["delegation_id"]
    # F5: the far agent performed the spawn on ITS machine
    assert (executor_fx / "f5-effect.txt").read_text().strip() \
        == "remote agent spawn"
    assert by_case["f5"]["actor"] == "f5-remote-agent"
    assert by_case["f5"]["machine"] == "executor"
    assert by_case["f5"]["server"] == "a2a-agent"
    f5_did = by_case["f5"]["delegation_id"]

    # the origin side's sent records: machine "origin", the remote
    # fixtures' channel/protocol/carrier shapes
    origin_records, problems = load_delegation_records(
        origin_dir / "delegation-records.jsonl")
    assert problems == []
    assert len(origin_records) == 2   # one sent line per remote action
    f4_sent = [r for r in origin_records if r["delegation_id"] == f4_did][0]
    f5_sent = [r for r in origin_records if r["delegation_id"] == f5_did][0]
    assert all(r["event"] == "sent" and r["machine"] == "origin"
               for r in origin_records)
    assert f4_sent["channel"] == "tool"
    assert f4_sent["protocol"] == "http"
    assert f4_sent["carrier"] == "http_header"
    assert f4_sent["to_actor"] == "f4-remote-tool-agent"
    assert f5_sent["channel"] == "network"
    assert f5_sent["protocol"] == "a2a"
    assert f5_sent["carrier"] == "queue_payload"
    assert f5_sent["to_actor"] == "f5-remote-agent"

    # the executor side's acceptance records: machine "executor", written
    # by the far servers into their OWN staging dir
    executor_records, problems = load_delegation_records(
        executor_dir / "delegation-records.jsonl")
    assert problems == []
    assert len(executor_records) == 2
    assert all(r["event"] == "accepted" and r["machine"] == "executor"
               for r in executor_records)

    # the runner's cross-host collection merges the two streams (the
    # same function run_one calls), and the chains build across the
    # boundary
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "delegation-records.jsonl").write_text(
        (origin_dir / "delegation-records.jsonl").read_text())
    run_mod = _load_module("run_remote", ROOT / "runner" / "run.py")
    # run_one passes the run id explicitly; the executor records carry it
    # (the request-carried x-inspection-run-id) and only THIS run's merge
    summary = run_mod.collect_executor_artifacts(run_dir, executor_dir,
                                                 map_events_here=False,
                                                 run_id="r-remote-branches")
    assert summary["records_merged"] == 2
    records, problems = load_delegation_records(
        run_dir / "delegation-records.jsonl")
    assert problems == []
    table = build_chains(records)
    assert table.problems == []
    for did in (f4_did, f5_did):
        res = trace_back([{"ts_epoch_ns": 1, "delegation_id": did}], table)
        assert res[0]["status"] == ATTRIBUTED
        assert res[0]["chain"] == [did]


def test_adapter_remote_branches_fail_loudly_without_the_addresses(tmp_path):
    """A remote-marked action with no remote address configured is a
    fixture-configuration mistake: the branch fails the action loudly
    (the f2Report error path keeps the echo), never silently performs
    the effect in-process."""
    node = subprocess.run(["which", "node"], capture_output=True,
                          text=True).stdout.strip()
    if not node:
        pytest.skip("node not available (the adapter is TypeScript)")
    origin_dir = tmp_path / "replay"
    origin_dir.mkdir()
    driver = tmp_path / "driver.ts"
    driver.write_text(_adapter_driver_source(origin_dir, UNSET_MAIN))
    env = dict(os.environ)
    env.update({"REPLAY_LOG_DIR": str(origin_dir),
                "INSPECTION_RUN_ID": "r-unset"})
    env.pop("F4_TOOL_SERVER_URL", None)
    env.pop("F5_AGENT_SERVER_URL", None)
    proc = subprocess.run(
        [node, "--experimental-strip-types", str(driver)],
        capture_output=True, text=True, timeout=60, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cases = [json.loads(line) for line in proc.stdout.splitlines()
             if line.startswith('{"case"')]
    unset = [c for c in cases if c["case"] == "unset"][0]
    assert "F4_TOOL_SERVER_URL" in unset["error"]
    # no hand-off ever happened: the check fires BEFORE the sent record
    # (a configuration mistake is not a taken-and-failed hand-off), so
    # no record stream exists and the error is the plain action error
    assert unset["report"] is None
    assert not (origin_dir / "delegation-records.jsonl").exists()
    assert not Path("/tmp/never-f4.txt").exists()


def test_a_failed_remote_call_keeps_the_hand_off_visible(tmp_path):
    """A remote hand-off whose transport failed (the far machine
    unreachable, the connection refused) is not a LOST hand-off: the
    sent record was written before the call, the error path keeps a
    report-shaped detail with the echo, and the collected chain shows
    the hand-off as sent-but-never-accepted — a finding, never silence."""
    node = subprocess.run(["which", "node"], capture_output=True,
                          text=True).stdout.strip()
    if not node:
        pytest.skip("node not available (the adapter is TypeScript)")
    origin_dir = tmp_path / "replay"
    origin_dir.mkdir()
    driver = tmp_path / "driver.ts"
    dead = _free_port()   # nothing listens here: the connection is refused
    driver.write_text(_adapter_driver_source(origin_dir, """
  try {
    j({ case: "f5-dead", detail: await delegateToRemoteAgent({
        id: "a031", class: "process_spawn", op: "exec", kind: "spawn",
        cmd: ["/bin/echo", "never"], performed_by: "remote-agent" }) });
  } catch (e) {
    j({ case: "f5-dead", error: String(e && e.message || e),
        report: e.f2Report ?? null });
  }
"""))
    env = dict(os.environ)
    env.update({"REPLAY_LOG_DIR": str(origin_dir),
                "INSPECTION_RUN_ID": "r-dead",
                "F5_AGENT_SERVER_URL": f"http://127.0.0.1:{dead}"})
    proc = subprocess.run(
        [node, "--experimental-strip-types", str(driver)],
        capture_output=True, text=True, timeout=60, env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    case = [json.loads(line) for line in proc.stdout.splitlines()
            if line.startswith('{"case"')][0]

    # the sent record exists (written BEFORE the call) — the hand-off is
    # visible as taken-attempted; the error keeps a report-shaped detail
    # with the echo (machine "executor": the far side's claim shape, even
    # though no far side ever answered)
    assert case["report"]["status"] == "error"
    did = case["report"]["delegation_id"]
    assert did
    assert case["report"]["actor"] == "f5-remote-agent"
    records, problems = load_delegation_records(
        origin_dir / "delegation-records.jsonl")
    assert problems == []
    assert records[0]["event"] == "sent"
    assert records[0]["machine"] == "origin"
    assert records[0]["delegation_id"] == did
    # the chain is honest: sent, never accepted — a problem the chain
    # table reports, never silently merged away
    table = build_chains(records)
    assert table.problems == [f"{did}: sent but never accepted"]


# --- the manifest's delegation section over a cross-machine run --------------------

def test_delegation_section_over_a_cross_machine_run(tmp_path):
    """The execution manifest's delegation section over a synthetic F4
    run: the collected stream carries BOTH machines' records (the
    origin's sent line, the executor's accepted line), the per-action
    trace-back attributes through the exact echo, and the effect-observed
    question reads the far server's per-effect claim."""
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    (out_dir / "delegation-records.jsonl").write_text(
        _records_text(f4_pair("d-f4-1")))
    (out_dir / "replay-result.json").write_text(json.dumps({
        "results": [
            {"id": "a041", "status": "ok", "started_epoch_ns": 1,
             "detail": {"status": "ok", "delegation_id": "d-f4-1",
                        "actor": "f4-remote-tool-agent",
                        "machine": "executor",
                        "results": [{"id": "a041", "status": "ok",
                                     "detail": {"bytes": 13}}],
                        "server": "toy-mcp-agent-http", "remote": True}},
        ]}))
    compiled_dir = out_dir / "compiled-trace"
    compiled_dir.mkdir()
    (compiled_dir / "baseline-f4.compiled.json").write_text(json.dumps(
        {"actions": [{"id": aid, "performed_by": "remote-tool-agent"}
                     for aid in DELEGATED_IDS]}))

    section = execute_mod._delegation_section({}, out_dir, _yaml(BASELINE))
    assert section is not None
    assert section["chain_problems"] == []
    a041 = section["per_action"]["a041"]
    assert a041["delegated"] is True
    assert a041["status"] == ATTRIBUTED
    assert a041["method"] == "id-echo"
    assert a041["chain"] == ["d-f4-1"]
    assert a041["effect_observed"] == "true"   # the far server's claim


# --- the runner's cross-host collection ---------------------------------------------

def test_collect_executor_artifacts_merges_records_and_keeps_events_separate(tmp_path):
    """The two-host collection: the executor host's pulled directory
    merges its delegation records into the run's stream (the chain joins
    on the delegation id), and the far machine's Tracee events are
    retained as SEPARATE artifacts — never pooled into the origin host's
    counts. A missing directory raises (a config mistake, never a silent
    skip); a directory without kernel events collects the records only."""
    run_mod = _load_module("run_collect", ROOT / "runner" / "run.py")
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    # the origin side's stream (run_one copies it before the collection)
    (out_dir / "delegation-records.jsonl").write_text(_records_text([
        handoff_record("sent", RID1, "d-x-1", channel="tool",
                       protocol="http", carrier="http_header",
                       from_actor="pi-root",
                       to_actor="f4-remote-tool-agent",
                       stream_id="pi-root", machine="origin")]))

    # the executor host's pulled artifacts: its records + its own
    # Tracee capture (raw docker-logs JSON, as pulled on the far host).
    # The far staging file is PERSISTENT across runs: it still carries a
    # PREVIOUS run's acceptance (run_id r-old-run) — only the current
    # run's records may merge (the run id travels with the request)
    executor_dir = tmp_path / "executor-artifacts"
    executor_dir.mkdir()
    (executor_dir / "delegation-records.jsonl").write_text(_records_text([
        handoff_record("accepted", RID2, "d-old-9", channel="tool",
                       protocol="http", carrier="http_header",
                       from_actor="pi-root",
                       to_actor="f4-remote-tool-agent",
                       stream_id="toy-mcp-agent-http-1",
                       machine="executor", run_id="r-old-run"),
        handoff_record("accepted", RID2, "d-x-1", channel="tool",
                       protocol="http", carrier="http_header",
                       from_actor="pi-root",
                       to_actor="f4-remote-tool-agent",
                       stream_id="toy-mcp-agent-http-1",
                       machine="executor")]))
    (executor_dir / "tracee-events.json").write_text("{}\n")

    summary = run_mod.collect_executor_artifacts(out_dir, executor_dir,
                                                map_events_here=False,
                                                run_id="r-remote")
    assert summary["records_merged"] == 1
    assert summary["records_skipped_other_run"] == 1   # the previous run's
    assert "tracee-events-executor" in summary["artifacts"]
    assert "mapped-actions-executor" not in summary["artifacts"]

    # the merged stream: both machines' records, one chain, clean
    records, problems = load_delegation_records(
        out_dir / "delegation-records.jsonl")
    assert problems == []
    assert {r["machine"] for r in records} == {"origin", "executor"}
    table = build_chains(records)
    assert table.problems == []
    assert table.accepted["d-x-1"] == "f4-remote-tool-agent"
    # the far machine's kernel observations are retained SEPARATELY (the
    # origin run's mapped-actions.jsonl is untouched — counts are never
    # pooled across machines)
    assert (out_dir / "tracee-events-executor.json").is_file()
    assert not (out_dir / "mapped-actions.jsonl").exists()
    assert (out_dir / "executor-collection.json").is_file()

    # a missing directory raises, never silently skips
    with pytest.raises(RuntimeError):
        run_mod.collect_executor_artifacts(out_dir,
                                           tmp_path / "nowhere",
                                           map_events_here=False)


def test_collect_executor_artifacts_maps_the_far_events(tmp_path):
    """With mapping on, the far machine's Tracee capture maps through the
    SAME sensor mapping rules into its own mapped-actions file (a
    separate artifact: the executor host's kernel view of the remote
    agents' effects)."""
    run_mod = _load_module("run_collect_map", ROOT / "runner" / "run.py")
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    executor_dir = tmp_path / "executor-artifacts"
    executor_dir.mkdir()
    (executor_dir / "tracee-events.json").write_text(
        json.dumps({"ts": 1, "event": "execve"}) + "\n")
    summary = run_mod.collect_executor_artifacts(out_dir, executor_dir)
    assert summary["records_merged"] == 0
    assert "mapped-actions-executor" in summary["artifacts"]
    assert (out_dir / "mapped-actions-executor.jsonl").is_file()


# --- the two-host compose topology ----------------------------------------------------

def test_the_executor_compose_stack_is_its_own_project():
    """The executor host runs its own compose stack: the two remote
    servers + the far machine's own network target + its OWN Tracee
    sensor (the profile pattern, like the origin host's), publishing the
    hand-off ports the origin's adapter POSTs to."""
    doc = _yaml(COMPOSE / "executor.yaml")
    assert doc["name"] == "inspection-executor"
    services = doc["services"]
    assert set(services) == {"f4-tool-server", "a2a-agent",
                             "net-peer", "tracee"}
    assert "sensor" in services["tracee"]["profiles"]
    assert services["tracee"]["privileged"] is True
    for svc, port in (("f4-tool-server", "8091"), ("a2a-agent", "8092")):
        published = services[svc]["ports"]
        assert any(p.startswith(f"{port}:") for p in published), \
            f"{svc} must publish its hand-off port"
        assert services[svc]["environment"]["REPLAY_LOG_DIR"] \
            == "/workspace/replay"
    # no harness service on the executor host — the harness never runs
    # where the remote effects occur
    assert "pi" not in services and "openclaw" not in services


def test_the_origin_overlay_adds_only_the_remote_addresses():
    """The origin-side overlay is additive: it adds ONLY the two remote
    hand-off env vars to the pi service (built from
    GUARDSCOPE_EXECUTOR_HOST), and the single-machine bases are
    untouched — t0.yaml carries no remote-fixture vocabulary."""
    overlay = _yaml(COMPOSE / "t0-remote.yaml")
    assert overlay["name"] == "inspection-t0"
    assert set(overlay["services"]) == {"pi"}
    env = overlay["services"]["pi"]["environment"]
    assert set(env) == {"F4_TOOL_SERVER_URL", "F5_AGENT_SERVER_URL"}
    assert "GUARDSCOPE_EXECUTOR_HOST" in env["F4_TOOL_SERVER_URL"]
    assert "GUARDSCOPE_EXECUTOR_HOST" in env["F5_AGENT_SERVER_URL"]
    for base in ("t0.yaml", "t1.yaml", "t2.yaml", "t3.yaml", "t4.yaml",
                 "t5.yaml", "t6.yaml", "t7.yaml"):
        text = (COMPOSE / base).read_text()
        assert "F4_TOOL_SERVER_URL" not in text, base
        assert "F5_AGENT_SERVER_URL" not in text, base
        assert "GUARDSCOPE_EXECUTOR_HOST" not in text, base


# --- rework regression tests (echo, timeout, routing, run_one, reconcile) ----------
#
# One test per checker finding, same offline style as above (real local
# servers where the finding was reproduced; stubs only where the finding
# needs a hostile/remote misbehavior no real fixture server produces).

import hashlib  # noqa: E402
import threading  # noqa: E402
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer  # noqa: E402

sys.path.insert(0, str(ROOT / "tests"))
import test_reconcile as t_reconcile  # noqa: E402


def _node():
    node = subprocess.run(["which", "node"], capture_output=True,
                          text=True).stdout.strip()
    if not node:
        pytest.skip("node not available (the adapter is TypeScript)")
    return node


def _run_driver(tmp_path, name, main_body, env_extra,
                timeout_s=60, origin="replay"):
    """Write the adapter driver, run it under node, return the parsed
    console cases."""
    origin_dir = tmp_path / origin
    origin_dir.mkdir(parents=True, exist_ok=True)
    driver = tmp_path / name
    driver.write_text(_adapter_driver_source(origin_dir, main_body))
    env = dict(os.environ)
    env.update({"REPLAY_LOG_DIR": str(origin_dir),
                "INSPECTION_RUN_ID": "r-rework"})
    env.update(env_extra)
    proc = subprocess.run([_node(), "--experimental-strip-types", str(driver)],
                          capture_output=True, text=True, timeout=timeout_s,
                          env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return [json.loads(line) for line in proc.stdout.splitlines()
            if line.startswith('{"case"')]


def _sent_delegation_id(origin_dir):
    records, problems = load_delegation_records(
        Path(origin_dir) / "delegation-records.jsonl")
    assert problems == []
    assert records and records[0]["event"] == "sent"
    return records[0]["delegation_id"]


class _StubReportHandler(BaseHTTPRequestHandler):
    """A hostile far server: answers with a report the adapter must NOT
    trust (wrong echo, missing echo, or not a report at all)."""

    mode = "wrong-echo"
    protocol_version = "HTTP/1.1"

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        did = self.headers.get("x-inspection-delegation-id")
        if self.mode == "wrong-echo":
            doc = {"status": "ok", "delegation_id": "d-not-mine",
                   "results": []}
        elif self.mode == "no-echo-error":
            doc = {"status": "error", "error": "boom", "results": []}
        else:   # "malformed": a valid JSON document that is not a report
            doc = {"hello": "world"}
        body = json.dumps(doc).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):  # console noise stays off the wire
        pass


def _stub_server(mode):
    handler = type("Stub", (_StubReportHandler,), {"mode": mode})
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def _f4_action_js(path):
    """One remote-marked file-write action, as the driver's JS source."""
    return ('{ id: "a041", class: "file_write", op: "write", '
            'kind: "file_write", path: %s, data: "rework write", '
            'append: false, performed_by: "remote-tool-agent" }'
            % json.dumps(str(path)))


@pytest.mark.parametrize("mode,needle", [
    ("wrong-echo", "delegation id mismatch"),
    ("no-echo-error", "delegation id mismatch"),
    ("malformed", "unreadable report"),
])
def test_a_response_without_a_valid_echo_is_a_visible_error(tmp_path, mode,
                                                            needle):
    """Fix 1 (echo validation): a report whose delegation_id does not echo
    the SENT id — wrong, missing, or not a report at all — is a visible
    error, never a silent acceptance; the error row KEEPS the sent
    record's echo (and the untrusted report rides it as evidence), so
    the trace-back stays resolvable and the mismatch is named."""
    effect = tmp_path / "never.txt"
    srv = _stub_server(mode)
    try:
        cases = _run_driver(
            tmp_path, "driver-echo.ts", f"""
  try {{
    j({{ case: "f4", detail: await delegateToRemoteTool({_f4_action_js(effect)}) }});
  }} catch (e) {{
    j({{ case: "f4", error: String(e && e.message || e),
        report: e.f2Report ?? null }});
  }}
""", {"F4_TOOL_SERVER_URL":
      f"http://127.0.0.1:{srv.server_address[1]}"})
    finally:
        srv.shutdown()
        srv.server_close()
    case = cases[0]
    assert "detail" not in case        # never accepted
    assert needle in case["error"]
    # the sent record was written BEFORE the call; the error row keeps ITS
    # echo (never the untrusted report's claim, never nothing)
    did = _sent_delegation_id(tmp_path / "replay")
    assert case["report"]["status"] == "error"
    assert case["report"]["delegation_id"] == did
    if mode == "wrong-echo":
        # the mismatched report is retained as evidence, not trusted
        assert case["report"]["server_report"]["delegation_id"] == "d-not-mine"
    if mode == "no-echo-error":
        # a report that says error but carries no echo still loses nothing:
        # the row keeps the sent id AND the far side's error claim (the
        # untrusted report rides the row as evidence)
        assert case["report"]["server_report"]["error"] == "boom"
        assert case["report"]["server_report"]["status"] == "error"
    # no effect was performed in-process either
    assert not effect.exists()


class _StalledBodyHandler(BaseHTTPRequestHandler):
    """Sends the response headers and then stalls the body: the old
    timeout (fetch headers only) never fired for this."""

    protocol_version = "HTTP/1.1"

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", "512")   # promised, never sent
        self.end_headers()
        self.wfile.flush()
        time.sleep(30)     # far past the action timeout

    def log_message(self, fmt, *args):
        pass


def test_a_stalled_response_body_cannot_outlive_the_action_timeout(tmp_path):
    """Fix 2 (full-cycle timeout): a server that sends the headers and
    stalls the body holds the hand-off only until the action timeout —
    the deadline bounds fetch + body read + parse, the driver finishes,
    and the error row keeps the sent record's echo (the hand-off was
    made; the response never arrived)."""
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _StalledBodyHandler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    effect = tmp_path / "never.txt"
    try:
        started = time.monotonic()
        cases = _run_driver(
            tmp_path, "driver-stall.ts", f"""
  try {{
    j({{ case: "f4", detail: await delegateToRemoteTool({_f4_action_js(effect)}) }});
  }} catch (e) {{
    j({{ case: "f4", error: String(e && e.message || e),
        report: e.f2Report ?? null }});
  }}
""", {"F4_TOOL_SERVER_URL":
      f"http://127.0.0.1:{srv.server_address[1]}",
      # the test runs the deployed 20s logic on a short deadline
      "INSPECTION_ACTION_TIMEOUT_MS": "1500"},
            timeout_s=30)
        elapsed = time.monotonic() - started
    finally:
        srv.shutdown()
        srv.server_close()
    case = cases[0]
    assert "detail" not in case
    assert "timeout" in case["error"]
    assert elapsed < 10, f"the stalled body held the replay for {elapsed:.1f}s"
    # the hand-off is visible (sent, never answered) with its echo on the
    # error row — the response never arrived, the id is not lost
    did = _sent_delegation_id(tmp_path / "replay")
    assert case["report"]["delegation_id"] == did
    assert case["report"]["status"] == "error"


class _AllowAllGateway:
    """The intercept contract gateway/server.py's handler calls (the real
    engine needs agent_os; the decision path is what matters here)."""

    def intercept_tool_call(self, agent_id, tool_name, arguments):
        return (True, "in allowed_tools (test policy)")


def test_with_a_gateway_configured_the_hand_off_crosses_it(tmp_path,
                                                           monkeypatch):
    """Fix 4 (gateway routing): with GATEWAY_URL set the remote hand-off
    crosses the gateway — a tools/call the gateway PROXIES to the remote
    server (the same pattern as the http tool calls) — instead of going
    direct. The gateway decides (a decision record is written), the
    request reaches the remote server unchanged (the chain ids ride the
    headers), the far effect happens on the far machine, and the report
    round-trips back through the gateway's result text."""
    executor_dir = tmp_path / "executor-replay"
    executor_fx = tmp_path / "executor-fx"
    executor_fx.mkdir(parents=True)
    executor_dir.mkdir(parents=True)
    effect = executor_fx / "f4-gateway.txt"
    port = _free_port()
    f4_proc, f4_url = _start_server(
        [sys.executable, "-u", str(F4_SERVER)], port, executor_dir,
        "F4_LISTEN_PORT")
    try:
        # the gateway needs the remote route's address at import time
        monkeypatch.setenv("F4_TOOL_SERVER_URL", f4_url)
        gateway_mod = _load_module("gateway_remote_route",
                                   ROOT / "gateway" / "server.py")
        gateway_logs = tmp_path / "gateway-logs"
        gateway_logs.mkdir()
        srv = gateway_mod.ThreadingHTTPServer(("127.0.0.1", 0),
                                              gateway_mod.Handler)
        srv.gateway = _AllowAllGateway()
        srv.native_writer = gateway_mod.NativeRecordWriter(gateway_logs)
        srv.policy_info = {"policy_id": "test", "policy_version": "1",
                           "policy_hash": "0" * 64}
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        cases = _run_driver(
            tmp_path, "driver-gateway.ts", f"""
  j({{ case: "f4", detail: await delegateToRemoteTool({_f4_action_js(effect)}) }});
""", {"F4_TOOL_SERVER_URL": f4_url,
      "GATEWAY_URL": f"http://127.0.0.1:{srv.server_address[1]}"})
        srv.shutdown()
        srv.server_close()
    finally:
        f4_proc.kill()
        f4_proc.wait()
    # the far effect happened (through the gateway's proxy, on the far
    # machine's filesystem), and the row detail echoes the hand-off
    assert effect.read_text() == "rework write"
    case = cases[0]["detail"]
    assert case["status"] == "ok"
    assert case["server"] == "toy-mcp-agent-http"
    did = case["delegation_id"]
    assert did
    # the gateway SAW the call: one native decision record for the remote
    # hand-off route, echoing the action id off the tools/call _meta
    decisions = [json.loads(l)
                 for l in (gateway_logs / "decision-records.jsonl")
                 .read_text().splitlines() if l.strip()]
    assert len(decisions) == 1
    assert decisions[0]["tool"] == "f4_remote_task"
    assert decisions[0]["decision"] == "allow"
    assert decisions[0]["action_id"] == "a041"
    assert decisions[0]["correlation_transport"] == "mcp_meta"
    # the origin side's sent record exists (machine "origin")
    records, problems = load_delegation_records(
        tmp_path / "replay" / "delegation-records.jsonl")
    assert problems == []
    assert records[0]["delegation_id"] == did
    assert records[0]["machine"] == "origin"
    # the far server's acceptance (machine "executor") chains onto it
    far_records, problems = load_delegation_records(
        executor_dir / "delegation-records.jsonl")
    assert problems == []
    assert far_records[0]["delegation_id"] == did
    assert far_records[0]["machine"] == "executor"


def _t4_entry_main(f4_action_js):
    return f"""
  // the fake pi: the extension entry registers the two remote hand-off
  // TOOLS (the harness tool pipeline's tools) and its hooks
  const calls = {{ tools: [], hooks: [], providers: [], commands: [] }};
  _entry({{
    registerTool: (t) => calls.tools.push(t),
    on: (ev, h) => calls.hooks.push(ev),
    registerProvider: (n, p) => calls.providers.push(n),
    registerCommand: (n, c) => calls.commands.push(n),
  }});
  j({{ case: "registered", tools: calls.tools.map(t => t.name),
      hooks: calls.hooks, providers: calls.providers }});
  // the scripted provider's selection: the remote hand-offs are TOOL
  // CALLS (t4ToolCalls), not process-phase bypass actions
  j({{ case: "selected", tools: t4ToolCalls({{ actions: [
      {{ id: "a041", class: "file_write", performed_by: "remote-tool-agent" }},
      {{ id: "a031", class: "process_spawn", performed_by: "remote-agent" }},
  ] }}).map(c => c.tool) }});
  // the registered tool's execute performs the hand-off (the pipeline's
  // tool execution path); in T4 mode the BRANCH writes no dispatch
  // record of its own — the pipeline's tool_result hook writes the one
  // attempt record (carrier "none")
  const f4 = calls.tools.find(t => t.name === "f4_remote_tool");
  j({{ case: "execute", detail: await f4.execute("tc-1", {{ action: {f4_action_js} }}) }});
  // the failed hand-off's report (with the echo) rides the call's error
  // result: the pipeline's row keeps the echo exactly like the T0 loop
  const f5 = calls.tools.find(t => t.name === "f5_remote_agent");
  const res = await f5.execute("tc-2", {{ action: {{
      id: "a031", class: "process_spawn", op: "exec", kind: "spawn",
      cmd: ["/bin/echo", "never"], performed_by: "remote-agent" }} }});
  j({{ case: "f5-dead", isError: res.isError === true,
      report: JSON.parse(res.content[0].text) }});
"""


def test_t4_mode_passes_the_remote_hand_offs_through_the_tool_pipeline(tmp_path):
    """Fix 4 (harness tool pipeline): with T4_MODE set the remote call is
    a REAL tool call — the two hand-offs are harness tools the scripted
    provider selects (t4ToolCalls), their execute performs the hand-off,
    and a failed hand-off's report (with the echo) rides the call's error
    result so the pipeline's row keeps it."""
    executor_dir = tmp_path / "executor-replay"
    executor_fx = tmp_path / "executor-fx"
    executor_fx.mkdir(parents=True)
    executor_dir.mkdir(parents=True)
    effect = executor_fx / "f4-pipeline.txt"
    port = _free_port()
    f4_proc, f4_url = _start_server(
        [sys.executable, "-u", str(F4_SERVER)], port, executor_dir,
        "F4_LISTEN_PORT")
    dead = _free_port()   # nothing listens: the F5 hand-off fails
    try:
        cases = _run_driver(
            tmp_path, "driver-t4.ts", _t4_entry_main(_f4_action_js(effect)),
            {"T4_MODE": "1",
             "F4_TOOL_SERVER_URL": f4_url,
             "F5_AGENT_SERVER_URL": f"http://127.0.0.1:{dead}"},
            timeout_s=90)
    finally:
        f4_proc.kill()
        f4_proc.wait()
    by_case = {c["case"]: c for c in cases}
    # the two remote hand-off tools are registered (the pipeline's tools)
    assert set(by_case["registered"]["tools"]) == \
        {"f4_remote_tool", "f5_remote_agent"}
    assert "tool_call" in by_case["registered"]["hooks"]
    # the scripted provider selects BOTH hand-offs as tool calls
    assert by_case["selected"]["tools"] == \
        ["f4_remote_tool", "f5_remote_agent"]
    # the F4 tool's execute performed the hand-off on the far machine; the
    # T4 branch adds no dispatch record of its own (the pipeline's
    # tool_result hook writes the single attempt record)
    assert effect.read_text() == "rework write"
    report = json.loads(by_case["execute"]["detail"]["content"][0]["text"])
    assert report["status"] == "ok"
    assert report["delegation_id"]
    assert not (tmp_path / "replay" / "dispatch-records.jsonl").exists()
    # the failed F5 hand-off keeps its echo on the pipeline's error result
    f5 = by_case["f5-dead"]
    assert f5["isError"] is True
    assert f5["report"]["delegation_id"]
    assert f5["report"]["status"] == "error"


def _f4_origin_stream():
    """The origin host's kernel view of a SUCCESSFUL baseline-f4 run: the
    six remote-performed effects are ABSENT (they happened on the
    executor host); the outer hand-off connects are ordinary unmapped
    socket churn. Built from the correct pi stream, same probe shape the
    checker reproduced the finding with."""
    stream = []
    for r in t_reconcile.correct_pi_stream():
        cls = r.get("class")
        detail = r.get("detail") or {}
        if cls == "direct_network":
            continue   # a021/a022: performed on the executor host
        if cls == "process_spawn" and detail.get("target") in ("/bin/sh",
                                                              "/bin/echo"):
            continue   # a031/a032: performed on the executor host
        if cls == "file_write" and detail.get("target") in (
                "/workspace/out/b.txt", "/workspace/out/c.log"):
            continue   # a041/a042: performed on the executor host
        stream.append(r)
    # the outer hand-off connects (8091/8092): origin-side kernel visible,
    # unmapped by the port-based rules (unrelated socket churn — retained
    # as noise, never a measured call)
    stream += [
        t_reconcile.rec("unmapped", "connect", 25_000_000,
                       detail={"port": 8091, "transport": "tcp"}),
        t_reconcile.rec("unmapped", "connect", 26_000_000,
                       detail={"port": 8092, "transport": "tcp"}),
    ]
    return stream


def _f4_origin_logs():
    """The origin host's target logs: the origin net-peer saw nothing (the
    delegated connects land on the EXECUTOR host's net-peer)."""
    return [l for l in t_reconcile.target_logs()
            if l.get("target") != "net-peer"]


def test_a_remote_fixture_run_reconciles_clean_on_the_origin_host():
    """Fix 5 (workload-aware reconciliation): remote-performed actions
    produce NO origin-host kernel effects BY DESIGN — R2/R3 treat them as
    expected absent (not failures), R5 counts them effective on the
    replay report (the far server's per-effect claim), and the successful
    F4-shaped origin stream reconciles clean with the spec's ground truth."""
    spec = t_reconcile.rc.load_spec(
        ROOT / "trace" / "traces" / "baseline-f4.yaml")
    profile = t_reconcile.rc.load_profile(
        ROOT / "runner" / "profiles" / "pi.yaml")
    report = t_reconcile.rc.Reconciler(
        spec, profile, t_reconcile.replay_result(), _f4_origin_stream(),
        _f4_origin_logs(), t_reconcile.CONTAINER, design="t0").run()
    assert report["status"] == "pass", \
        [c for c in report["checks"] if c["status"] == "fail"]
    assert report["effective_counts"] == t_reconcile.GROUND_TRUTH
    # the expected-absent model is explicit per class, not a silent skip
    kernel = report["kernel"]["per_class"]
    assert kernel["direct_network"]["remote_expected_absent"] == \
        ["a021", "a022"]
    assert kernel["process_spawn"]["remote_expected_absent"] == \
        ["a031", "a032"]
    assert kernel["file_write"]["remote_expected_absent"] == \
        ["a041", "a042"]
    assert "remote-expected-absent" in \
        kernel["direct_network"]["evidence"]
    # the outer hand-off connects are retained as unrelated noise, not
    # leftovers and not measured calls
    assert report["leftovers"] == []


def test_the_same_stream_without_the_remote_markings_still_fails():
    """Fix 5, negative control: the tolerance is workload-aware, not
    blanket — the SAME stream reconciled against the unmarked baseline
    (the six effects genuinely missing on this host) still fails."""
    profile = t_reconcile.rc.load_profile(
        ROOT / "runner" / "profiles" / "pi.yaml")
    report = t_reconcile.rc.Reconciler(
        t_reconcile.SPEC, profile, t_reconcile.replay_result(),
        _f4_origin_stream(), _f4_origin_logs(),
        t_reconcile.CONTAINER, design="t0").run()
    assert report["status"] == "fail"
    failed = {c["id"] for c in report["checks"] if c["status"] == "fail"}
    assert {"R3-kernel-direct_network", "R3-kernel-process_spawn",
            "R3-kernel-file_write", "R5-effective-counts"} <= failed


def test_run_one_collects_both_hosts_evidence_on_a_replay_failure(
        tmp_path, monkeypatch):
    """Fix 3 (replay failure is not a run abort): a failed remote action
    must NOT abort run_one before the run directory exists — the run
    continues, the adapter's echo and the executor's acceptance reach the
    retained run artifacts (both hosts), and the run completes with a
    failure verdict that names the failed actions."""
    run_mod = _load_module("run_rework", ROOT / "runner" / "run.py")
    staging = tmp_path / "staging-pi"
    staging.mkdir(parents=True)
    run_id = "r-failed-remote"
    # the replay result: one remote action failed (the error row KEEPS the
    # hand-off's echo — the pattern the adapter produces), the rest ran ok
    spec = _yaml(ROOT / "trace" / "traces" / "baseline-f4.yaml")
    rows = []
    for a in spec["actions"]:
        if a["id"] == "a041":
            rows.append({
                "id": a["id"], "class": a["class"], "op": a["op"],
                "started_ns": 1, "ended_ns": 2, "started_epoch_ns": 1,
                "status": "error",
                "detail": {"status": "error",
                           "delegation_id": "d-failed-1",
                           "actor": "f4-remote-tool-agent",
                           "machine": "executor", "results": [],
                           "error": "f4 tool server (HTTP 404)"},
                "error": "f4 tool server (HTTP 404)"})
        else:
            rows.append({
                "id": a["id"], "class": a["class"], "op": a["op"],
                "started_ns": 1, "ended_ns": 2, "started_epoch_ns": 1,
                "status": "ok", "detail": None, "error": None})
    replay_result = {"ok": False, "executed": len(rows), "failed": 1,
                     "window_ns": {"start": 1, "end": 2},
                     "window_epoch_ns": {"start": 1, "end": 2},
                     "replay_log": "replay-log.jsonl",
                     "results": rows}
    # the origin staging volume: the replay log, the dispatch records and
    # the delegation stream (the adapter's sent record with its echo)
    (staging / "replay-log.jsonl").write_text("{}\n")
    (staging / "dispatch-records.jsonl").write_text("{}\n")
    (staging / "delegation-records.jsonl").write_text(_records_text([
        handoff_record("sent", RID1, "d-failed-1", channel="tool",
                       protocol="http", carrier="http_header",
                       from_actor="pi-root",
                       to_actor="f4-remote-tool-agent",
                       stream_id="pi-root", run_id=run_id,
                       machine="origin")]))
    # the executor host's pulled directory: the far server's acceptance
    # for the same hand-off (the chain evidence that must be retained)
    executor_dir = tmp_path / "executor-artifacts"
    executor_dir.mkdir()
    (executor_dir / "delegation-records.jsonl").write_text(_records_text([
        handoff_record("accepted", RID2, "d-failed-1", channel="tool",
                       protocol="http", carrier="http_header",
                       from_actor="pi-root",
                       to_actor="f4-remote-tool-agent",
                       stream_id="toy-mcp-agent-http-1", run_id=run_id,
                       machine="executor")]))
    # the docker-bound steps are substituted (the failure-gate change is
    # what this test measures; the containers are compose-declared only)
    monkeypatch.setattr(run_mod, "trigger_replay",
                        lambda *a, **k: (replay_result,
                                         staging / "replay-log.jsonl"))
    monkeypatch.setattr(run_mod, "chown_target_logs", lambda *a, **k: None)
    monkeypatch.setattr(run_mod, "container_id", lambda *a, **k: None)

    def _fake_pull_target_logs(out_dir, cfg):
        Path(out_dir).mkdir(parents=True, exist_ok=True)   # empty logs
        return Path(out_dir)

    monkeypatch.setattr(run_mod, "pull_target_logs", _fake_pull_target_logs)
    monkeypatch.setenv("GUARDSCOPE_EXECUTOR_ARTIFACTS", str(executor_dir))
    runs_dir = tmp_path / "runs"
    summary = run_mod.run_one("pi", run_id, runs_dir, design="t0",
                              sensor=False, workdir=tmp_path,
                              workload="baseline-f4")
    # the run COMPLETED with a failure verdict naming the failed action —
    # no abort, no lost evidence
    assert summary["status"] == "fail"
    assert summary["replay_failed_actions"] == ["a041"]
    out_dir = runs_dir / run_id
    assert (out_dir / "replay-result.json").is_file()
    assert (out_dir / "dispatch-records.jsonl").is_file()
    # BOTH hosts' evidence reached the retained run artifacts: the origin
    # sent record (with the failed hand-off's echo) AND the executor's
    # acceptance, merged into one chain by the collection
    records, problems = load_delegation_records(
        out_dir / "delegation-records.jsonl")
    assert problems == []
    assert [r["event"] for r in records] == ["sent", "accepted"]
    assert records[0]["delegation_id"] == "d-failed-1"
    assert {r["machine"] for r in records} == {"origin", "executor"}
    collection = json.loads(
        (out_dir / "executor-collection.json").read_text())
    assert collection["records_merged"] == 1
    # the run record + manifest are retained (the failure is a recorded
    # verdict, not a traceback)
    assert (out_dir / "run-record.json").is_file()
    assert (out_dir / "manifest.json").is_file()
    replay = json.loads((out_dir / "replay-result.json").read_text())
    a041 = next(r for r in replay["results"] if r["id"] == "a041")
    assert a041["status"] == "error"
    assert a041["detail"]["delegation_id"] == "d-failed-1"


def test_collect_remote_updates_the_manifest_hashes(tmp_path):
    """Fix 8 (manifest hashes): the advertised post-run collect-remote
    command keeps the run's manifest true — the merged delegation stream
    and the executor host's kernel artifacts are (re)hashed, and an
    existing artifact's stale hash is recomputed."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    existing = run_dir / "replay-result.json"
    existing.write_text("{}\n")
    (run_dir / "manifest.json").write_text(json.dumps({
        "schema": 1, "run_id": run_dir.name,
        "artifacts": {"replay-result": {"path": str(existing),
                                        "sha256": "stale-sentinel",
                                        "bytes": 3}}}) + "\n")
    executor_dir = tmp_path / "executor-artifacts"
    executor_dir.mkdir()
    (executor_dir / "delegation-records.jsonl").write_text(_records_text([
        handoff_record("accepted", RID2, "d-m-1", channel="tool",
                       protocol="http", carrier="http_header",
                       from_actor="pi-root",
                       to_actor="f4-remote-tool-agent",
                       stream_id="s", machine="executor",
                       run_id=run_dir.name)]))
    (executor_dir / "tracee-events.json").write_text("{}\n")
    (run_dir / "delegation-records.jsonl").write_text(_records_text([
        handoff_record("sent", RID1, "d-m-1", channel="tool",
                       protocol="http", carrier="http_header",
                       from_actor="pi-root",
                       to_actor="f4-remote-tool-agent",
                       stream_id="pi-root", machine="origin",
                       run_id=run_dir.name)]))
    proc = subprocess.run(
        [sys.executable, str(ROOT / "runner" / "run.py"), "collect-remote",
         "--run-dir", str(run_dir), "--executor-dir", str(executor_dir),
         "--no-map"], capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    summary = json.loads(proc.stdout)
    assert summary["manifest_updated"] is True
    manifest = json.loads((run_dir / "manifest.json").read_text())
    arts = manifest["artifacts"]
    # the pre-existing artifact's stale hash is recomputed
    assert arts["replay-result"]["sha256"] == \
        hashlib.sha256(existing.read_bytes()).hexdigest()
    # the merged delegation stream is hashed at its NEW content
    merged = run_dir / "delegation-records.jsonl"
    assert arts["delegation-records"]["sha256"] == \
        hashlib.sha256(merged.read_bytes()).hexdigest()
    # the executor host's kernel artifact is hashed too
    far = run_dir / "tracee-events-executor.json"
    assert arts["tracee-events-executor"]["sha256"] == \
        hashlib.sha256(far.read_bytes()).hexdigest()


@pytest.mark.parametrize("hop", ["0", "-1", "banana"])
def test_f4_refuses_an_invalid_hop(tmp_path, hop):
    """Fix 6 (hop validation, F4): the hop is a chain-position integer
    >= 1 (delegation-record/1); a 0/negative/non-integer hop is refused
    BEFORE anything is performed or recorded — no schema-invalid
    acceptance, no effects."""
    log_dir = tmp_path / "executor-replay"
    port = _free_port()
    proc, url = _start_server([sys.executable, "-u", str(F4_SERVER)],
                              port, log_dir, "F4_LISTEN_PORT")
    try:
        code, report = _post(f"{url}/task", {
            "steps": [{"id": "a041", "kind": "file_write",
                       "path": str(tmp_path / "never.txt"),
                       "data": "x"}]},
            headers={"x-inspection-delegation-id": "d-hop-1",
                     "x-inspection-hop": hop})
    finally:
        proc.kill()
        proc.wait()
    assert code == 400
    assert "invalid hop" in report["error"]
    assert not (tmp_path / "never.txt").exists()
    assert not (log_dir / "delegation-records.jsonl").exists()


@pytest.mark.parametrize("hop", [0, -1, "banana"])
def test_f5_refuses_an_invalid_hop(tmp_path, hop):
    """Fix 6 (hop validation, F5): the same refusal on the agent route —
    an invalid chain position never reaches the acceptance record or the
    effects."""
    log_dir = tmp_path / "executor-replay"
    port = _free_port()
    proc, url = _start_server([sys.executable, "-u", str(F5_SERVER)],
                              port, log_dir, "A2A_LISTEN_PORT")
    try:
        code, resp = _post(f"{url}/", {
            "jsonrpc": "2.0", "id": 7, "method": "message/send",
            "params": {"message": {
                "messageId": "d-hop-2",
                "metadata": {
                    "io.inspection/delegation_id": "d-hop-2",
                    "io.inspection/hop": hop},
                "data": {"steps": [
                    {"id": "a041", "kind": "file_write",
                     "path": str(tmp_path / "never.txt"),
                     "data": "x"}]}}}})
    finally:
        proc.kill()
        proc.wait()
    assert code == 200   # JSON-RPC carries the refusal as an error result
    assert "invalid hop" in resp["error"]["message"]
    assert not (tmp_path / "never.txt").exists()
    assert not (log_dir / "delegation-records.jsonl").exists()
