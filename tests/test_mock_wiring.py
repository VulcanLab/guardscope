"""Mock-harness runner wiring tests: the mock harness -> the experiment
runner -> the framework execution path (DESIGN.md 3, 8, 9).

Covers the wiring added when the mock harness became a runnable harness
inside the framework (everything here is LOCAL with fakes; live validation
against a built topology is the next pass):

  - the runner's mock trigger command shape (docker exec -e
    INSPECTION_RUN_ID ... python3 -m mock_harness.driver; harness_cfg
    prefixes, per-design plan selection);
  - the pinned per-design plans (t1/t2 gateway route; t0 default plan);
  - the driver's dispatch-record emission (one dispatch-record/1 per
    tool-call attempt, carriers per transport, run identity from
    INSPECTION_RUN_ID; process-level actions get none — the M2a decision);
  - the mock-run evidence class through execute_experiment with a fake
    executor (mock-harness vs pi vs the degraded no-sensor mode);
  - the reconcile profile (runner/profiles/mock-harness.yaml) and its
    expected count ranges against the path manifest's declarations;
  - the compose fixtures (docker compose config parse when docker is
    available; schema-level sanity otherwise);
  - the example experiment files validate through framework.cli.

Run from the repo root:  python3 -m pytest tests/test_mock_wiring.py -v
"""

import json
import shutil
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "tests"))

import test_mock_harness as mh  # noqa: E402  (the shared fake syscall layer)
from mock_harness import driver as drv  # noqa: E402
from mock_harness import originators as org  # noqa: E402
from mock_harness import trace_spec as tspec  # noqa: E402

import run as run_mod  # noqa: E402  (runner/run.py)
import reconcile as runner_reconcile  # noqa: E402  (runner/reconcile.py)

from framework import execute as execute_mod  # noqa: E402
from framework.cli import main as cli_main  # noqa: E402
from framework.execute import execute_experiment  # noqa: E402
from framework.experiment import load_experiment  # noqa: E402
from framework.records import validate_dispatch_record  # noqa: E402

BASELINE = ROOT / "trace" / "traces" / "baseline.yaml"
PLAN_SCHEMA = ROOT / "mock_harness" / "plan-schema.json"
PROFILE = ROOT / "runner" / "profiles" / "mock-harness.yaml"
PATH_MANIFEST = ROOT / "mock_harness" / "manifest.yaml"

MOCK_RUNS = {"a001", "a002", "a003", "a011", "a012", "a013", "a014"}
TOOL_CALL_IDS = ["a001", "a002", "a003", "a011", "a012", "a013", "a014"]


# ------------------------------------------------- harness config + trigger argv


@pytest.mark.parametrize("design, container", [("t0", "t0-mock"),
                                               ("t1", "t1-mock"),
                                               ("t2", "t2-mock"),
                                               ("t3", "t3-mock")])
def test_harness_cfg_mock_prefixes(design, container):
    cfg = run_mod.harness_cfg("mock-harness", design)
    assert cfg["container"] == container
    # one prefix covers every fixture container name (targets, gateway,
    # tracee, the egress jail): t{N}-mock-*
    assert cfg["prefix"] == f"{design}-mock"
    assert cfg["trigger"] == "mock"
    assert cfg["replay_dir"].name == "mock"


def test_harness_cfg_mock_fixtures_only():
    """Fixtures exist for t0..t3 (plugins/mock-harness/manifest.json declares
    the same set); the runner refuses the rest. t4-t6 fail the harness-native
    gate first (the mock harness hosts no enforcement points at all), so
    the fixture gate is the defensive check for designs beyond t3."""
    for design in ("t0", "t1", "t2", "t3"):
        run_mod.harness_cfg("mock-harness", design)
    for design in ("t4", "t5", "t6"):
        with pytest.raises(ValueError, match="harness-native"):
            run_mod.harness_cfg("mock-harness", design)
    with pytest.raises(ValueError, match="harness-native"):
        run_mod.run_design("mock-harness", "t4", "x")


def _flag(cmd: list, flag: str) -> str:
    return cmd[cmd.index(flag) + 1]


def test_mock_trigger_command_shape():
    """The docker-exec argv: env-stamped run identity, cwd /repo, the driver
    module, the canonical trace, the per-run out dir, and the run id."""
    cfg = run_mod.harness_cfg("mock-harness", "t0")
    cmd = run_mod.mock_trigger_command(cfg, "mock-m1-1")
    assert cmd[:2] == ["docker", "exec"]
    assert _flag(cmd, "-e") == "INSPECTION_RUN_ID=mock-m1-1"
    assert _flag(cmd, "-w") == "/repo"
    assert "t0-mock" in cmd
    i = cmd.index("python3")
    assert cmd[i + 1:i + 3] == ["-m", "mock_harness.driver"]
    assert _flag(cmd, "--trace") == "trace/traces/baseline.yaml"
    assert _flag(cmd, "--out") == "/workspace/replay/mock-m1-1"
    assert _flag(cmd, "--run-id") == "mock-m1-1"
    # t0 keeps the driver's built-in default plan (raw route, no --plan)
    assert "--plan" not in cmd


def test_mock_trigger_command_plan_per_design():
    """t1/t2/t3 run the pinned gateway-route plan in-container; t0 does not."""
    for design in ("t1", "t2", "t3"):
        cfg = run_mod.harness_cfg("mock-harness", design)
        cmd = run_mod.mock_trigger_command(cfg, "r1")
        assert _flag(cmd, "--plan") == f"/repo/mock_harness/plans/{design}.json"


def test_mock_replay_result_shape(tmp_path):
    """Driver artifacts -> the replay-layer dict the shared machinery
    consumes: per-action id/class/op/status results and the driver
    manifest's window as the measurement window."""
    d = tmp_path / "driver-out"
    d.mkdir()
    records = [
        {"id": "a001", "class": "stdio_tool_call", "op": "write_file",
         "status": "ok", "error": None},
        {"id": "a021", "class": "direct_network", "op": "tcp_connect",
         "status": "error", "error": "[Errno 111] Connection refused"},
    ]
    (d / "action-log.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in records))
    (d / "run-manifest.json").write_text(json.dumps({
        "window_epoch_ns": {"start": 100, "end": 200}}))
    result = run_mod.mock_replay_result(d)
    assert result["executed"] == 2 and result["failed"] == 1
    assert result["ok"] is False
    assert result["window_epoch_ns"] == {"start": 100, "end": 200}
    assert result["results"][0] == records[0]
    assert result["results"][1]["class"] == "direct_network"


# --------------------------------------------------------- per-design plans


@pytest.mark.parametrize("design", ["t1", "t2", "t3"])
def test_pinned_plans_gateway_route(design):
    """The t1/t2/t3 plans pin the gateway route so the http pair crosses the
    design's enforcement point (the inspected-pair parity, DESIGN.md 8)."""
    path = ROOT / "mock_harness" / "plans" / f"{design}.json"
    plan = json.loads(path.read_text())
    schema = json.loads(PLAN_SCHEMA.read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    cls(schema).validate(plan)
    assert plan["routes"]["http"] == "gateway"
    assert plan["routes"]["gateway_url"] == "http://gateway:8090"
    # the driver's cross-check accepts the plan against the canonical spec
    spec = tspec.load_spec(BASELINE)
    assert drv.check_plan_against_spec(plan, spec) == []


def test_pinned_t3_plan_routes_stdio_via_gateway():
    """The t3 plan routes the stdio pairs through the gateway too (the fs
    tools are proxied behind it — the T3 topology where the stdio transport
    is eliminated; DESIGN.md 7); the t1/t2 plans keep the local session."""
    t3 = json.loads((ROOT / "mock_harness" / "plans" / "t3.json").read_text())
    assert t3["routes"]["stdio"] == "gateway"
    for design in ("t1", "t2"):
        plan = json.loads((ROOT / "mock_harness" / "plans" / f"{design}.json").read_text())
        assert plan["routes"].get("stdio", "local") == "local"


def test_default_plan_is_raw_t0_route():
    """t0 (no enforcement point) keeps the built-in default plan: raw
    fetch, no plan file, matching the driver's DEFAULT_PLAN."""
    cfg = run_mod.harness_cfg("mock-harness", "t0")
    assert "mock_plan" not in cfg
    assert drv.DEFAULT_PLAN["routes"]["http"] == "raw"


# ------------------------------------------------- driver dispatch records (M2a)


def _run_driver(monkeypatch, tmp_path, **kwargs):
    fake = mh.install_fake(monkeypatch, mh.FakeSyscalls())
    run_manifest = drv.execute(BASELINE, dict(drv.DEFAULT_PLAN), tmp_path,
                               **kwargs)
    return fake, run_manifest


def test_driver_emits_dispatch_records(monkeypatch, tmp_path):
    """One dispatch-record/1 per TOOL-CALL attempt (7 for the full surface),
    none for the process-level classes (no carrier exists; the M2a
    decision), each validating against dispatch-record/1."""
    monkeypatch.setenv("INSPECTION_RUN_ID", "run-x")
    fake, run_manifest = _run_driver(monkeypatch, tmp_path)
    path = tmp_path / "dispatch-records.jsonl"
    assert path.is_file()
    records = [json.loads(l) for l in path.read_text().splitlines() if l.strip()]
    assert [r["action_id"] for r in records] == TOOL_CALL_IDS
    assert len(records) == 7
    for record in records:
        validate_dispatch_record(record)   # framework/schemas/dispatch-record
        assert record["run_id"] == "run-x"
        assert record["attempt"] == 0
        assert record["carrier_used"] in ("mcp_meta", "http_header")
        assert "result" in record and record["result"]["status"] == "ok"
    # the process-level classes get no dispatch record
    assert not ({r["action_id"] for r in records} - MOCK_RUNS)
    # the run manifest carries the dispatch-records block
    assert run_manifest["dispatch_records"]["records"] == 7
    assert run_manifest["dispatch_records"]["tool_call_actions"] == 7


def test_dispatch_carriers_per_transport(monkeypatch, tmp_path):
    """Raw route (t0 default plan): stdio pairs -> mcp_meta, http pairs ->
    http_header. Gateway route (t1/t2 plan): both -> mcp_meta."""
    monkeypatch.delenv("INSPECTION_RUN_ID", raising=False)
    _, _ = _run_driver(monkeypatch, tmp_path)
    records = [json.loads(l) for l in
               (tmp_path / "dispatch-records.jsonl").read_text().splitlines()]
    by_id = {r["action_id"]: r for r in records}
    for aid in ("a001", "a002", "a003"):
        assert by_id[aid]["carrier_used"] == "mcp_meta"
    for aid in ("a011", "a012", "a013", "a014"):
        assert by_id[aid]["carrier_used"] == "http_header"
    # the run identity falls back to the shared adapter convention
    assert {r["run_id"] for r in records} == {"unattributed"}

    monkeypatch.setenv("INSPECTION_RUN_ID", "gw-run")
    out2 = tmp_path / "gateway"
    plan = {"schema": "mock-harness-plan/1",
            "routes": {"http": "gateway", "gateway_url": "http://gateway:8090"}}
    fake = mh.install_fake(monkeypatch, mh.FakeSyscalls())
    drv.execute(BASELINE, plan, out2)
    records = [json.loads(l) for l in
               (out2 / "dispatch-records.jsonl").read_text().splitlines()]
    assert {r["carrier_used"] for r in records} == {"mcp_meta"}
    assert {r["run_id"] for r in records} == {"gw-run"}


def test_dispatch_record_on_tool_call_error(monkeypatch, tmp_path):
    """A failing tool-call attempt records the dispatch error, never a
    result (DESIGN.md 4: 'result or error', exactly one)."""
    monkeypatch.setenv("INSPECTION_RUN_ID", "err-run")

    class RefusingHttp(mh.FakeSyscalls):
        def http_request(self, method, url, body=None, headers=None):
            self.calls.append(("http_request", method, url, body,
                               dict(headers) if headers else None))
            raise OSError(111, "Connection refused")

    fake = mh.install_fake(monkeypatch, RefusingHttp())
    run_manifest = drv.execute(BASELINE, dict(drv.DEFAULT_PLAN), tmp_path)
    records = [json.loads(l) for l in
               (tmp_path / "dispatch-records.jsonl").read_text().splitlines()]
    http = {r["action_id"]: r for r in records
            if r["action_id"] in ("a011", "a012", "a013", "a014")}
    assert http, "expected the http pairs to fail against the fake"
    for record in http.values():
        assert "error" in record and "result" not in record
        assert "Connection refused" in record["error"]["message"]
        validate_dispatch_record(record)
    # the stdio pairs' dispatches are results (exactly one of result|error)
    for record in records:
        if record["action_id"] in ("a001", "a002", "a003"):
            assert "result" in record and "error" not in record


def test_carriers_travel_on_the_transports(monkeypatch, tmp_path):
    """The pairs inject the carriers where the real adapter does: _meta on
    the stdio and gateway tools/call frames, the x-inspection-* headers on
    the raw fetch (DESIGN.md 5)."""
    monkeypatch.setenv("INSPECTION_RUN_ID", "carrier-run")
    fake, _ = _run_driver(monkeypatch, tmp_path)

    # stdio pair: every tools/call frame carries params._meta
    stdio_frames = [json.loads(c[2]) for c in fake.calls
                    if c[0] == "write_fd" and c[1] > 2]
    calls = [f for f in stdio_frames if f.get("method") == "tools/call"]
    assert [f["params"]["_meta"]["io.inspection/action_id"]
            for f in calls] == ["a001", "a002", "a003"]
    assert all(f["params"]["_meta"]["io.inspection/attempt"] == 0
               for f in calls)

    # raw http pair: the header carrier on each request
    https = [c for c in fake.calls if c[0] == "http_request"]
    assert len(https) == 4
    for c, aid in zip(https, ("a011", "a012", "a013", "a014")):
        assert c[4] == {"x-inspection-action-id": aid,
                        "x-inspection-attempt": "0"}

    # gateway route: the _meta carrier on the JSON-RPC tools/call body
    out = tmp_path / "gw"
    plan = {"schema": "mock-harness-plan/1",
            "routes": {"http": "gateway", "gateway_url": "http://gateway:8090"}}
    fake = mh.install_fake(monkeypatch, mh.FakeSyscalls())
    drv.execute(BASELINE, plan, out)
    gw_frames = [json.loads(c[3]) for c in fake.calls
                 if c[0] == "http_request" and '"tools/call"' in c[3]]
    assert all(f["params"]["_meta"]["io.inspection/attempt"] == 0
               for f in gw_frames)
    assert [f["params"]["_meta"]["io.inspection/action_id"] for f in gw_frames] \
        == ["a011", "a012", "a013", "a014"]


def test_t3_plan_full_driver_run(monkeypatch, tmp_path):
    """The pinned t3 plan end-to-end via the fake syscall layer: EVERY
    tool-call pair goes through the gateway (one JSON-RPC POST per attempt,
    bare fs tool names + per-action carriers on the stdio frames), the
    stdio pairs spawn NO local server child, and all 7 dispatch records use
    the mcp_meta carrier (the stdio pair's gateway route is a _meta carrier,
    exactly like the http pair's)."""
    monkeypatch.setenv("INSPECTION_RUN_ID", "t3-run")
    plan = json.loads((ROOT / "mock_harness" / "plans" / "t3.json").read_text())
    fake = mh.install_fake(monkeypatch, mh.FakeSyscalls())
    run_manifest = drv.execute(BASELINE, plan, tmp_path)
    # 3 stdio + 4 http tool calls, all one JSON-RPC POST to the gateway each
    # (plus the ONE streamable-HTTP session handshake both pairs share:
    # initialize + the initialized notification, one session per run)
    posts = [c for c in fake.calls if c[0] == "http_request"]
    frames = [json.loads(c[3]) for c in posts]
    tools_calls = [f for f in frames if f.get("method") == "tools/call"]
    assert len(tools_calls) == 7
    assert sorted(f["method"] for f in frames
                  if f.get("method") in ("initialize",
                                          "notifications/initialized")) == \
        ["initialize", "notifications/initialized"]
    assert all(c[1] == "POST" and c[2] == "http://gateway:8090/mcp" for c in posts)
    stdio_frames = [f for f in tools_calls if f["params"]["name"]
                    in ("write_file", "read_file", "list_directory")]
    assert [f["params"]["name"] for f in stdio_frames] == \
        ["write_file", "read_file", "list_directory"]
    assert [f["params"]["_meta"]["io.inspection/action_id"] for f in stdio_frames] \
        == ["a001", "a002", "a003"]
    # the stdio transport is eliminated on this route: no local server child
    assert not any("mcp-stdio" in c[1] for c in fake.calls if c[0] == "execv")
    # dispatch records: one per tool-call attempt, ALL carrier mcp_meta
    records = [json.loads(l) for l in
               (tmp_path / "dispatch-records.jsonl").read_text().splitlines()]
    assert len(records) == 7
    assert {r["carrier_used"] for r in records} == {"mcp_meta"}
    assert run_manifest["summary"]["failed"] == 0


def test_t3_gateway_refusal_is_data_not_run_failure(monkeypatch, tmp_path):
    """Errors-as-data under the t3 plan: a gateway that refuses every
    connection fails ALL seven tool-call attempts as error records (the
    rest of the surface still runs, the run never aborts), and every one
    still gets its dispatch record with an error, never a result."""
    monkeypatch.setenv("INSPECTION_RUN_ID", "t3-refused")

    class RefusingGateway(mh.FakeSyscalls):
        def http_request_full(self, method, url, body=None, headers=None):
            raise OSError(111, "Connection refused")

    fake = mh.install_fake(monkeypatch, RefusingGateway())
    plan = json.loads((ROOT / "mock_harness" / "plans" / "t3.json").read_text())
    run_manifest = drv.execute(BASELINE, plan, tmp_path)
    records = {json.loads(l)["id"]: json.loads(l) for l in
               (tmp_path / "action-log.jsonl").read_text().splitlines()}
    assert len(records) == 15   # the full surface ran
    tool_ids = {"a001", "a002", "a003", "a011", "a012", "a013", "a014"}
    assert {aid for aid, r in records.items() if r["status"] == "error"} == tool_ids
    assert all("Connection refused" in records[aid]["error"] for aid in tool_ids)
    # the failed stdio pairs still name the channel they attempted
    assert records["a001"]["origin_channel"] == "http-connect"
    dispatch = [json.loads(l) for l in
                (tmp_path / "dispatch-records.jsonl").read_text().splitlines()]
    assert {r["action_id"] for r in dispatch} == tool_ids
    for r in dispatch:
        assert "error" in r and "result" not in r
        validate_dispatch_record(r)


# --------------------------------------------- evidence class through the framework


class _FakeOutcome:
    """Minimal run_executor: one run per design, no Docker, sensor-present
    by default; everything the framework assembly consumes comes from the
    outcome dict."""

    def __init__(self, sensor_present=True):
        self.sensor_present = sensor_present
        self.calls = []

    def __call__(self, descriptor, run_id, out_root):
        self.calls.append(descriptor)
        out_dir = Path(out_root) / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "run-record.json").write_text(json.dumps({"run_id": run_id}))
        return {"run_id": run_id, "harness": descriptor.harness,
                "design": descriptor.design, "out_dir": str(out_dir),
                "run_record": str(out_dir / "run-record.json"),
                "status": "pass", "coverage": None, "window_epoch_ns": None,
                "decision_log": None, "decision_stream": {},
                "sensor_present": self.sensor_present,
                "effective_counts": {}, "spec_sha256": "f" * 64,
                "dispatch_records": None, "native_decision_records": None}


def _write_experiment(tmp_path, doc, name="exp.yaml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return p


def test_mock_harness_runs_label_mock_run(tmp_path):
    """A mock-harness run through execute_experiment carries the mock-run
    evidence class (DESIGN.md 8, 9), in the run summary AND the execution
    manifest; a pi run stays harness-run; a sensor-less mock run is
    self-reported (claims never self-upgrade)."""
    executor = _FakeOutcome(sensor_present=True)
    doc = {"schema": 1, "control": None, "designs": ["t0"],
           "harness": "mock-harness"}
    result = execute_experiment(_write_experiment(tmp_path, doc),
                                run_executor=executor,
                                out_root=tmp_path / "runs")
    assert len(result.runs) == 1
    summary = result.runs[0]
    assert summary.evidence_class == "mock-run"
    manifest_entry = [r for r in result.manifest["runs"]
                     if r["run_id"] == summary.run_id][0]
    assert manifest_entry["evidence_class"] == "mock-run"
    # the fixture fingerprint pins the MOCK fixture's compose file
    assert manifest_entry["fixture_fingerprint"]["compose"]["path"] \
        == "compose/t0-mock.yaml"

    # pi stays harness-run
    executor = _FakeOutcome(sensor_present=True)
    doc = {"schema": 1, "control": None, "designs": ["t0"], "harness": "pi"}
    result = execute_experiment(_write_experiment(tmp_path, doc, "e2.yaml"),
                                run_executor=executor,
                                out_root=tmp_path / "runs2")
    assert result.runs[0].evidence_class == "harness-run"

    # degraded no-sensor mode is self-reported for either harness
    executor = _FakeOutcome(sensor_present=False)
    result = execute_experiment(_write_experiment(tmp_path, doc, "e3.yaml"),
                                run_executor=executor,
                                out_root=tmp_path / "runs3")
    assert result.runs[0].evidence_class == "self-reported"
    assert result.runs[0].degraded == ["sensor-absent"]


def test_mock_run_evidence_not_upgraded_by_merge(tmp_path):
    """The merged-report worst-class ordering knows mock-run (it ranks
    below harness-run); a mock-run row is never silently upgraded."""
    from framework.report import EVIDENCE_CLASS_WORST_FIRST, _worst_evidence_class
    assert "mock-run" in EVIDENCE_CLASS_WORST_FIRST
    assert _worst_evidence_class(["mock-run", "harness-run"]) == "mock-run"
    assert _worst_evidence_class(["self-reported", "mock-run"]) == "self-reported"


# --------------------------------------------------------- reconcile profile


def test_mock_profile_loads_and_declares_expected_ranges():
    """runner/profiles/mock-harness.yaml validates through the shared
    profile loader and declares the mock expected count ranges."""
    profile = runner_reconcile.load_profile(PROFILE)
    assert profile["profile"] == "mock-harness/v1"
    assert profile["harness"] == "mock-harness"
    assert profile["container_name"] == "t0-mock"
    assert isinstance(profile["window_tolerance_ns"], int)
    mult = profile["multiplicity"]
    assert mult["stdio_handshake_extra_writes"] == 1
    assert mult["http_connects_min"] == 1
    assert mult["tcp_connects_per_action"] == 1
    assert mult["udp_max_per_action"] == 2
    assert mult["file_write_opens_per_action"] == [1, 2]
    assert mult["credential_opens_per_action"] == [1, 2]
    # served-target names (the stdio server logs under its SERVER_NAME)
    assert profile["served_targets"] == {"http": "http-endpoint",
                                         "stdio": "toy-mcp-fs",
                                         "network": "net-peer"}


def test_mock_profile_multiplicity_matches_path_manifest():
    """The profile's per-class expected count ranges agree with the pinned path
    manifest's expected_multiplicity declarations (mock_harness/
    manifest.yaml), which the driver refuses to run against on drift."""
    profile = runner_reconcile.load_profile(PROFILE)
    manifest = yaml.safe_load(PATH_MANIFEST.read_text())
    by_id = {p["id"]: p for p in manifest["paths"]}
    assert profile["multiplicity"]["file_write_opens_per_action"] == \
        by_id["a041"]["expected_multiplicity"]["file_write_opens_per_action"]
    assert profile["multiplicity"]["credential_opens_per_action"] == \
        by_id["a051"]["expected_multiplicity"]["credential_opens_per_action"]
    assert profile["multiplicity"]["udp_max_per_action"] == \
        by_id["a022"]["expected_multiplicity"]["udp_max_per_action"]
    # tcp: one connect per tcp_connect action in both declarations
    assert profile["multiplicity"]["tcp_connects_per_action"] == \
        by_id["a021"]["expected_multiplicity"]["tcp_connects_per_action"]


def test_mock_profile_reconciler_end_to_end():
    """The shared Reconciler consumes the mock profile end-to-end: a mock
    replay with NO kernel evidence reconciles R1 (the replay layer matches
    the spec) and FAILS the kernel checks — a mock run without kernel
    confirmation never passes silently (DESIGN.md 8, 9)."""
    profile = runner_reconcile.load_profile(PROFILE)
    spec = runner_reconcile.load_spec(BASELINE)
    replay = {"ok": True, "executed": len(spec["actions"]), "failed": 0,
              "window_epoch_ns": {"start": 1, "end": 2},
              "results": [{"id": a["id"], "class": a["class"],
                           "op": a["op"], "status": "ok"}
                          for a in spec["actions"]]}
    report = runner_reconcile.Reconciler(
        spec, profile, replay, [], [], None, design="t0").run()
    checks = {c["id"]: c["status"] for c in report["checks"]}
    assert checks["R1-replay-layer"] == "pass"
    assert report["status"] == "fail"
    for cls in runner_reconcile.SIX_CLASSES:
        assert checks[f"R3-kernel-{cls}"] == "fail"


def test_mock_profile_t3_pooled_range():
    """Design-aware reconciliation consumes the mock profile under t3: BOTH
    tool classes take the shared pooled-gateway branch (runner/reconcile.py
    T3_SHARED_POOL_DESIGNS — the stdio pairs' gateway route produces the
    same pooled gateway connects as the http pairs, no local stdio
    session), and with no kernel evidence the pooled count range fails loud,
    never silently. The profile adds no t3-specific keys: the range's
    lower bound IS http_connects_min."""
    profile = runner_reconcile.load_profile(PROFILE)
    spec = runner_reconcile.load_spec(BASELINE)
    # replay statuses shape the prevented-class contract: the egress jail
    # refuses the tcp attempt (error with the refusal errno); the udp send
    # succeeds locally (ok — the served layer adjudicates effect)
    statuses = {"a021": ("error", "[Errno 111] Connection refused")}
    replay = {"ok": False, "executed": len(spec["actions"]), "failed": 1,
              "window_epoch_ns": {"start": 1, "end": 2},
              "results": [{"id": a["id"], "class": a["class"],
                           "op": a["op"],
                           "status": statuses.get(a["id"], ("ok", None))[0],
                           "error": statuses.get(a["id"], ("ok", None))[1]}
                          for a in spec["actions"]]}
    report = runner_reconcile.Reconciler(
        spec, profile, replay, [], [], None, design="t3").run()
    checks = {c["id"]: c["status"] for c in report["checks"]}
    assert checks["R1-replay-layer"] == "pass"
    n_tool_calls = (sum(1 for a in spec["actions"]
                        if a["class"] == "stdio_tool_call")
                    + sum(1 for a in spec["actions"]
                          if a["class"] == "http_tool_call"))
    for cls in ("stdio_tool_call", "http_tool_call"):
        assert checks[f"R3-kernel-{cls}"] == "fail"
        result = report["kernel"]["per_class"][cls]
        assert result["evidence"] == "kernel-pooled-shared"
        n_http = len([a for a in spec["actions"]
                      if a["class"] == "http_tool_call"])
        assert result["problems"] == [
            f"0 pooled gateway connects outside "
            f"[1, {n_tool_calls + n_http}]"]
    assert runner_reconcile.T3_SHARED_POOL_DESIGNS == {"t3"}


# --------------------------------------------------------- compose fixtures

@pytest.mark.parametrize("design", ["t0", "t1", "t2", "t3"])
def test_compose_fixture_shape(design):
    """Schema-level sanity on the mock BASES (DESIGN.md 7: placeholder
    slot + control-binding overlay). t0 has no control slot and stays a
    single-file fixture; t1/t2/t3 are bases with the gateway slot declared
    but the control service ABSENT: the mock-harness service depends on the
    slot's gateway service (which only the overlay provides — the base
    alone is not a validatable unit) and points GATEWAY_URL at it by
    service name. The t{N}-mock-* container prefixes, the sensor profile,
    and the t2/t3 jail attachment to the mock service's netns hold."""
    path = ROOT / "compose" / f"{design}-mock.yaml"
    doc = yaml.safe_load(path.read_text())
    assert doc["name"] == f"inspection-{design}-mock"
    svc = doc["services"]["mock-harness"]
    assert svc["container_name"] == f"{design}-mock"
    assert svc["image"] == "inspection/mock-harness"
    assert svc["build"]["dockerfile"] == "mock_harness/Dockerfile"
    assert svc["working_dir"] == "/workspace"
    # long-lived idle command (the runner docker-execs the driver into it)
    assert "sleep infinity" in " ".join(svc["command"])
    # volumes: target logs, the per-run replay dir, the repo read-only
    vols = svc["volumes"]
    # the staging mount is env-driven (GUARDSCOPE_STAGING_DIR; unset
    # keeps the repo-relative ../runs default; framework/workdir.py)
    assert "${GUARDSCOPE_STAGING_DIR:-../runs}/mock:/workspace/replay" in vols
    assert "..:/repo:ro" in vols
    assert any(v.startswith("target-logs:") for v in vols)
    env = svc["environment"]
    assert env["REPLAY_LOG_DIR"] == "/workspace/replay"
    assert env["TARGET_LOG_DIR"] == "/var/log/targets"
    if design == "t0":
        assert "GATEWAY_URL" not in env
        assert "gateway" not in doc["services"]
    else:
        assert env["GATEWAY_URL"] == "http://gateway:8090"
        # the slot is DECLARED (the harness service depends on it) but the
        # control service is ABSENT: base+overlay is the validatable unit
        assert "gateway" not in doc["services"]
        assert "gateway" in svc["depends_on"]
        # the log volume the slot's overlay wires the control's records to
        assert "gateway-logs" in doc["volumes"]
    # every container name in the project carries the t{N}-mock- prefix
    # (the harness service itself is exactly t{N}-mock)
    for name, s in doc["services"].items():
        assert s["container_name"] == f"{design}-mock" \
            if name == "mock-harness" else \
            s["container_name"].startswith(f"{design}-mock-")
    # the sensor stays outside the topology
    assert doc["services"]["tracee"]["profiles"] == ["sensor"]
    assert doc["services"]["tracee"]["container_name"] == f"{design}-mock-tracee"
    if design == "t2":
        jail = doc["services"]["egress-jail-mock"]
        # the jail attaches to the mock service's netns BY SERVICE NAME
        assert jail["network_mode"] == "service:mock-harness"
        assert jail["container_name"] == "t2-mock-egress-jail"
        assert jail["restart"] == "no"
        assert "gateway" in jail["depends_on"]
    elif design == "t3":
        # the t3 topology minus the gateway: the fs tool server stays in the
        # base (the overlay's gateway proxies it)
        assert doc["services"]["mcp-fs-http"]["container_name"] \
            == "t3-mock-mcp-fs-http"
        # same forced egress as t2, attached to the mock service's netns
        jail = doc["services"]["egress-jail-mock"]
        assert jail["network_mode"] == "service:mock-harness"
        assert jail["container_name"] == "t3-mock-egress-jail"
        assert jail["restart"] == "no"
        assert "gateway" in jail["depends_on"]
    else:
        assert "egress-jail-mock" not in doc["services"]
        assert "mcp-fs-http" not in doc["services"]


@pytest.mark.parametrize("design", ["t1", "t2", "t3"])
def test_mock_overlay_fixture_shape(design):
    """The shipped agt-gateway binding for the mock fixtures (DESIGN.md 7):
    the gateway slot's service definition, moved out of the old single-file
    fixture into the control's overlay bundle. The mock overlay is the
    design overlay's binding on the mock project (container prefix and
    agent id differ); t3's carries both tool classes behind the gateway and
    the T3 policy."""
    path = ROOT / "plugins" / "agt-gateway" / "overlay" / f"{design}-mock.yaml"
    doc = yaml.safe_load(path.read_text())
    # pure binding: the overlay adds the slot service and nothing else
    assert set(doc) == {"services"}
    assert set(doc["services"]) == {"gateway"}
    gw = doc["services"]["gateway"]
    assert gw["build"]["dockerfile"] == "gateway/Dockerfile"
    assert gw["image"] == "inspection/gateway"
    assert gw["container_name"] == f"{design}-mock-gateway"
    assert gw["networks"] == [f"{design}net"]
    env = gw["environment"]
    assert env["UPSTREAM_URL"] == "http://mcp-http:8091/mcp"
    assert env["GATEWAY_AGENT_ID"] == f"{design}-mock-replay"
    assert gw["volumes"] == ["gateway-logs:/var/log/gateway"]
    assert gw["restart"] == "unless-stopped"
    if design == "t3":
        # the t3 binding: fs tools proxied behind the gateway, T3 policy
        assert env["UPSTREAM_FS_URL"] == "http://mcp-fs-http:8092/mcp"
        assert env["GATEWAY_POLICY"] == "/opt/inspection/gateway/policy-t3.yaml"
        assert gw["depends_on"] == ["mcp-http", "mcp-fs-http"]
    else:
        assert gw["depends_on"] == ["mcp-http"]


@pytest.mark.skipif(shutil.which("docker") is None,
                    reason="docker not available locally")
@pytest.mark.parametrize("design", ["t0", "t1", "t2", "t3"])
def test_compose_fixture_config_parses(design):
    """docker compose config accepts each mock fixture (parse-level
    validation; building/starting the topology is the live pass). t0 is a
    single-file fixture; t1/t2/t3 validate as the MERGED base+overlay
    composition (the base alone is not a validatable unit)."""
    base = ROOT / "compose" / f"{design}-mock.yaml"
    overlay = (ROOT / "plugins" / "agt-gateway" / "overlay" /
               f"{design}-mock.yaml")
    files = [str(base)]
    if design != "t0":
        files.append(str(overlay))
    cmd = ["docker", "compose"]
    for f in files:
        cmd += ["-f", f]
    cmd += ["config", "--quiet"]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(shutil.which("docker") is None,
                    reason="docker not available locally")
@pytest.mark.parametrize("design", ["t1", "t2", "t3"])
def test_mock_base_alone_fails_loudly(design):
    """A base with a declared slot is NOT a validatable unit on its own
    (DESIGN.md 7): docker compose config fails loudly, naming the missing
    slot service the harness depends on."""
    base = ROOT / "compose" / f"{design}-mock.yaml"
    proc = subprocess.run(
        ["docker", "compose", "-f", str(base), "config", "--quiet"],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0
    assert "depends on undefined service \"gateway\"" in proc.stderr


# --------------------------------------------------------- examples validate


@pytest.mark.parametrize("name, control, design", [
    ("t0-mock.yaml", None, "t0"),
    ("t1-mock.yaml", "agt-gateway", "t1"),
    ("t2-mock.yaml", "agt-gateway", "t2"),
    ("t3-mock.yaml", "agt-gateway", "t3"),
])
def test_example_experiments_validate(name, control, design):
    path = ROOT / "examples" / name
    # the CLI path (framework.cli validate)
    assert cli_main(["validate", str(path)]) == 0
    # and the loader resolves the mock-harness pairing from the plugin
    # manifests (not a hardcoded harness list)
    experiment = load_experiment(path)
    assert experiment.control == control
    assert experiment.designs == [design]
    assert experiment.harness == "mock-harness"
    assert experiment.off_matrix is False


def test_mock_harness_gateway_designs_with_control_loads():
    """harness mock-harness accepts control agt-gateway for t1/t2/t3 because
    experiment validation reads the capability manifests (the mock
    manifest declares the same gateway-slot semantics as pi)."""
    for design in ("t1", "t2", "t3"):
        doc = {"schema": 1, "control": "agt-gateway", "designs": [design],
               "harness": "mock-harness"}
        experiment = load_experiment(_write_experiment(Path("/tmp"), doc,
                                                       f"mock-{design}.yaml"))
        assert experiment.designs == [design]
    # and a design outside the manifest's supported set is a load-time
    # error naming it (the harness-native designs host no mock fixture)
    doc = {"schema": 1, "control": None, "designs": ["t4"],
           "harness": "mock-harness"}
    with pytest.raises(Exception, match="t4 not supported by harness"):
        load_experiment(_write_experiment(Path("/tmp"), doc, "mock-t4.yaml"))


def test_plugin_manifest_declares_the_fixture_set():
    """plugins/mock-harness/manifest.json declares the supported designs
    (the fixture set) and documents the t3 stdio gateway route — the same
    set runner/run.py's fixture gate enforces."""
    manifest = json.loads(
        (ROOT / "plugins" / "mock-harness" / "manifest.json").read_text())
    assert manifest["supported_designs"] == ["t0", "t1", "t2", "t3"]
    assert "routes.stdio=gateway" in manifest["notes"]
    assert "t3-mock.yaml" in manifest["notes"]


# --------------------------------------------------------- version pins


def test_mock_harness_version_pins_present():
    """pinned_versions() resolves the mock-harness image/version keys for
    the run record's pinned block (runner/runrecord.py VERSION_KEYS)."""
    import runrecord as rr
    versions = rr.load_versions(ROOT / "env" / "versions.env")
    pinned = rr.pinned_versions(versions, "mock-harness", {"version": "v"})
    assert pinned["harness"] == "mock-harness"
    assert pinned["harness_version"] == "mock-harness@1"
    assert pinned["harness_image"] == "inspection/mock-harness"
