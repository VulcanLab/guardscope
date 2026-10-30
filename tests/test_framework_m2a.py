"""M2a tests: correlation carriers end-to-end — C5 id consistency
(framework/c5.py + the execute wiring), the fidelity check
(framework/fidelity.py + the CLI), the dispatch-record emission contract
(the exact shape the TS/JS adapters write, validated against
dispatch-record/1), and the gateway's native decision-record stream
(gateway/server.py).

Docker-free. The TS/JS adapters are not unit-tested locally (their runtime
behavior is validated live later); the dispatch-record shape they emit is
pinned here by constructing the same shape in Python and validating it
against the schema. Same for the gateway: server.py keeps agent_os imports
lazy, so its mapping functions import docker-free.

Run from the repo root:  python3 -m pytest tests/test_framework_m2a.py -v
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))

from framework import execute as execute_mod  # noqa: E402
from framework import reconcile as reconcile_lib  # noqa: E402
from framework.c5 import run_c5  # noqa: E402
from framework.cli import main as cli_main  # noqa: E402
from framework.execute import execute_experiment  # noqa: E402
from framework.fidelity import (  # noqa: E402
    FidelityConfigError, load_fidelity_config, publish_fidelity_report,
    run_fidelity_check,
)
from framework.records import (  # noqa: E402
    RecordValidationError, epoch_ns_to_rfc3339_ms, make_decision_record,
    make_dispatch_record, validate_decision_record, validate_dispatch_record,
)

INSPECTION_ROOT = ROOT


def _load_gateway():
    spec = importlib.util.spec_from_file_location(
        "m2a_gateway", INSPECTION_ROOT / "gateway" / "server.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


gateway_server = _load_gateway()


# --- shared constructors --------------------------------------------------------


def dispatch(action_id, run_id="run-1", carrier="mcp_meta", attempt=0,
             error=None):
    """A valid dispatch-record/1 for one attempt."""
    fields = {"run_id": run_id, "action_id": action_id,
              "carrier_used": carrier, "attempt": attempt}
    if error is not None:
        fields["error"] = {"message": error}
    else:
        fields["result"] = {"status": "ok"}
    return make_dispatch_record(**fields)


def decision(action_id, run_id="run-1", stream_id="run-1:gateway", seq=0,
             attempt=0, transport="mcp_meta", allowed=True, ts_ns=1_500_000_000):
    """A valid native decision-record/1 echoing (or not) an id."""
    return make_decision_record(
        run_id=run_id, stream_id=stream_id, seq=seq,
        ts=epoch_ns_to_rfc3339_ms(ts_ns),
        enforcement_point={"slot_id": "gateway",
                           "product": "agent-governance-gateway",
                           "product_version": "0.1.0"},
        producer={"plugin": "agt-gateway", "plugin_version": "0.1.0",
                  "record_source": "native"},
        action_class="http_tool_call", protocol="mcp", tool="post_hook",
        target={"kind": "unknown", "note": "test"},
        parameters_digest="d" * 64,
        action_id=action_id, attempt=attempt,
        correlation_transport=transport,
        decision="allow" if allowed else "deny",
        policy={"policy_id": "t1-allow-all", "policy_version": "1",
                "policy_hash": "h" * 64},
        evidence=[{"kind": "gateway-audit-entry",
                   "locator": {"source": "decisions.jsonl"}}],
    )


# ============================================================================ C5


def test_c5_pass_on_matching_echo():
    report = run_c5([dispatch("a011")],
                    [decision("a011", seq=0)], run_id="run-1")
    assert report["status"] == "pass"
    assert report["findings"] == []
    assert report["scope"]["method"] == "run_id"
    assert report["echoed_pairs"] == 1
    assert report["carried_pairs"] == 1


def test_c5_fabrication():
    report = run_c5([dispatch("a011")],
                    [decision("a999")], run_id="run-1")
    assert report["status"] == "fail"
    ids = {f["id"] for f in report["findings"]}
    # the unknown echo is a fabrication; the dispatched-but-unechoed a011
    # is additionally a stripping finding
    assert ids == {"C5-fabrication", "C5-stripping"}
    fab = next(f for f in report["findings"] if f["id"] == "C5-fabrication")
    assert "a999" in fab["detail"]


def test_c5_duplication_at_one_point():
    report = run_c5([dispatch("a011")],
                    [decision("a011", seq=0), decision("a011", seq=1)],
                    run_id="run-1")
    (finding,) = report["findings"]
    assert finding["id"] == "C5-duplication"
    assert report["skipped"] == {"dispatch_invalid": 0,
                                 "dispatch_carrier_none": 0,
                                 "decision_null_action_id": 0,
                                 "dispatch_not_inspected": 0}


def test_c5_same_pair_at_two_points_is_not_duplication():
    # two enforcement points echoing the same dispatch is the T5 shape, not
    # a duplication (DESIGN.md 5 join key includes stream_id)
    report = run_c5([dispatch("a011")],
                    [decision("a011", stream_id="run-1:gateway", seq=0),
                     decision("a011", stream_id="run-1:harness", seq=0)],
                    run_id="run-1")
    assert report["status"] == "pass"


def test_c5_stripping():
    report = run_c5([dispatch("a011", carrier="mcp_meta"),
                     dispatch("a012", carrier="none")],
                    [], run_id="run-1")
    assert report["status"] == "fail"
    (finding,) = report["findings"]
    assert finding["id"] == "C5-stripping"
    assert "a011" in finding["detail"]
    # the carrier-less dispatch is skipped, not a finding
    assert report["skipped"]["dispatch_carrier_none"] == 1
    assert not any("a012" in f["detail"] for f in report["findings"])


def test_c5_stripping_scoped_to_inspected_traffic():
    """DESIGN.md 5: stripping is a defect on INSPECTABLE traffic only. In
    t1/t2 the stdio calls (a001-a003) are dispatched with carriers but cross
    no enforcement point by design; their missing echo is expected."""
    # a stdio dispatch, unscoped: stripping fires (direct unit use)
    report = run_c5([dispatch("a001")], [])
    assert report["status"] == "fail"
    # the same dispatch, scoped to the design's inspected ids: skipped
    report = run_c5([dispatch("a001"), dispatch("a011")],
                    [decision("a011", seq=0)],
                    inspected_action_ids={"a011", "a012", "a013", "a014"})
    assert report["status"] == "pass", report["findings"]
    assert report["skipped"]["dispatch_not_inspected"] == 1


def test_c5_multi_attempt():
    dispatches = [dispatch("a011", attempt=0), dispatch("a011", attempt=1)]
    records = [decision("a011", attempt=0), decision("a011", attempt=2)]
    report = run_c5(dispatches, records, run_id="run-1")
    ids = sorted(f["id"] for f in report["findings"])
    # attempt 1 dispatched but never echoed (stripping); attempt 2 echoed but
    # never dispatched (fabrication); attempt 0 matches
    assert ids == ["C5-fabrication", "C5-stripping"]


def test_c5_v0_null_action_ids_are_skipped_not_findings():
    # v0-mapped records carry action_id null (framework/records.py): they
    # carry no ids to check and must not become findings
    report = run_c5([dispatch("a011")],
                    [decision(None, seq=0), decision(None, seq=1)],
                    run_id="run-1")
    assert report["findings"][0]["id"] == "C5-stripping"  # a011 not echoed
    assert report["skipped"]["decision_null_action_id"] == 2
    # with the echo present, the null-id records are purely incidental
    report = run_c5([dispatch("a011")],
                    [decision(None, seq=0), decision("a011", seq=1)],
                    run_id="run-1")
    assert report["status"] == "pass"


def test_c5_carrier_none_dispatch_echoed_is_not_fabrication():
    # a dispatch with carrier_used none still carried the id (DESIGN.md 3:
    # dispatch records are one per attempt regardless of carrier), so a
    # decision echoing it is not fabrication; and carrier-none dispatches
    # are never stripping findings
    report = run_c5([dispatch("a011", carrier="none")],
                    [decision("a011")], run_id="run-1")
    assert report["status"] == "pass"
    assert report["skipped"]["dispatch_carrier_none"] == 1


def test_c5_scopes_decision_records_by_run_id():
    # a foreign-run record echoing an unknown id is out of scope, not a
    # fabrication finding
    report = run_c5([dispatch("a011")],
                    [decision("a011"), decision("a777", run_id="other-run")],
                    run_id="run-1")
    assert report["status"] == "pass"
    assert report["scope"] == {"method": "run_id",
                               "decision_records": 1,
                               "dispatch_records": 1}


def test_c5_scopes_decision_records_by_window():
    # native streams accumulate across runs on the enforcement-point volume;
    # with no run_id match the measurement window scopes them (the same
    # convention the C1-C4 window uses)
    records = [decision("a011", run_id="unattributed", ts_ns=1_500_000_000),
               decision("a777", run_id="unattributed", ts_ns=9_000_000_000)]
    report = run_c5([dispatch("a011")], records, run_id="run-1",
                    window=(900_000_000, 2_000_000_000))
    assert report["status"] == "pass"
    assert report["scope"] == {"method": "window",
                               "decision_records": 1,
                               "dispatch_records": 1}


def test_c5_invalid_dispatch_record_is_a_finding():
    bad = {"schema": 1, "run_id": "run-1", "action_id": "a011",
           "dispatched_at": "2026-10-28T12:00:00.000Z"}   # missing fields
    report = run_c5([bad], [], run_id="run-1")
    assert report["status"] == "fail"
    (finding,) = report["findings"]
    assert finding["id"] == "C5-dispatch-invalid"


def test_c5_dispatch_ambiguous_carrier():
    report = run_c5([dispatch("a011", carrier="mcp_meta"),
                     dispatch("a011", carrier="http_header")],
                    [decision("a011")], run_id="run-1")
    ids = [f["id"] for f in report["findings"]]
    assert ids == ["C5-dispatch-ambiguous"]


# --- the execute wiring (C5 runs when both artifacts are present) --------------

WINDOW = {"start": 900_000_000, "end": 2_000_000_000}

HTTP_DECISIONS = [
    {"tool_name": "post_hook",
     "parameters": {"path": "/hook", "body": "tool-call payload"}},
    {"tool_name": "post_hook",
     "parameters": {"path": "/hook", "body": "policy-deny case"}},
    {"tool_name": "get_health", "parameters": {"path": "/health"}},
    {"tool_name": "put_state", "parameters": {"path": "/state", "body": "k=v"}},
]

# the canonical http_tool_call action ids (trace/traces/baseline.yaml):
# a011 and a014 share the POST /hook route (distinguished by body); all four
# are dispatched on the _meta carrier and echoed by the native stream
HTTP_ACTION_IDS = ["a011", "a014", "a012", "a013"]


def write_experiment(tmp_path, doc, name="exp.yaml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return p


class FakeCarrierExecutor:
    """Fake run_executor (same contract as the one in test_framework_execute)
    that additionally writes the two M2a C5 artifacts: the adapter's
    dispatch records and the gateway's native decision stream. The outcome
    dict omits both hint keys so the assembly's on-disk probing is what's
    exercised. echo_ids: which dispatched ids the native stream echoes."""

    def __init__(self, echo_ids=None):
        self.echo_ids = (HTTP_ACTION_IDS if echo_ids is None else echo_ids)
        self.spec = yaml.safe_load(
            (ROOT / "trace" / "traces" / "baseline.yaml").read_text())

    def __call__(self, descriptor, run_id, out_root):
        out_dir = Path(out_root) / run_id
        (out_dir / "gateway").mkdir(parents=True, exist_ok=True)
        entries = [dict(e, timestamp=1.0 + i * 0.01, allowed=True)
                   for i, e in enumerate(HTTP_DECISIONS)]
        (out_dir / "decisions.jsonl").write_text(
            "".join(json.dumps(e) + "\n" for e in entries))
        (out_dir / "run-record.json").write_text(json.dumps({"run_id": run_id}))
        (out_dir / "replay-result.json").write_text(
            json.dumps({"window_epoch_ns": WINDOW}))

        # the adapter's dispatch-record/1 stream (one per tool-call
        # attempt): BOTH tool classes carry ids in a real t1 run (the stdio
        # calls a001-a003 too); only the inspected class echoes.
        (out_dir / "dispatch-records.jsonl").write_text("".join(
            json.dumps(dispatch(a, run_id=run_id)) + "\n"
            for a in ["a001", "a002", "a003"] + HTTP_ACTION_IDS))
        # the gateway's native decision-record/1 stream (echoing the ids)
        native = []
        for seq, aid in enumerate(self.echo_ids):
            if aid is None:
                native.append(decision(None, run_id=run_id, seq=seq))
            else:
                native.append(decision(aid, run_id=run_id, seq=seq))
        (out_dir / "gateway" / "decision-records.jsonl").write_text(
            "".join(json.dumps(r) + "\n" for r in native))

        coverage = reconcile_lib.compute(
            self.spec, entries, [], descriptor.design,
            (WINDOW["start"], WINDOW["end"]))
        return {
            "run_id": run_id, "harness": descriptor.harness,
            "design": descriptor.design, "out_dir": str(out_dir),
            "run_record": str(out_dir / "run-record.json"),
            "status": "pass", "coverage": coverage,
            "window_epoch_ns": WINDOW,
            "decision_log": str(out_dir / "decisions.jsonl"),
            "decision_stream": {"slot_id": "gateway",
                                "plugin": "agt-gateway",
                                "plugin_version": "0.1.0",
                                "product": "agent-governance-gateway",
                                "product_version": "0.1.0"},
            "sensor_present": True,
            "effective_counts": {"checked": 4},
            "spec_sha256": "f" * 64,
        }


def test_execute_c5_runs_and_passes(tmp_path):
    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    result = execute_experiment(p, run_executor=FakeCarrierExecutor(),
                                out_root=tmp_path)
    run = result.runs[0]
    assert run.c5["status"] == "pass"
    assert run.c5["scope"]["method"] == "run_id"
    assert run.findings == []
    assert result.manifest["runs"][0]["c5"]["status"] == "pass"


def test_execute_c5_stripping_is_a_finding(tmp_path):
    # the native stream echoes only 3 of the 4 dispatched ids: the fourth was
    # stripped (DESIGN.md 5: a reportable defect, so a run finding)
    echo = ["a011", None, "a012", "a013"]
    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    result = execute_experiment(p, run_executor=FakeCarrierExecutor(echo_ids=echo),
                                out_root=tmp_path)
    run = result.runs[0]
    assert run.c5["status"] == "fail"
    ids = {f["id"] for f in run.findings}
    assert ids == {"C5-stripping"}


def test_execute_c5_skipped_when_artifacts_absent(tmp_path):
    # no dispatch records, no native stream: C5 skipped with a note, never a
    # finding (the v0-only M1 topology stays a valid result)
    class BareExecutor(FakeCarrierExecutor):
        def __call__(self, descriptor, run_id, out_root):
            outcome = super().__call__(descriptor, run_id, out_root)
            out_dir = Path(outcome["out_dir"])
            (out_dir / "dispatch-records.jsonl").unlink()
            (out_dir / "gateway" / "decision-records.jsonl").unlink()
            return outcome

    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    result = execute_experiment(p, run_executor=BareExecutor(),
                                out_root=tmp_path)
    run = result.runs[0]
    assert run.c5["status"] == "skipped"
    assert "absent artifacts" in run.c5["note"]
    assert run.findings == []


def test_execute_c5_skipped_when_native_stream_empty(tmp_path):
    class EmptyNativeExecutor(FakeCarrierExecutor):
        def __call__(self, descriptor, run_id, out_root):
            outcome = super().__call__(descriptor, run_id, out_root)
            (Path(outcome["out_dir"]) / "gateway" /
             "decision-records.jsonl").write_text("")
            return outcome

    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    result = execute_experiment(p, run_executor=EmptyNativeExecutor(),
                                out_root=tmp_path)
    run = result.runs[0]
    assert run.c5["status"] == "skipped"
    assert run.findings == []


# ==================================================================== fidelity


class FakeIssuer:
    """Records the marked calls; the fake control's carrier behavior is
    injected via echo_map: transport -> whether the id survives."""

    def __init__(self, echo_map=None):
        self.calls = []
        self.echo_map = echo_map or {}

    def __call__(self, transport, action_id, attempt):
        self.calls.append((transport, action_id, attempt))
        self.last = (transport, action_id, attempt)

    def collect(self):
        transport, action_id, attempt = self.last
        records = []
        if self.echo_map.get(transport, True):
            records.append(decision(action_id, run_id="fidelity",
                                    stream_id="fidelity:gateway",
                                    transport=transport, attempt=attempt))
        else:
            records.append(decision(None, run_id="fidelity",
                                    stream_id="fidelity:gateway",
                                    transport="none"))
        return records


def test_fidelity_check_pass():
    issuer = FakeIssuer()
    report = run_fidelity_check(issuer, issuer.collect, attempt=0)
    assert report["status"] == "pass"
    assert report["preserves_meta"] is True
    assert report["preserves_header"] is True
    # one marked call per transport, distinct per-transport check ids so one
    # transport's echo cannot satisfy another's assertion
    assert [c[0] for c in issuer.calls] == ["mcp_meta", "http_header"]
    assert issuer.calls[0][1] != issuer.calls[1][1]
    for detail in report["per_transport"].values():
        assert detail["result"] == "pass"
        assert detail["records_echoing"] == 1


def test_fidelity_check_detects_strip():
    issuer = FakeIssuer(echo_map={"mcp_meta": False, "http_header": False})
    report = run_fidelity_check(issuer, issuer.collect)
    assert report["status"] == "fail"
    assert report["preserves_meta"] is False
    assert report["preserves_header"] is False
    meta = report["per_transport"]["mcp_meta"]
    assert meta["records_collected"] == 1      # a record was emitted...
    assert meta["records_echoing"] == 0        # ...but it echoes no id (strip)


def test_fidelity_check_per_transport_flags():
    # meta preserved, header stripped: the flags diverge per transport
    issuer = FakeIssuer(echo_map={"mcp_meta": True, "http_header": False})
    report = run_fidelity_check(issuer, issuer.collect)
    assert report["preserves_meta"] is True
    assert report["preserves_header"] is False
    assert report["per_transport"]["mcp_meta"]["result"] == "pass"
    assert report["per_transport"]["http_header"]["result"] == "fail"


def test_fidelity_check_explicit_action_id_and_attempt():
    issuer = FakeIssuer()
    report = run_fidelity_check(issuer, issuer.collect,
                                action_id="check-x", attempt=3)
    assert all(action_id == "check-x" and attempt == 3
               for _, action_id, attempt in issuer.calls)
    assert report["attempt"] == 3


def test_fidelity_check_rejects_unknown_transport():
    with pytest.raises(ValueError, match="unknown transports"):
        run_fidelity_check(FakeIssuer(), lambda: [], transports=["carrier_pid"])


def test_publish_fidelity_report(tmp_path):
    issuer = FakeIssuer(echo_map={"mcp_meta": True, "http_header": False})
    report = run_fidelity_check(issuer, issuer.collect)
    plugins = tmp_path / "plugins"
    (plugins / "demo-gateway").mkdir(parents=True)
    (plugins / "demo-gateway" / "manifest.json").write_text(json.dumps(
        {"schema": 1, "id": "demo-gateway", "version": "0.2.0",
         "kind": "control"}))
    out = publish_fidelity_report("demo-gateway", report,
                                  plugins_dir=plugins)
    assert out == plugins / "demo-gateway" / "fidelity.json"
    doc = json.loads(out.read_text())
    # version-keyed capability facts (DESIGN.md 11): control version,
    # transport, result, timestamp
    assert doc["control_version"] == "0.2.0"
    assert doc["preserves_meta"] is True
    assert doc["preserves_header"] is False
    assert {(c["transport"], c["result"], c["control_version"])
            for c in doc["checks"]} == {("mcp_meta", "pass", "0.2.0"),
                                       ("http_header", "fail", "0.2.0")}
    for check in doc["checks"]:
        assert set(check) == {"control_version", "transport", "result",
                              "timestamp"}


def test_publish_fidelity_report_unknown_plugin(tmp_path):
    issuer = FakeIssuer()
    report = run_fidelity_check(issuer, issuer.collect)
    with pytest.raises(ValueError, match="unknown plugin"):
        publish_fidelity_report("no-such-plugin", report,
                                plugins_dir=tmp_path / "plugins")


def test_load_fidelity_config_validates():
    version = json.loads(
        (ROOT / "plugins" / "agt-gateway" / "manifest.json").read_text()
    )["version"]
    good = ROOT / "tmp-m2a-fidelity.yaml"
    good.write_text(yaml.safe_dump(
        {"schema": 1, "plugin": "agt-gateway",
         "gateway_url": "http://127.0.0.1:8090/mcp"}))
    try:
        cfg = load_fidelity_config(good)
        assert cfg["plugin"] == "agt-gateway"
        assert cfg["transports"] == ["mcp_meta", "http_header"]
        assert cfg["control_version"] == version
    finally:
        good.unlink()

    bad_path = ROOT / "tmp-m2a-fidelity-bad.yaml"
    for doc, match in (
        ({"plugin": "no-such-control", "gateway_url": "http://x/"},
         "unknown plugin"),
        ({"plugin": "pi", "gateway_url": "http://x/"}, "not a control"),
        ({"plugin": "agt-gateway", "gateway_url": "http://x/",
          "transports": ["smoke-signal"]}, "unknown transports"),
        ({"plugin": "agt-gateway"}, "gateway_url is required"),
        ({"plugin": "agt-gateway", "gateway_url": "not-a-url"},
         "must be an http"),
    ):
        bad_path.write_text(yaml.safe_dump(doc))
        try:
            with pytest.raises(FidelityConfigError, match=match):
                load_fidelity_config(bad_path)
        finally:
            bad_path.unlink()


def test_cli_fidelity_validates_only(tmp_path, capsys):
    p = tmp_path / "fidelity.yaml"
    p.write_text(yaml.safe_dump({"schema": 1, "plugin": "agt-gateway",
                                 "gateway_url": "http://127.0.0.1:8090/mcp",
                                 "transports": ["mcp_meta"]}))
    assert cli_main(["fidelity", str(p)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["status"] == "not-run"
    assert "running topology" in out["note"]
    assert out["plugin"] == "agt-gateway"


def test_cli_fidelity_rejects_bad_config(tmp_path, capsys):
    p = tmp_path / "fidelity.yaml"
    p.write_text(yaml.safe_dump({"plugin": "no-such-control",
                                 "gateway_url": "http://x/"}))
    assert cli_main(["fidelity", str(p)]) == 1
    assert "unknown plugin" in capsys.readouterr().err


# ================================================== dispatch-record emission shape
#
# The TS (harnesses/pi/adapter/replay.ts) and JS (openclaw adapter) writers
# are not unit-tested locally; this pins the exact shape they emit against
# dispatch-record/1 by constructing the same fields in Python.


def adapter_dispatch_shape(action_id, carrier="mcp_meta", error=None):
    """The byte shape of writeDispatchRecord in both adapters."""
    return {
        "schema": 1,
        "run_id": "pi-t1-1",
        "action_id": action_id,
        "attempt": 0,
        "dispatched_at": "2026-10-28T12:00:00.123Z",
        "carrier_used": carrier,
        **({"error": {"message": error}} if error is not None
           else {"result": {"status": "ok",
                            "detail": {"tool": "post_hook"}}}),
    }


def test_adapter_dispatch_shape_validates():
    validate_dispatch_record(adapter_dispatch_shape("a011"))
    validate_dispatch_record(adapter_dispatch_shape("a011", carrier="none"))
    validate_dispatch_record(
        adapter_dispatch_shape("a011", carrier="http_header",
                               error="connect ECONNREFUSED"))
    # result | error is exactly one (the oneOf in the schema)
    both = adapter_dispatch_shape("a011")
    both["error"] = {"message": "x"}
    with pytest.raises(RecordValidationError):
        validate_dispatch_record(both)


def test_make_dispatch_record_defaults_and_rejects_outcome_keys():
    rec = make_dispatch_record(run_id="r", action_id="a011",
                               carrier_used="mcp_meta",
                               result={"status": "ok"})
    assert rec["attempt"] == 0
    assert rec["schema"] == 1
    assert rec["dispatched_at"].endswith("Z")
    with pytest.raises(RecordValidationError):
        make_dispatch_record(run_id="r", action_id="a011",
                             carrier_used="mcp_meta", outcome="checked")


# ============================================ the gateway native decision stream


def test_gateway_extract_carriers_priority():
    # carrier 1: params._meta wins (DESIGN.md 5 priority order)
    got = gateway_server.extract_carriers(
        {"_meta": {"io.inspection/action_id": "a011",
                   "io.inspection/attempt": 0}}, {})
    assert got == {"action_id": "a011", "attempt": 0,
                   "correlation_transport": "mcp_meta"}
    # carrier 2: HTTP headers when no _meta
    got = gateway_server.extract_carriers(
        {}, {"x-inspection-action-id": "a012",
             "x-inspection-attempt": "0"})
    assert got == {"action_id": "a012", "attempt": 0,
                   "correlation_transport": "http_header"}
    # no carrier -> echoed as null, never invented
    got = gateway_server.extract_carriers({}, {})
    assert got == {"action_id": None, "attempt": 0,
                   "correlation_transport": "none"}


def test_gateway_native_decision_record_validates():
    rec = gateway_server.native_decision_record(
        tool_name="post_hook", arguments={"body": "x"}, allowed=True,
        reason="in allowed_tools", action_id="a011", attempt=0,
        correlation_transport="mcp_meta", seq=3,
        run_id="pi-t1-1", stream_id="pi-t1-1:gateway",
        policy={"policy_id": "t1-allow-all", "policy_version": "1",
                "policy_hash": "h" * 64})
    validate_decision_record(rec)          # decision-record/1
    assert rec["schema"] == 1              # bare stamp (DESIGN.md 4)
    assert rec["producer"]["record_source"] == "native"
    assert rec["run_id"] == "pi-t1-1"
    assert rec["seq"] == 3
    assert rec["action_id"] == "a011"       # echoed, never minted
    assert rec["attempt"] == 0
    assert rec["correlation_transport"] == "mcp_meta"
    assert rec["action_class"] == "http_tool_call"
    assert (rec["method"], rec["path"]) == ("POST", "/hook")
    assert rec["decision"] == "allow"
    assert rec["decision_detail"] == "in allowed_tools"
    assert rec["policy"]["policy_id"] == "t1-allow-all"


def test_gateway_native_record_deny_carries_evidence():
    # DESIGN.md 4: evidence is mandatory when decision == deny
    rec = gateway_server.native_decision_record(
        tool_name="write_file", arguments={"path": "/x"}, allowed=False,
        reason="not in allowed_tools", action_id=None, attempt=0,
        correlation_transport="none", seq=0)
    validate_decision_record(rec)
    assert rec["decision"] == "deny"
    assert rec["evidence"][0]["locator"]["source"] == "decisions.jsonl"
    assert rec["action_class"] == "stdio_tool_call"   # an FS tool (T3)
    assert rec["action_id"] is None


def test_gateway_native_writer_appends_monotonic_seq(tmp_path):
    writer = gateway_server.NativeRecordWriter(tmp_path)
    for i in range(3):
        writer.record(tool_name="get_health", arguments={}, allowed=True,
                    action_id=f"a01{i}", attempt=0,
                    correlation_transport="mcp_meta")
    lines = (tmp_path / "decision-records.jsonl").read_text().splitlines()
    assert len(lines) == 3
    seqs = [json.loads(l)["seq"] for l in lines]
    assert seqs == [0, 1, 2]           # per-stream monotonic (DESIGN.md 4)
    for line in lines:
        validate_decision_record(json.loads(line))
