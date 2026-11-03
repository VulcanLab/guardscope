"""M2b tests: C6 denial effectiveness (framework/c6.py + the execute
wiring), the degraded no-eBPF mode (DESIGN.md 9: self-reported labeling,
sensor-less runner path, prevented-as-claim marking), and the report-level
merge (framework/report.py + the CLI report subcommand, DESIGN.md 10).

Docker-free: C6 and the merge consume retained artifacts; the two
live-validated execution manifests under tests/fixtures/live-runs (copied,
trimmed: execution.json + outcomes.json + manifest.json only) anchor the
merge tests in real run data. The runner's sensor-less path is tested at
the assembly level (assemble_sensorless is pure once the replay result and
the decision log are given); the live no-sensor run is validated on the
testbed host.

Run from the repo root:  python3 -m pytest tests/test_framework_m2b.py -v
"""

import inspect
import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))

from framework import execute as execute_mod  # noqa: E402
from framework import report as report_mod  # noqa: E402
from framework.c6 import run_c6  # noqa: E402
from framework.cli import main as cli_main  # noqa: E402
from framework.execute import execute_experiment  # noqa: E402
from framework.records import (  # noqa: E402
    epoch_ns_to_rfc3339_ms, make_decision_record,
)
from framework.report import (  # noqa: E402
    MergeError, merge_reports, render_summary,
)

LIVE_RUNS = ROOT / "tests" / "fixtures" / "live-runs"
T0_EXEC = LIVE_RUNS / "t0-pi" / "execution.json"
T1_EXEC = LIVE_RUNS / "t1-pi" / "execution.json"

# the canonical workload hash of the live fixtures (both executions ran
# baseline-15); synthetic manifests reuse it to stay comparable
WORKLOAD_SHA = json.loads(T0_EXEC.read_text())["runs"][0]["spec_sha256"]

WINDOW = (1_400_000_000, 1_600_000_000)   # epoch ns


# --- constructors -----------------------------------------------------------------


def deny_record(action_id=None, tool="post_hook", seq=0, run_id="r1",
                stream_id="r1:gateway", action_class="http_tool_call",
                parameters=None, ts_ns=1_500_000_000, method=None,
                path=None, transport="mcp_meta"):
    """A valid deny decision-record/1 (native records carry action_id; the
    v0-mapped shape carries null and resolves by target identity)."""
    fields = {
        "run_id": run_id, "stream_id": stream_id, "seq": seq,
        "ts": epoch_ns_to_rfc3339_ms(ts_ns),
        "enforcement_point": {"slot_id": "gateway",
                              "product": "agent-governance-gateway",
                              "product_version": "3.7.0"},
        "producer": {"plugin": "agt-gateway", "plugin_version": "0.1.0",
                     "record_source": "native"},
        "action_class": action_class, "protocol": "mcp", "tool": tool,
        "target": {"kind": "unknown", "note": "test"},
        "parameters_digest": "d" * 64,
        "action_id": action_id, "attempt": 0,
        "correlation_transport": transport, "decision": "deny",
        "policy": {"policy_id": "p1", "policy_version": "1",
                   "policy_hash": "h" * 64},
        "evidence": [{"kind": "gateway-audit-entry",
                     "locator": {"source": "decisions.jsonl"}}],
    }
    if parameters is not None:
        fields["parameters"] = parameters
    if method is not None:
        fields["method"] = method
    if path is not None:
        fields["path"] = path
    return make_decision_record(**fields)


def mapped(class_, event, ts, detail, raw_index=0, retval=0):
    """One mapped kernel record (the mapped-actions stream shape)."""
    return {"class": class_, "event": event, "ts": ts, "container": "c1",
            "pid": 7, "process": "p",
            "detail": detail, "provenance": {"raw_index": raw_index,
                                             "retval": retval}}


def write_mapped(run_dir: Path, records) -> Path:
    """Write the run's mapped-actions kernel stream. An empty record list
    still writes one unrelated filler event: an EMPTY stream is the
    no-kernel-evidence skip in C6, and these tests want evidence present
    with the denied action's signature absent."""
    run_dir.mkdir(parents=True, exist_ok=True)
    if not records:
        records = [mapped("unmapped", "write", WINDOW[0] + 5,
                         {"fd": 2}, raw_index=99)]
    path = run_dir / "mapped-actions.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in records),
                    encoding="utf-8")
    return path


def write_experiment(tmp_path, doc, name="exp.yaml"):
    p = tmp_path / name
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return p


# =========================================================== C6 (DESIGN.md 9)


def test_c6_effective_deny_confirmed(tmp_path):
    # a031 denied; its execve signature is absent from the kernel evidence
    write_mapped(tmp_path, [])
    rep = run_c6(tmp_path, [deny_record(action_id="a031")],
                 window=WINDOW, run_id="r1")
    assert rep["status"] == "pass"
    assert rep["findings"] == []
    (entry,) = rep["per_deny"]
    assert entry["verdict"] == "denial-confirmed"
    assert entry["attribution_method"] == "id"
    assert entry["evidence"] == []
    assert rep["denies"]["denials_confirmed"] == 1


def test_c6_ineffective_deny_is_the_key_finding(tmp_path):
    # a031 denied but its execve signature IS present in-window: the
    # control claimed prevention while the effect happened (DESIGN.md 9)
    write_mapped(tmp_path, [
        mapped("process_spawn", "execve", WINDOW[0] + 500,
               {"target": "/bin/sh", "cmd": ["/bin/sh", "-c", "echo hi"]},
               raw_index=3),
    ])
    rep = run_c6(tmp_path, [deny_record(action_id="a031")],
                 window=WINDOW, run_id="r1")
    assert rep["status"] == "fail"
    (finding,) = rep["findings"]
    assert finding["id"] == "C6-ineffective"
    assert finding["status"] == "fail"
    (entry,) = rep["per_deny"]
    assert entry["verdict"] == "C6-ineffective"
    assert entry["evidence"][0]["raw_index"] == 3


def test_c6_skipped_without_kernel_evidence(tmp_path):
    # degraded mode / retained run without mapped-actions: skipped with a
    # note, never a finding (DESIGN.md 9)
    write_mapped(tmp_path, [])
    (tmp_path / "mapped-actions.jsonl").unlink()
    rep = run_c6(tmp_path, [deny_record(action_id="a031")],
                 window=WINDOW, run_id="r1")
    assert rep["status"] == "skipped"
    assert "no kernel evidence" in rep["note"]
    assert rep["findings"] == []
    # an empty mapped stream is the same absence
    (tmp_path / "mapped-actions.jsonl").write_text("\n")
    rep = run_c6(tmp_path, [deny_record(action_id="a031")],
                 window=WINDOW, run_id="r1")
    assert rep["status"] == "skipped"


def test_c6_deny_without_action_id_resolves_by_target_identity(tmp_path):
    # the v0-mapped shape (action_id null): a014 vs a011 share the POST
    # /hook route; the exact parameter match (the deny case body) picks
    # a014, and its endpoint-connect signature is absent -> confirmed
    write_mapped(tmp_path, [])
    v0_deny = deny_record(
        action_id=None, tool="post_hook", method="POST", path="/hook",
        parameters={"path": "/hook", "body": "policy-deny case"},
        transport="none", ts_ns=1_500_000_000)
    rep = run_c6(tmp_path, [v0_deny], window=WINDOW, run_id="r1")
    assert rep["status"] == "pass"
    (entry,) = rep["per_deny"]
    assert entry["action_id"] == "a014"
    assert entry["attribution_method"] == "target_identity"
    assert entry["verdict"] == "denial-confirmed"
    # the same-route a011 resolves with its own body
    v0_deny_a011 = deny_record(
        action_id=None, tool="post_hook", method="POST", path="/hook",
        parameters={"path": "/hook", "body": "tool-call payload"},
        transport="none")
    rep = run_c6(tmp_path, [v0_deny_a011], window=WINDOW, run_id="r1")
    assert rep["per_deny"][0]["action_id"] == "a011"


def test_c6_window_scoping(tmp_path):
    # the denied action's signature lands OUTSIDE the window (+tolerance):
    # absence within the window still confirms the denial
    write_mapped(tmp_path, [
        mapped("direct_network", "connect", WINDOW[1] + 10 * 10**9,
               {"target_port": 9000, "transport": "tcp"}),
    ])
    rep = run_c6(tmp_path, [deny_record(action_id="a021")],
                 window=WINDOW, window_tolerance_ns=10**9, run_id="r1")
    assert rep["per_deny"][0]["verdict"] == "denial-confirmed"


def test_c6_kernel_record_denies_join_on_class_target(tmp_path):
    # the t7 actplane shim's kill record: `tool` is the acting process COMM
    # ("echo"), protocol "none", target the kernel path — the op-based
    # route cannot match it; the kernel join (coverage-layer ladder)
    # resolves it onto a032 (exec /bin/echo), and C6 verifies absence of
    # its execve signature (found live 2026-11-03: the t7 re-check run
    # left these denies unresolved)
    write_mapped(tmp_path, [
        # a031's execve signature present (not the denied instance)
        mapped("process_spawn", "execve", WINDOW[0] + 100,
               {"target": "/bin/sh", "cmd": ["/bin/sh", "-c", "echo hi"]},
               raw_index=1),
    ])
    rec = deny_record(tool="echo", action_class="process_spawn",
                       transport="none")
    rec["protocol"] = "none"
    rec["target"] = {"kind": "kernel_path_or_endpoint",
                     "value": "/bin/echo", "note": "kernel op=0 comm=echo"}
    rep = run_c6(tmp_path, [rec], window=WINDOW, run_id="r1")
    assert rep["status"] == "pass"
    (entry,) = rep["per_deny"]
    assert entry["action_id"] == "a032"
    assert entry["attribution_method"] == "target_identity"
    assert entry["verdict"] == "denial-confirmed"
    assert rep["denies"]["denials_confirmed"] == 1


def test_c6_effect_classes_use_the_manifest_signatures(tmp_path):
    # per-action classes (exact target match): file_write, credential, and
    # the direct-network ports derive from the mock harness manifest + spec
    write_mapped(tmp_path, [
        # a041's write effect present (deny ineffective)
        mapped("file_write", "security_file_open", WINDOW[0] + 100,
               {"target": "/workspace/out/b.txt",
                "flags": "O_WRONLY|O_CREAT|O_TRUNC"}, raw_index=1),
        # a051's secret read present (deny ineffective)
        mapped("credential_access", "security_file_open", WINDOW[0] + 200,
               {"target": "file:///run/secrets/token", "flags": "O_RDONLY"},
               raw_index=2),
        # a022's udp datagram present (deny ineffective)
        mapped("direct_network", "net_packet_udp", WINDOW[0] + 300,
               {"target_port": 9001, "transport": "udp"}, raw_index=3),
    ])
    rep = run_c6(tmp_path, [
        deny_record(action_id="a041"),
        deny_record(action_id="a051"),
        deny_record(action_id="a022"),
    ], window=WINDOW, run_id="r1")
    assert rep["status"] == "fail"
    assert rep["denies"]["ineffective"] == 3
    verdicts = {e["action_id"]: e["verdict"] for e in rep["per_deny"]}
    assert set(verdicts.values()) == {"C6-ineffective"}
    # the sibling actions stay confirmed: a042's c.log and a052's second
    # secret never appear; a021's tcp connect never appears
    rep2 = run_c6(tmp_path, [
        deny_record(action_id="a042"),
        deny_record(action_id="a052"),
        deny_record(action_id="a021"),
    ], window=WINDOW, run_id="r1")
    assert rep2["status"] == "pass"
    assert rep2["denies"]["denials_confirmed"] == 3


def test_c6_stdio_write_effect_via_manifest_attribute(tmp_path):
    # a001 (stdio write_file): the effect is the write-mode open of the
    # tool's path (the manifest's tool_effect_open, which "maps as
    # file_write"); a read-mode open of the same path is NOT the effect
    write_mapped(tmp_path, [
        mapped("unmapped", "security_file_open", WINDOW[0] + 100,
               {"path": "/workspace/out/a.txt", "flags": "O_RDONLY"}),
    ])
    rep = run_c6(tmp_path, [
        deny_record(action_id="a001", action_class="stdio_tool_call"),
    ], window=WINDOW, run_id="r1")
    assert rep["status"] == "pass"
    assert rep["per_deny"][0]["verdict"] == "denial-confirmed"
    # the write-mode open makes the denial ineffective
    write_mapped(tmp_path, [
        mapped("file_write", "security_file_open", WINDOW[0] + 100,
               {"target": "/workspace/out/a.txt", "flags": "O_WRONLY"}),
    ])
    rep = run_c6(tmp_path, [
        deny_record(action_id="a001", action_class="stdio_tool_call"),
    ], window=WINDOW, run_id="r1")
    assert rep["per_deny"][0]["verdict"] == "C6-ineffective"


def test_c6_stdio_read_deny_is_unverifiable_not_confirmed(tmp_path):
    # a002 (read_file): the manifest's read-mode open collides with unrelated
    # events by
    # its own note, so absence cannot ground a verdict — unverifiable with
    # a note, never a finding, never silently confirmed
    write_mapped(tmp_path, [])
    rep = run_c6(tmp_path, [
        deny_record(action_id="a002", action_class="stdio_tool_call"),
    ], window=WINDOW, run_id="r1")
    assert rep["status"] == "pass"
    (entry,) = rep["per_deny"]
    assert entry["verdict"] == "unverifiable"
    assert "read-mode" in entry["signature"]["note"]
    assert rep["denies"]["unverifiable"] == 1


def test_c6_duplicate_deny_across_streams_is_one_verification(tmp_path):
    # the same decision reaches C6 through both the v0-mapped records and
    # the native stream: one verification, both records counted
    write_mapped(tmp_path, [])
    native = deny_record(action_id="a031", seq=0)
    v0 = deny_record(action_id="a031", seq=1, stream_id="r1:gateway",
                     transport="none")
    v0["producer"]["record_source"] = "ingested"
    rep = run_c6(tmp_path, [native, v0], window=WINDOW, run_id="r1")
    assert rep["status"] == "pass"
    assert rep["denies"]["records"] == 2
    assert rep["denies"]["unique"] == 1
    assert rep["per_deny"][0]["deny_records"] == 2


def test_c6_unresolved_deny_is_recorded_not_dropped(tmp_path):
    # a deny for traffic outside the spec (organic or off-spec): recorded
    # as unresolved with a note; the C1-C4 accounting flags it separately
    write_mapped(tmp_path, [])
    rep = run_c6(tmp_path, [deny_record(action_id="a999")],
                 window=WINDOW, run_id="r1")
    assert rep["status"] == "pass"
    (entry,) = rep["per_deny"]
    assert entry["verdict"] == "unresolved"
    assert "not a spec action" in entry["note"]


def test_c6_scopes_records_by_run_id(tmp_path):
    # a foreign run's deny record is out of scope (the native stream
    # accumulates across runs on the enforcement-point volume): with at
    # least one record carrying this run's id, C6 scopes by run_id and the
    # foreign deny (plus its in-window effect) is ignored
    write_mapped(tmp_path, [
        mapped("process_spawn", "execve", WINDOW[0] + 100,
               {"target": "/bin/sh", "cmd": ["/bin/sh"]}),
    ])
    in_run_allow = deny_record(action_id="a031", run_id="r1")
    in_run_allow["decision"] = "allow"
    foreign = deny_record(action_id="a031", run_id="other-run", seq=1)
    rep = run_c6(tmp_path, [in_run_allow, foreign], window=WINDOW,
                 run_id="r1")
    assert rep["status"] == "pass"
    assert rep["scope"]["method"] == "run_id"
    assert rep["denies"]["records"] == 0


# --- the execute wiring (C6 next to C5) --------------------------------------------


WINDOW_DICT = {"start": WINDOW[0], "end": WINDOW[1]}

HTTP_DECISIONS = [
    {"tool_name": "post_hook",
     "parameters": {"path": "/hook", "body": "tool-call payload"}},
    {"tool_name": "post_hook",
     "parameters": {"path": "/hook", "body": "policy-deny case"}},
    {"tool_name": "get_health", "parameters": {"path": "/health"}},
    {"tool_name": "put_state", "parameters": {"path": "/state", "body": "k=v"}},
]


def outcomes_doc(counts=None, prevented_ids=("a021", "a022")):
    """A runner outcomes.json shape (instance-level classification)."""
    rows = []
    for i, aid in enumerate(["a011", "a012", "a013", "a014", "a021",
                             "a022"]):
        outcome = ("prevented" if aid in prevented_ids
                   else "checked-allowed")
        rows.append({"id": aid, "class": "http_tool_call", "op": "POST",
                     "outcome": outcome, "replay_status": "ok",
                     "decision_verdict": None, "decisions": 0,
                     "decision_refs": [], "reason": None})
    return {"schema": "inspection-outcomes/1", "design": "t1",
            "status": "pass",
            "counts": counts or {"checked-allowed": 4, "prevented": 2,
                                 "bypassed": 0, "checked-denied": 0,
                                 "indeterminate": 0},
            "checked_total": 4, "per_action": rows}


class FakeC6Executor:
    """Fake run_executor writing the C6 inputs: a mapped-actions kernel
    stream, a v0 decision log with one DENY (a014's twin), the run's
    outcomes.json, and (optionally) the native decision stream."""

    def __init__(self, sensor_present=True, kernel_effect=False,
                 native_echo=False):
        self.sensor_present = sensor_present
        self.kernel_effect = kernel_effect
        self.native_echo = native_echo
        self.spec = yaml.safe_load(
            (ROOT / "trace" / "traces" / "baseline.yaml").read_text())

    def __call__(self, descriptor, run_id, out_root):
        out_dir = Path(out_root) / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        entries = [dict(e, timestamp=1.5 + i * 0.01, allowed=True)
                   for i, e in enumerate(HTTP_DECISIONS)]
        # the a014 twin is denied by the enforcement point
        entries[1]["allowed"] = False
        (out_dir / "decisions.jsonl").write_text(
            "".join(json.dumps(e) + "\n" for e in entries))
        (out_dir / "run-record.json").write_text(json.dumps({"run_id": run_id}))
        (out_dir / "replay-result.json").write_text(
            json.dumps({"window_epoch_ns": WINDOW_DICT}))
        (out_dir / "outcomes.json").write_text(
            json.dumps(outcomes_doc(), indent=1))
        # the kernel evidence: the denied action's effect connect appears
        # only when the denial was ineffective
        effect = ([mapped("http_tool_call", "connect", WINDOW[0] + 100,
                          {"target_port": 8080, "transport": "tcp"})]
                  if self.kernel_effect else [])
        write_mapped(out_dir, effect)
        if self.native_echo:
            (out_dir / "gateway").mkdir(exist_ok=True)
            (out_dir / "gateway" / "decision-records.jsonl").write_text(
                json.dumps(deny_record(
                    action_id="a014", run_id=run_id,
                    stream_id=f"{run_id}:gateway")) + "\n")
        coverage = execute_mod.reconcile_lib.compute(
            self.spec, entries, [], descriptor.design,
            (WINDOW_DICT["start"], WINDOW_DICT["end"]))
        return {
            "run_id": run_id, "harness": descriptor.harness,
            "design": descriptor.design, "out_dir": str(out_dir),
            "run_record": str(out_dir / "run-record.json"),
            "status": "pass", "coverage": coverage,
            "window_epoch_ns": WINDOW_DICT,
            "decision_log": str(out_dir / "decisions.jsonl"),
            "decision_stream": {"slot_id": "gateway", "plugin": "agt-gateway",
                                "plugin_version": "0.1.0",
                                "product": "agent-governance-gateway",
                                "product_version": "3.7.0"},
            "sensor_present": self.sensor_present,
            "effective_counts": {"http_tool_call": 4},
            "spec_sha256": "f" * 64,
        }


def test_execute_c6_confirms_effective_deny(tmp_path):
    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    result = execute_experiment(p, run_executor=FakeC6Executor(),
                                out_root=tmp_path)
    run = result.runs[0]
    # the v0-mapped deny resolves a014 by target identity; its endpoint
    # connect is absent -> denial-confirmed, no finding
    assert run.c6["status"] == "pass"
    assert run.c6["denies"]["denials_confirmed"] == 1
    (entry,) = run.c6["per_deny"]
    assert entry["action_id"] == "a014"
    assert entry["attribution_method"] == "target_identity"
    assert run.findings == []
    assert result.manifest["runs"][0]["c6"]["status"] == "pass"


def test_execute_c6_ineffective_deny_is_a_run_finding(tmp_path):
    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    result = execute_experiment(
        p, run_executor=FakeC6Executor(kernel_effect=True), out_root=tmp_path)
    run = result.runs[0]
    assert run.c6["status"] == "fail"
    ids = {f["id"] for f in run.findings}
    assert ids == {"C6-ineffective"}
    assert result.manifest["runs"][0]["c6"]["status"] == "fail"


def test_execute_c6_native_stream_joins_the_v0_records(tmp_path):
    # with the native stream present, the deny appears twice (v0 + native)
    # and is verified once
    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    result = execute_experiment(
        p, run_executor=FakeC6Executor(native_echo=True), out_root=tmp_path)
    run = result.runs[0]
    assert run.c6["denies"]["records"] == 2
    assert run.c6["denies"]["unique"] == 1


# ===================================== the degraded no-eBPF mode (DESIGN.md 9)


def test_sensor_absent_labels_the_run_self_reported(tmp_path):
    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    result = execute_experiment(
        p, run_executor=FakeC6Executor(sensor_present=False),
        out_root=tmp_path)
    run = result.runs[0]
    # DESIGN.md 9: every output of the degraded mode is self-reported
    assert run.evidence_class == execute_mod.EVIDENCE_CLASS_SELF_REPORTED
    assert run.degraded == [execute_mod.SENSOR_ABSENT]
    # C6 is skipped with a note, never a finding
    assert run.c6["status"] == "skipped"
    assert "no kernel sensor" in run.c6["note"]
    assert run.findings == []
    assert result.manifest["runs"][0]["evidence_class"] == "self-reported"


def test_sensor_absent_prevented_outcomes_are_marked_claims(tmp_path):
    # DESIGN.md 9: prevented requires kernel verification of the effect
    # absence; without the sensor the outcome counts are claimed-only
    # (verified: false) and every prevented entry carries a per-action
    # unverified-claim note
    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    result = execute_experiment(
        p, run_executor=FakeC6Executor(sensor_present=False),
        out_root=tmp_path)
    run = result.runs[0]
    counts = run.outcome_counts
    assert counts["verified"] is False
    assert counts["counts"]["prevented"] == 2
    unverified = counts["prevented_unverified"]
    assert {r["id"] for r in unverified} == {"a021", "a022"}
    for row in unverified:
        assert "unverified claim" in row["note"]
        assert "kernel" in row["note"]
    # the manifest carries the same claim-preserving view
    assert result.manifest["runs"][0]["outcome_counts"]["verified"] is False


def test_sensor_present_marks_outcome_counts_verified(tmp_path):
    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    result = execute_experiment(p, run_executor=FakeC6Executor(),
                                out_root=tmp_path)
    run = result.runs[0]
    assert run.evidence_class == execute_mod.EVIDENCE_CLASS
    assert run.outcome_counts["verified"] is True
    assert "prevented_unverified" not in run.outcome_counts
    assert run.outcome_counts["per_class"]["http_tool_call"][
        "checked-allowed"] == 4


def test_sensor_aware_default_executor_passes_the_flag(tmp_path, monkeypatch):
    # execute_experiment(sensor=False) binds the sensor mode into the
    # default executor when it accepts the flag (the runner path without
    # the sensor; DESIGN.md 9)
    seen = {}

    class RecordingExecutor:
        def __call__(self, descriptor, run_id, out_root, sensor=True):
            seen["sensor"] = sensor
            return FakeC6Executor()(descriptor, run_id, out_root)

    monkeypatch.setattr(execute_mod, "default_run_executor",
                        RecordingExecutor())
    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    execute_experiment(p, out_root=tmp_path, sensor=False)
    assert seen["sensor"] is False
    execute_experiment(p, out_root=tmp_path, sensor=True)
    assert seen["sensor"] is True
    # the real default executor accepts the flag (the wiring is real)
    assert "sensor" in inspect.signature(
        execute_mod.default_run_executor).parameters


def test_cli_run_no_sensor_switch(tmp_path, monkeypatch):
    seen = {}

    def fake_execute(experiment_path, *, out_root=None, sensor=True,
                     workdir=None):
        seen["sensor"] = sensor
        from framework.experiment import load_experiment, resolve
        plan = resolve(load_experiment(experiment_path))
        return execute_mod.ExecutionResult(
            experiment=plan.experiment, runs=[], manifest_path=tmp_path,
            manifest={})

    monkeypatch.setattr(execute_mod, "execute_experiment", fake_execute)
    p = write_experiment(tmp_path, {"schema": 1, "control": "agt-gateway",
                                    "designs": ["t1"]})
    assert cli_main(["run", str(p), "--out-root", str(tmp_path),
                     "--no-sensor"]) == 0
    assert seen["sensor"] is False
    assert cli_main(["run", str(p), "--out-root", str(tmp_path)]) == 0
    assert seen["sensor"] is True


# --- the runner's sensor-less path (assembly level; docker-free) ---------------------


def _replay_results(status_map=None):
    spec = yaml.safe_load((ROOT / "trace" / "traces" / "baseline.yaml")
                          .read_text())
    status_map = status_map or {}
    return {"ok": True, "executed": len(spec["actions"]), "failed": 0,
            "window_epoch_ns": WINDOW_DICT,
            "results": [{"id": a["id"], "class": a["class"], "op": a["op"],
                         "status": status_map.get(a["id"], "ok")}
                        for a in spec["actions"]]}


def test_runner_sensorless_assembly(tmp_path):
    import run as run_mod
    import reconcile as rec_mod

    # t2 replay shape: the egress-refused direct-network actions are the
    # prevented claims; the rest executed
    replay = _replay_results({"a021": "error", "a022": "error"})
    replay["results"][-1]["error"] = "connect ECONNREFUSED"
    (tmp_path / "gateway").mkdir()
    (tmp_path / "gateway" / "decisions.jsonl").write_text("".join(
        json.dumps(dict(e, timestamp=1.5 + i * 0.01, allowed=True))
        + "\n" for i, e in enumerate(HTTP_DECISIONS)))
    profile = rec_mod.load_profile(ROOT / "runner" / "profiles" / "pi.yaml")
    run_record, manifest, report = run_mod.assemble_sensorless(
        ROOT / "trace" / "traces" / "baseline.yaml", profile, replay,
        None, "cid", run_mod.rr_mod.load_versions(run_mod.VERSIONS)
        if hasattr(run_mod, "rr_mod") else rec_mod.load_spec,
        "pi", "ns-1", design="t2",
        gateway_log=tmp_path / "gateway" / "decisions.jsonl",
        gateway_policy=None,
        window_tolerance_ns=1_000_000_000)
    # the degraded labeling (DESIGN.md 9)
    assert run_record["sensor"]["present"] is False
    assert run_record["reconciliation"]["status"] == "skipped-no-sensor"
    assert "self-reported" in run_record["sensor"]["note"]
    # effective counts are kernel-derived: never a claim
    assert run_record["effective_counts"] is None
    # the decision-log coverage still computes (C1-C4, kernel-free)
    assert run_record["coverage"]["status"] == "pass"
    # prevented entries carry the unverified-claim note
    prevented = [r for r in run_record["outcomes"]["per_action"]
                 if r["outcome"] == "prevented"]
    assert {r["id"] for r in prevented} == {"a021", "a022"}
    for row in prevented:
        assert "unverified claim" in row["note"]
    assert manifest["sensor_present"] is False
    assert manifest["degraded"] == ["sensor-absent"]
    assert manifest["reconciliation"] == "skipped-no-sensor"
    assert report["status"] == "skipped-no-sensor"


def test_runner_accepts_sensor_flag():
    import run as run_mod
    # the flag exists on both entries and validation still precedes Docker
    assert "sensor" in inspect.signature(run_mod.run_one).parameters
    assert "sensor" in inspect.signature(run_mod.run_design).parameters
    with pytest.raises(ValueError, match="unknown design"):
        run_mod.run_design("pi", "t9", "x", sensor=False)


# ================================================= report --merge (DESIGN.md 10)


# the live t1 reference-rig fingerprint (compose + enforcement_config
# sha256s of the 2026-10-28 runs): synthetic executions reuse it so they
# are comparable with the live fixtures (DESIGN.md 10 fixture component)
LIVE_T1_FINGERPRINT = json.loads(T1_EXEC.read_text())["runs"][0][
    "fixture_fingerprint"]


def synthetic_execution(out_root: Path, exp_id: str, runs, created="2026-10-28T10:00:00Z"):
    """Write a minimal execution.json + per-run dirs (outcomes.json,
    manifest.json) with the shape execute_experiment produces; `runs` maps
    run_id -> run-entry overrides."""
    exp_dir = out_root / exp_id
    exp_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for run_id, overrides in runs.items():
        run_dir = out_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        doc = {
            "run_id": run_id,
            "design": "t1",
            "fixture": "reference-rig/t1",
            "control": "agt-gateway",
            "control_binding": "selected",
            "harness": "pi",
            "workload": "baseline-15",
            "off_matrix": False,
            "observation_only": False,
            "run_dir": str(run_dir),
            "run_record": str(run_dir / "run-record.json"),
            "decision_records": {"path": str(run_dir / "decision-records.jsonl"),
                                 "count": 8},
            "fixture_fingerprint": json.loads(json.dumps(
                LIVE_T1_FINGERPRINT)),
            "evidence_class": "harness-run",
            "degraded": [],
            "status": "pass",
            "coverage": {"status": "pass"},
            "coverage_consistent": True,
            "findings": [],
            "spec_sha256": WORKLOAD_SHA,
        }
        doc.update(overrides)
        entries.append(doc)
        if "outcomes" in overrides:
            (run_dir / "outcomes.json").write_text(
                json.dumps(overrides.pop("outcomes"), indent=1))
        run_manifest = {"schema": "inspection-run-manifest/1", "run_id": run_id,
                        "created": overrides.get("created",
                                                 "2026-10-28T10:00:00+00:00")}
        (run_dir / "manifest.json").write_text(json.dumps(run_manifest))
    manifest = {
        "schema": 1, "created": created,
        "experiment": {"path": f"examples/{exp_id}.yaml", "sha256": "c" * 64,
                       "resolved": {"control": "agt-gateway",
                                    "designs": ["t1"], "harness": "pi",
                                    "workload": "baseline-15"}},
        "plugin_versions": {"pi": {"version": "1.0.4",
                                   "kind": "harness-adapter"}},
        "sensor": {"instrument": "tracee", "version": "v0.24.1"},
        "runs": entries,
    }
    path = exp_dir / "execution.json"
    path.write_text(json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    return path


def test_merge_two_compatible_live_executions_one_grid():
    report = merge_reports([T0_EXEC, T1_EXEC])
    assert len(report["grids"]) == 1
    grid = report["grids"][0]
    # one column per (control, design) run: the t0 baseline + the t1 gateway
    assert [(c["control"], c["design"]) for c in grid["columns"]] == \
        [(None, "t0"), ("agt-gateway", "t1")]
    # origin labels (DESIGN.md 7 table): t0 has no enforcement point; the
    # t1 gateway is the selected control
    assert grid["columns"][0]["origin_labels"] == []
    assert grid["columns"][1]["origin_labels"] == ["selected"]
    # per-class outcome counts loaded from the live outcomes.json
    row = grid["columns"][1]["rows"][0]
    assert row["run_id"] == "t1-pi-t1-2"
    assert row["evidence_class"] == "harness-run"
    assert row["outcome_counts"]["per_class"]["http_tool_call"] == \
        {"checked-allowed": 4}
    assert row["outcome_counts"]["counts"]["bypassed"] == 11
    assert row["provenance"]["run_manifest"]["run_id"] == "t1-pi-t1-2"
    # the untested design-column context: the control's manifest supports
    # t2/t3/t5 and no run covered them (listed, not omitted)
    assert grid["untested"]["agt-gateway"]["untested"] == ["t2", "t3", "t5"]
    assert report["warnings"] == []


def test_merge_incompatible_workload_splits_grids(tmp_path):
    # a second workload (different content hash) forms its own section
    other = synthetic_execution(tmp_path, "exp-other", {
        "other-t1": {"spec_sha256": "9" * 64}})
    report = merge_reports([T1_EXEC, other])
    assert len(report["grids"]) == 2
    assert report["grids"][0]["key"]["workload_sha256"] == WORKLOAD_SHA
    assert report["grids"][1]["key"]["workload_sha256"] == "9" * 64
    # the split warning names the mismatching key component, not a generic
    # cross-version label (DESIGN.md 10)
    assert any("workload" in w for w in report["warnings"])


def test_merge_strict_raises_on_key_mismatch(tmp_path):
    other = synthetic_execution(tmp_path, "exp-other", {
        "other-t1": {"spec_sha256": "9" * 64}})
    with pytest.raises(MergeError, match="comparability key"):
        merge_reports([T1_EXEC, other], strict=True)


def test_merge_allow_incomparable_marks_cells(tmp_path):
    other = synthetic_execution(tmp_path, "exp-other", {
        "other-t1": {"spec_sha256": "9" * 64}})
    report = merge_reports([T1_EXEC, other], allow_incomparable=True)
    # one forced grid; the off-key column's cells are marked per row
    assert len(report["grids"]) == 1
    marked = [r for c in report["grids"][0]["columns"] for r in c["rows"]
              if "non_comparable" in r]
    assert len(marked) == 1
    assert any("workload_sha256" in reason
               for reason in marked[0]["non_comparable"])


def test_merge_collision_keeps_both_rows_and_recency(tmp_path):
    # two runs of the same control x design cell: both evidence rows are
    # kept with provenance, one is recency-marked current, nothing averaged
    first = synthetic_execution(tmp_path, "exp-a", {
        "run-1": {"created": "2026-10-28T10:00:00+00:00"}})
    second = synthetic_execution(tmp_path, "exp-b", {
        "run-2": {"created": "2026-10-28T11:00:00+00:00"}})
    report = merge_reports([first, second])
    (column,) = report["grids"][0]["columns"]
    assert len(column["rows"]) == 2
    currents = [r for r in column["rows"] if r["current"]]
    assert len(currents) == 1
    assert currents[0]["run_id"] == "run-2"
    older = [r for r in column["rows"] if not r["current"]]
    assert older[0]["run_id"] == "run-1"
    # each row keeps its own executed-at provenance (never merged)
    assert {r["executed_at"] for r in column["rows"]} == \
        {"2026-10-28T10:00:00+00:00", "2026-10-28T11:00:00+00:00"}


def test_merge_fixture_fingerprint_mismatch_is_non_comparable(tmp_path):
    # DESIGN.md 10: the comparability key includes the fixture fingerprint
    # (incl. enforcement_config); same control x design but different
    # fixtures -> per-cell non_comparable marks; strict hard-fails
    a = synthetic_execution(tmp_path, "exp-a", {"run-1": {}})
    b = synthetic_execution(tmp_path, "exp-b", {"run-2": {
        "fixture_fingerprint": {"id": "reference-rig/t1",
                                "compose": {"sha256": "e" * 64}}}})
    report = merge_reports([a, b])
    (column,) = report["grids"][0]["columns"]
    assert len(column["rows"]) == 2
    for row in column["rows"]:
        assert any("fixture-fingerprint-mismatch" in reason
                   for reason in row["non_comparable"])
    with pytest.raises(MergeError, match="fixture fingerprint"):
        merge_reports([a, b], strict=True)


def test_merge_preserves_self_reported_evidence_class(tmp_path):
    # a degraded (sensor-less) run stays self-reported at report level:
    # evidence classes are never upgraded (DESIGN.md 10). A sensor-less
    # run no longer shares a grid with a sensor run by default (its sensor
    # key component is "absent", DESIGN.md 9/10): the merge splits, the
    # warning names the sensor component, and the degraded run's own grid
    # keeps every preserved fact
    degraded = synthetic_execution(tmp_path, "exp-deg", {
        "deg-t1": {"evidence_class": "self-reported",
                   "degraded": ["sensor-absent"],
                   "outcome_counts": {
                       "counts": outcomes_doc()["counts"],
                       "verified": False,
                       "prevented_unverified": [
                           {"id": aid, "class": "direct_network",
                            "note": "unverified claim: no kernel sensor "
                                    "(DESIGN.md 9)"}
                           for aid in ("a021", "a022")]},
                   "outcomes": outcomes_doc()}})
    report = merge_reports([T1_EXEC, degraded])
    # separate grids by default; the sensor component is named in the warning
    assert len(report["grids"]) == 2
    assert any("kernel_sensor_version" in w for w in report["warnings"])
    deg_grids = [g for g in report["grids"]
                 if any("deg-t1" in (r.get("run_id") or "")
                        for c in g["columns"] for r in c["rows"])]
    rows = [r for c in deg_grids[0]["columns"] for r in c["rows"]]
    deg = next(r for r in rows if r["run_id"] == "deg-t1")
    assert deg["evidence_class"] == "self-reported"
    assert deg["degraded"] == ["sensor-absent"]
    assert deg["outcome_counts"]["verified"] is False
    assert {r["id"] for r in deg["outcome_counts"]["prevented_unverified"]} \
        == {"a021", "a022"}


def test_merge_origin_labels_t4_t5(tmp_path):
    # t4/t6: the harness permission chain is harness-intrinsic; t5 has both
    # points (gateway selected + chain intrinsic); DESIGN.md 7 table
    exec_t4 = synthetic_execution(tmp_path, "exp-t4", {
        "t4-run": {"design": "t4", "control": None,
                   "control_binding": "harness-intrinsic",
                   "fixture_fingerprint": {"id": "reference-rig/t4"}}})
    exec_t5 = synthetic_execution(tmp_path, "exp-t5", {
        "t5-run": {"design": "t5", "control_binding": "selected"}})
    report = merge_reports([exec_t4, exec_t5])
    labels = {c["design"]: c["origin_labels"]
              for c in report["grids"][0]["columns"]}
    assert labels["t4"] == ["harness-intrinsic"]
    assert labels["t5"] == ["selected", "harness-intrinsic"]


def test_merge_vendor_overlap_same_plugin_id(tmp_path):
    # no vendor ids beyond plugin ids exist today: the flag fires only when
    # the control's and the harness's plugin ids are equal (recorded
    # limitation, framework/report.py)
    exec_v = synthetic_execution(tmp_path, "exp-v", {
        "v-run": {"control": "pi"}})
    report = merge_reports([exec_v])
    (flag,) = report["grids"][0]["vendor_overlap"]
    assert flag["control"] == "pi" and flag["harness"] == "pi"
    assert "same-plugin-id" in flag["flag"]


def test_merge_unresolvable_run_dir_keeps_provenance(tmp_path):
    # a run dir that no longer resolves on disk: the cell keeps its
    # recorded provenance; outcome counts stay absent (not derived), and a
    # warning says so
    moved = synthetic_execution(tmp_path, "exp-moved", {
        "gone-run": {"run_dir": "runs/gone-run"}})   # recorded, never created
    import shutil
    shutil.rmtree(tmp_path / "gone-run")   # the recorded path must not resolve
    report = merge_reports([moved])
    (row,) = report["grids"][0]["columns"][0]["rows"]
    assert row["run_id"] == "gone-run"
    assert row["outcome_counts"] is None
    assert row["provenance"]["run_manifest"] is None
    assert any("does not resolve" in w for w in report["warnings"])


def test_merge_empty_inputs(tmp_path):
    report = merge_reports([])
    assert report["grids"] == []
    assert "0 grid" in render_summary(report)


# --- the CLI report subcommand -------------------------------------------------------


def test_cli_report_runs_root_and_out(tmp_path, capsys):
    runs_root = tmp_path / "runs"
    synthetic_execution(runs_root, "exp-a", {"run-1": {}})
    synthetic_execution(runs_root, "exp-b", {"run-2": {}})
    out = tmp_path / "merged.json"
    assert cli_main(["report", "--runs-root", str(runs_root),
                     "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert len(doc["grids"]) == 1
    assert len(doc["grids"][0]["columns"]) == 1   # same control x design cell
    assert len(doc["grids"][0]["columns"][0]["rows"]) == 2
    summary = capsys.readouterr().out
    assert "1 grid section(s)" in summary
    assert "rows=2" in summary


def test_cli_report_manifest_paths_stdout_json(tmp_path, capsys):
    out = tmp_path / "runs"
    synthetic_execution(out, "exp-a", {"run-1": {}})
    assert cli_main(["report", str(out / "exp-a" / "execution.json")]) == 0
    captured = capsys.readouterr()
    doc = json.loads(captured.out)          # the JSON contract on stdout
    assert doc["schema"] == 1
    assert "merged report" in captured.err  # the human summary on stderr


def test_cli_report_strict_failure(tmp_path, capsys):
    runs_root = tmp_path / "runs"
    synthetic_execution(runs_root, "exp-a", {"run-1": {}})
    synthetic_execution(runs_root, "exp-b", {"run-2": {"spec_sha256": "9" * 64}})
    assert cli_main(["report", "--runs-root", str(runs_root),
                     "--strict"]) == 1
    assert "comparability key" in capsys.readouterr().err


def test_cli_report_no_inputs(tmp_path):
    assert cli_main(["report"]) == 2
    assert cli_main(["report", str(tmp_path / "nope" / "execution.json")]) == 1


def test_render_summary_lists_untested_and_non_comparable(tmp_path):
    other = synthetic_execution(tmp_path, "exp-other", {
        "other-t1": {"spec_sha256": "9" * 64}})
    report = merge_reports([T1_EXEC, other], allow_incomparable=True)
    text = render_summary(report)
    assert "grid section(s)" in text or "grid sections" in text
    assert "untested" in text
    assert "non-comparable rows=1" in text
