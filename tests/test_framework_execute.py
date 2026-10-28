"""Framework execution-wiring tests (M1 final piece): execute_experiment
(DESIGN.md 6, 9) — plan expansion to per-design execution, the run manifest
contents (fixture fingerprint stability, recorded defaults, sensor version,
evidence class, degraded flags), the mapped-record C1-C4 consistency
assertion, and the CLI run path.

Docker-free: a fake run_executor stands in for the runner machinery (the
default executor runs on the Linux testbed host only). The recomputed C1-C4
coverage is real: it runs against the canonical baseline spec
(trace/traces/baseline.yaml), so the fake's synthetic decision logs must
satisfy the same C1-C4 checks a live run's log satisfies.

Run from the repo root:  python3 -m pytest tests/test_framework_execute.py -v
"""

import hashlib
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
from framework.cli import main as cli_main  # noqa: E402
from framework.execute import (  # noqa: E402
    execute_experiment, load_env_versions, sensor_version,
)
from framework.records import (  # noqa: E402
    V0_AUDIT_ENTRY_SCHEMA, validate_decision_record,
)
from framework.experiment import load_experiment  # noqa: E402


def write_experiment(tmp_path: Path, doc: dict, name: str = "e.yaml") -> Path:
    p = tmp_path / name
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return p


def base_doc(**overrides) -> dict:
    doc = {"schema": 1, "control": None, "designs": ["t0"]}
    doc.update(overrides)
    return doc


# --- the fake run_executor (no Docker, no network) ------------------------------

# The fake's synthetic v0 AuditEntry decision log: the gateway-routed http
# tools (all four http spec actions) and, for designs that inspect them, the
# fs tools, with parameters matching the canonical spec's args (C2/C3 need
# every inspected action accounted and evaluated). Timestamps are epoch
# seconds (the v0 format), so the window is second-scale epoch ns.
WINDOW = {"start": 900_000_000, "end": 2_000_000_000}

HTTP_DECISIONS = [
    {"tool_name": "post_hook",
     "parameters": {"path": "/hook", "body": "tool-call payload"}},
    {"tool_name": "post_hook",
     "parameters": {"path": "/hook", "body": "policy-deny probe"}},
    {"tool_name": "get_health", "parameters": {"path": "/health"}},
    {"tool_name": "put_state", "parameters": {"path": "/state", "body": "k=v"}},
]
FS_DECISIONS = [
    {"tool_name": "write_file",
     "parameters": {"path": "/workspace/out/a.txt",
                    "data": "hello from mcp fs"}},
    {"tool_name": "read_file", "parameters": {"path": "/workspace/out/a.txt"}},
    {"tool_name": "list_directory", "parameters": {"path": "/workspace/out"}},
]


class FakeRunExecutor:
    """Stands in for the runner machinery: writes a synthetic v0 AuditEntry
    decision log for the design's inspected classes, reports the coverage a
    live run would compute over that log (framework/reconcile.compute), and
    records every (descriptor, run_id) call.

    phantom_wrapper_decision: report coverage computed over the log PLUS one
    duplicate decision that the log does not contain — inconsistent data,
    for the coverage-consistency mismatch path.
    """

    def __init__(self, *, sensor_present: bool = True,
                 phantom_wrapper_decision: bool = False):
        self.calls = []
        self.sensor_present = sensor_present
        self.phantom = phantom_wrapper_decision
        self.spec = yaml.safe_load(
            (ROOT / "trace" / "traces" / "baseline.yaml").read_text())

    def __call__(self, descriptor, run_id: str, out_root) -> dict:
        self.calls.append((descriptor, run_id, Path(out_root)))
        out_dir = Path(out_root) / run_id
        out_dir.mkdir(parents=True, exist_ok=True)

        inspected = reconcile_lib.INSPECTED_CLASSES[descriptor.design]
        entries = []
        if "http_tool_call" in inspected:
            entries += [dict(e, timestamp=1.0 + i * 0.01, allowed=True)
                       for i, e in enumerate(HTTP_DECISIONS)]
        if "stdio_tool_call" in inspected:
            entries += [dict(e, timestamp=1.0 + 0.1 + i * 0.01, allowed=True)
                       for i, e in enumerate(FS_DECISIONS)]

        has_log = bool(entries)
        if has_log:
            (out_dir / "decisions.jsonl").write_text(
                "".join(json.dumps(e) + "\n" for e in entries))
        (out_dir / "run-record.json").write_text(json.dumps({"run_id": run_id}))
        (out_dir / "replay-result.json").write_text(
            json.dumps({"window_epoch_ns": WINDOW}))

        coverage = None
        if has_log:
            wrapper_entries = list(entries)
            if self.phantom:
                # a decision the log does not contain: the run's reported
                # coverage and the log disagree
                wrapper_entries.append(
                    dict(HTTP_DECISIONS[0], timestamp=1.5, allowed=True))
            coverage = reconcile_lib.compute(
                self.spec, wrapper_entries, [], descriptor.design,
                (WINDOW["start"], WINDOW["end"]))

        return {
            "run_id": run_id,
            "harness": descriptor.harness,
            "design": descriptor.design,
            "out_dir": str(out_dir),
            "run_record": str(out_dir / "run-record.json"),
            "status": "pass",
            "coverage": coverage,
            "window_epoch_ns": WINDOW if has_log else None,
            "decision_log": (str(out_dir / "decisions.jsonl")
                             if has_log else None),
            # no decision_stream: the assembly must fall back to the
            # control/gateway producer defaults
            "sensor_present": self.sensor_present,
            "effective_counts": {"checked": len(entries)} if has_log else {},
            "spec_sha256": "f" * 64,
        }


# --- plan expansion to per-design execution ---------------------------------------

def test_one_executor_call_per_design(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1", "t3"]), name="exp.yaml")
    fake = FakeRunExecutor()
    result = execute_experiment(p, run_executor=fake, out_root=tmp_path)

    assert [r.design for r in result.runs] == ["t1", "t3"]
    assert [c[1] for c in fake.calls] == ["exp-t1", "exp-t3"]
    for descriptor, run_id, out_root in fake.calls:
        assert descriptor.control == "agt-gateway"
        assert descriptor.control_binding == "selected"
        assert out_root == tmp_path
    # both run dirs exist under the out root, with the mapped records
    for run in result.runs:
        assert (tmp_path / run.run_id).is_dir()
        assert Path(run.decision_records).is_file()


def test_t0_run_has_no_decision_records(tmp_path):
    p = write_experiment(tmp_path, base_doc(designs=["t0"]))
    fake = FakeRunExecutor()
    result = execute_experiment(p, run_executor=fake, out_root=tmp_path)
    run = result.runs[0]
    assert run.design == "t0"
    assert run.decision_record_count == 0
    assert run.coverage is None                    # no enforcement point
    assert run.coverage_consistent is None
    assert run.findings == []
    # the (empty) mapped-records file is still written per DESIGN.md 9 output
    assert Path(run.decision_records).read_text() == ""


# --- the mapped decision records (v0 AuditEntry -> decision-record/1) -------------

def test_decision_records_mapped_and_valid(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1"]))
    result = execute_experiment(p, run_executor=FakeRunExecutor(),
                                out_root=tmp_path)
    run = result.runs[0]
    lines = [json.loads(l)
             for l in Path(run.decision_records).read_text().splitlines()]
    assert run.decision_record_count == len(lines) == 4
    for record in lines:
        validate_decision_record(record)          # decision-record/1 (C1 view)
        assert record["source_schema"] == V0_AUDIT_ENTRY_SCHEMA
        assert record["run_id"] == run.run_id
        assert record["decision"] == "allow"
        # producer defaults from the descriptor's control (DESIGN.md 4:
        # the v0 emitter is read back through the declared mapping)
        assert record["producer"]["plugin"] == "agt-gateway"
        assert record["producer"]["record_source"] == "ingested"
        assert record["enforcement_point"]["slot_id"] == "gateway"
        assert record["stream_id"] == f"{run.run_id}:gateway"
        # the raw_ref evidence points back at the original log line
        assert record["evidence"][0]["kind"] == "v0-audit-entry"
    assert {r["tool"] for r in lines} == \
        {"post_hook", "get_health", "put_state"}


# --- run manifest contents ----------------------------------------------------------

def test_manifest_records_experiment_hash_and_defaults(tmp_path):
    p = write_experiment(tmp_path, base_doc(designs=["t4"]))  # harness+workload omitted
    result = execute_experiment(p, run_executor=FakeRunExecutor(),
                                out_root=tmp_path)
    manifest = json.loads(result.manifest_path.read_text())
    assert result.manifest_path == tmp_path / "e" / "execution.json"
    assert manifest["experiment"]["path"] == str(p)
    # experiment file hash matches the file bytes
    assert manifest["experiment"]["sha256"] == hashlib.sha256(
        p.read_bytes()).hexdigest()
    resolved = manifest["experiment"]["resolved"]
    assert resolved["harness"] == "pi"
    assert resolved["workload"] == "baseline-15"
    # DESIGN.md 6: omitted fields are recorded as facts, not choices
    assert resolved["defaults_applied"] == {"harness": "pi",
                                           "workload": "baseline-15"}


def test_manifest_stamps_plugin_versions_and_sensor(tmp_path):
    p = write_experiment(tmp_path, base_doc(control="agt-gateway",
                                             designs=["t1"]))
    result = execute_experiment(p, run_executor=FakeRunExecutor(),
                                out_root=tmp_path)
    manifest = result.manifest
    # plugin versions from plugins/*/manifest.json (DESIGN.md 11 claims)
    assert manifest["plugin_versions"]["pi"]["version"] == "1.0.4"
    assert manifest["plugin_versions"]["agt-gateway"]["kind"] == "control"
    # sensor version from env/versions.env (runner-managed, informational)
    assert manifest["sensor"] == sensor_version()
    assert manifest["sensor"]["version"] == \
        load_env_versions()["TRACEE_VERSION"]
    run = manifest["runs"][0]
    # DESIGN.md 9 output: evidence class of a run through the real harness
    assert run["evidence_class"] == "harness-run"
    assert run["degraded"] == []
    assert run["status"] == "pass"
    assert run["coverage"]["status"] == "pass"
    assert run["run_record"].endswith("run-record.json")


def test_fixture_fingerprint_stable_across_executions(tmp_path):
    p = write_experiment(tmp_path, base_doc(control="agt-gateway",
                                             designs=["t1"]), name="exp.yaml")
    first = execute_experiment(p, run_executor=FakeRunExecutor(),
                               out_root=tmp_path)
    second = execute_experiment(p, run_executor=FakeRunExecutor(),
                               out_root=tmp_path)
    # the second execution does not collide with the first's run dir
    assert first.runs[0].run_id == "exp-t1"
    assert second.runs[0].run_id == "exp-t1-2"
    fp1 = first.runs[0].fixture_fingerprint
    fp2 = second.runs[0].fixture_fingerprint
    # DESIGN.md 10 comparability key: compose id + sha256 (+ policy when
    # the design deploys one) — identical across executions
    assert fp1 == fp2
    assert fp1["id"] == "reference-rig/t1"
    assert fp1["compose"]["id"] == "inspection-t1"
    assert fp1["compose"]["sha256"] == hashlib.sha256(
        (ROOT / "compose" / "t1.yaml").read_bytes()).hexdigest()
    assert fp1["enforcement_config"]["path"] == "gateway/policy.yaml"
    # the experiment hash is stable too; only timing/run ids differ
    assert first.manifest["experiment"]["sha256"] == \
        second.manifest["experiment"]["sha256"]


def test_sensor_absent_flags_the_run_degraded(tmp_path):
    p = write_experiment(tmp_path, base_doc(control="agt-gateway",
                                             designs=["t1"]))
    result = execute_experiment(
        p, run_executor=FakeRunExecutor(sensor_present=False),
        out_root=tmp_path)
    run = result.runs[0]
    # DESIGN.md 9: a degraded run is downgraded and flagged, never trusted
    # silently
    assert run.degraded == [execute_mod.SENSOR_ABSENT]
    assert result.manifest["runs"][0]["degraded"] == \
        [execute_mod.SENSOR_ABSENT]


# --- the C1-C4 consistency assertion (recompute vs the run's own coverage) --------

def test_coverage_recomputed_consistent(tmp_path):
    p = write_experiment(tmp_path, base_doc(control="agt-gateway",
                                             designs=["t1"]))
    result = execute_experiment(p, run_executor=FakeRunExecutor(),
                                out_root=tmp_path)
    run = result.runs[0]
    assert run.coverage_consistent is True
    assert run.findings == []
    # the recomputed C1-C4 report passes over the mapped records
    assert run.coverage["status"] == "pass"
    assert {c["id"] for c in run.coverage["checks"]} == \
        {"C1-parse", "C2-accounted", "C3-evaluated", "C4-inspected-only"}
    http = run.coverage["coverage"]["http_tool_call"]
    assert (http["covered"], http["ground_truth"]) == (4, 4)


def test_coverage_mismatch_is_a_finding(tmp_path):
    p = write_experiment(tmp_path, base_doc(control="agt-gateway",
                                             designs=["t1"]))
    result = execute_experiment(
        p, run_executor=FakeRunExecutor(phantom_wrapper_decision=True),
        out_root=tmp_path)
    run = result.runs[0]
    assert run.coverage_consistent is False
    findings = {f["id"]: f for f in run.findings}
    assert "coverage-consistency" in findings
    assert "does not match coverage recomputed" in \
        findings["coverage-consistency"]["detail"]
    # the recomputed coverage itself (from the log as written) still passes:
    # the finding is about the disagreement, recorded, never silent
    assert run.coverage["status"] == "pass"


# --- CLI ----------------------------------------------------------------------------

def test_cli_run_happy_path(tmp_path, capsys, monkeypatch):
    p = write_experiment(tmp_path, base_doc(control="agt-gateway",
                                            designs=["t1"]), name="exp.yaml")
    fake = FakeRunExecutor()
    monkeypatch.setattr(execute_mod, "default_run_executor", fake)
    assert cli_main(["run", str(p), "--out-root", str(tmp_path)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out) == 1
    assert out[0]["design"] == "t1"
    assert out[0]["run_id"] == "exp-t1"
    assert out[0]["evidence_class"] == "harness-run"
    assert out[0]["coverage"] == "pass"
    assert out[0]["coverage_consistent"] is True
    assert out[0]["findings"] == []
    # the execution manifest landed next to the run
    assert (tmp_path / "exp" / "execution.json").is_file()


def test_cli_run_reports_executor_failure(tmp_path, capsys, monkeypatch):
    p = write_experiment(tmp_path, base_doc(control="agt-gateway",
                                            designs=["t1"]))

    def failing(descriptor, run_id, out_root):
        raise RuntimeError("docker: no such container")

    monkeypatch.setattr(execute_mod, "default_run_executor", failing)
    assert cli_main(["run", str(p), "--out-root", str(tmp_path)]) == 1
    assert "no such container" in capsys.readouterr().err


def test_cli_run_exits_nonzero_on_coverage_mismatch(tmp_path, capsys,
                                                    monkeypatch):
    p = write_experiment(tmp_path, base_doc(control="agt-gateway",
                                            designs=["t1"]))
    monkeypatch.setattr(execute_mod, "default_run_executor",
                        FakeRunExecutor(phantom_wrapper_decision=True))
    assert cli_main(["run", str(p), "--out-root", str(tmp_path)]) == 1


# --- the runner programmatic entry (validation only; no Docker) --------------------

def test_run_design_validates_harness_and_design():
    import run as run_mod   # runner/run.py (already on sys.path)
    with pytest.raises(ValueError, match="unknown harness"):
        run_mod.run_design("nope", "t0", "x")
    with pytest.raises(ValueError, match="unknown design"):
        run_mod.run_design("pi", "t9", "x")
    # the t4 pairing is validated before any topology is touched
    with pytest.raises(ValueError, match="unknown design"):
        run_mod.run_design("pi", "t7", "x")
    with pytest.raises(ValueError, match="unknown design"):
        run_mod.run_design("openclaw", "t9", "x")
