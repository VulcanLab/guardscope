"""M2d tests: the loose-end fixes from the M2 live pass.

1. Append-oriented execution manifests (DESIGN.md 10: cell collisions keep
   both rows): a rerun of the same experiment file appends its run entries
   to execution.json (runs = the complete history, current_run_ids = the
   latest execution's runs, executions = per-execution provenance); the
   merged report shows repeated executions as collision rows with a
   recency mark, never as a replacement. Old-format manifests (no history
   fields) still load; a corrupt manifest is refused, never clobbered.
2. Sensor-less key stamping in the merged report (DESIGN.md 9 + 10): a run
   without kernel evidence is keyed by the sensor component "absent", not
   by the manifest's pinned sensor version — sensor and sensor-less runs
   form separate grids by default; --allow-incomparable marks the rows
   non-comparable with the sensor component named.
3. The example experiment files for the design-space live pass validate,
   including the t5 pairing (pi + agt-gateway + t5) validated for the
   first time.

Docker-free: the execution tests inject the same fake run_executor the
execute tests use (test_framework_execute.FakeRunExecutor); the merge
tests consume synthetic execution manifests.

Run from the repo root:  python3 -m pytest tests/test_framework_m2d.py -v
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))
sys.path.insert(0, str(ROOT / "tests"))

from test_framework_execute import (  # noqa: E402
    FakeRunExecutor, base_doc, write_experiment,
)
from framework import report as report_mod  # noqa: E402
from framework.cli import main as cli_main  # noqa: E402
from framework.experiment import load_experiment, resolve  # noqa: E402
from framework.execute import execute_experiment  # noqa: E402
from framework.report import merge_reports  # noqa: E402

# the synthetic manifest's pinned sensor version (env/versions.env value
# shape); sensor runs key on it, sensor-less runs key "absent"
SENSOR_VERSION = "v0.24.1"
WORKLOAD_SHA = "f" * 64


# --- helpers ------------------------------------------------------------------------


def run_entry(run_id: str, design: str = "t1", **overrides) -> dict:
    """One run entry of an execution manifest (the shape
    execute_experiment writes), with per-test overrides."""
    control = None if design == "t4" else "agt-gateway"
    # composed fixture id for control-bearing designs (DESIGN.md 7
    # base+overlay); the plain per-design id for control:null runs
    fixture = (f"reference-rig/{design}+{control}" if control
               else f"reference-rig/{design}")
    doc = {
        "run_id": run_id,
        "design": design,
        "fixture": fixture,
        "control": control,
        "control_binding": "selected" if control else "none",
        "harness": "pi",
        "workload": "baseline-15",
        "off_matrix": False,
        "observation_only": False,
        "run_dir": None,
        "run_record": None,
        "decision_records": {"path": None, "count": 4},
        "fixture_fingerprint": {"id": fixture},
        "evidence_class": "harness-run",
        "degraded": [],
        "status": "pass",
        "coverage": {"status": "pass"},
        "coverage_consistent": True,
        "findings": [],
        "spec_sha256": WORKLOAD_SHA,
    }
    doc.update(overrides)
    return doc


def execution_manifest(runs, created="2026-10-29T10:00:00Z",
                       executions=None, current_run_ids=None,
                       sensor=None) -> dict:
    """An execution.json document; by default the NEW append-oriented
    shape (executions + current_run_ids), or the OLD shape when the
    history fields are passed as None."""
    doc = {
        "schema": 1, "created": created,
        "experiment": {"path": "examples/exp.yaml", "sha256": "c" * 64,
                       "resolved": {"control": "agt-gateway",
                                    "designs": ["t1"], "harness": "pi",
                                    "workload": "baseline-15"}},
        "plugin_versions": {"pi": {"version": "1.0.4",
                                   "kind": "harness-adapter"}},
        "sensor": sensor or {"instrument": "tracee",
                             "version": SENSOR_VERSION},
        "runs": runs,
    }
    if executions is not None:
        doc["executions"] = executions
    if current_run_ids is not None:
        doc["current_run_ids"] = current_run_ids
    return doc


def write_execution(out_root: Path, exp_id: str, doc: dict) -> Path:
    exp_dir = out_root / exp_id
    exp_dir.mkdir(parents=True, exist_ok=True)
    for run in doc["runs"]:
        if run.get("run_dir"):
            Path(run["run_dir"]).mkdir(parents=True, exist_ok=True)
    path = exp_dir / "execution.json"
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n")
    return path


# --- 1. append-oriented execution manifests -----------------------------------------


def test_first_execution_records_history_fields(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1"]), name="exp.yaml")
    result = execute_experiment(p, run_executor=FakeRunExecutor(),
                                out_root=tmp_path)
    manifest = json.loads(result.manifest_path.read_text())
    assert [r["run_id"] for r in manifest["runs"]] == ["exp-t1"]
    # the latest execution's runs are named in current_run_ids
    assert manifest["current_run_ids"] == ["exp-t1"]
    # one history entry per execution, with its own sensor pins
    (execution,) = manifest["executions"]
    assert execution["run_ids"] == ["exp-t1"]
    assert execution["experiment_sha256"] == manifest["experiment"]["sha256"]
    assert execution["sensor"] == manifest["sensor"]
    # every run entry carries its execution time
    assert manifest["runs"][0]["executed_at"] == execution["executed_at"]


def test_rerun_appends_run_history_never_replaces(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1"]), name="exp.yaml")
    first = execute_experiment(p, run_executor=FakeRunExecutor(),
                               out_root=tmp_path)
    second = execute_experiment(p, run_executor=FakeRunExecutor(),
                                out_root=tmp_path)
    # fresh run ids: the second execution does not collide with the first
    assert [r.run_id for r in second.runs] == ["exp-t1-2"]
    manifest = json.loads(second.manifest_path.read_text())
    # runs lists EVERY run ever executed under this experiment, in order;
    # no entry was removed (DESIGN.md 10: collisions keep both rows)
    assert [r["run_id"] for r in manifest["runs"]] == ["exp-t1", "exp-t1-2"]
    assert manifest["current_run_ids"] == ["exp-t1-2"]
    assert [e["run_ids"] for e in manifest["executions"]] == \
        [["exp-t1"], ["exp-t1-2"]]
    # the earlier entry is untouched, the new one carries its own stamp
    assert manifest["runs"][0] == first.manifest["runs"][0]
    assert manifest["runs"][1]["executed_at"] == \
        manifest["executions"][1]["executed_at"]
    # the manifest's created stays the first creation (history is a fact)
    assert manifest["created"] == first.manifest["created"]
    # the per-execution result keeps its shape: only this execution's runs
    assert [r.run_id for r in second.runs] == \
        [rid for rid in manifest["current_run_ids"]]


def test_rerun_surfaces_as_collision_rows_in_the_merged_grid(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1"]), name="exp.yaml")
    execute_experiment(p, run_executor=FakeRunExecutor(), out_root=tmp_path)
    execute_experiment(p, run_executor=FakeRunExecutor(), out_root=tmp_path)
    exec_path = tmp_path / "exp" / "execution.json"
    report = merge_reports([exec_path])
    # both executions of the same control x design cell are distinct
    # evidence rows; one is recency-marked current; nothing averaged
    (grid,) = report["grids"]
    (column,) = grid["columns"]
    assert {r["run_id"] for r in column["rows"]} == {"exp-t1", "exp-t1-2"}
    current = [r for r in column["rows"] if r["current"]]
    assert len(current) == 1
    assert current[0]["run_id"] == "exp-t1-2"   # the later execution
    older = [r for r in column["rows"] if not r["current"]]
    assert older[0]["run_id"] == "exp-t1"
    # each row keeps its own executed-at (never merged, never averaged)
    assert column["rows"][0]["executed_at"] <= column["rows"][1]["executed_at"]


def test_old_format_manifest_still_loads_and_appends(tmp_path):
    # an execution.json without the history fields (the old overwrite-era
    # format) loads unchanged: the rerun appends, and the earlier run's
    # provenance is synthesized into the executions history, never dropped
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1"]), name="exp.yaml")
    old_run = run_entry("exp-t1", run_dir=str(tmp_path / "exp-t1"))
    # the old format: no executed_at per run, no executions/current_run_ids
    old_manifest = execution_manifest([old_run], created="2026-10-01T09:00:00Z",
                                      executions=None, current_run_ids=None)
    write_execution(tmp_path, "exp", old_manifest)
    (tmp_path / "exp-t1").mkdir(parents=True, exist_ok=True)

    result = execute_experiment(p, run_executor=FakeRunExecutor(),
                                out_root=tmp_path)
    manifest = json.loads(result.manifest_path.read_text())
    assert [r["run_id"] for r in manifest["runs"]] == ["exp-t1", "exp-t1-2"]
    assert manifest["current_run_ids"] == ["exp-t1-2"]
    # the prior execution's facts are synthesized from the old manifest
    assert manifest["executions"][0] == {
        "executed_at": "2026-10-01T09:00:00Z",
        "run_ids": ["exp-t1"],
        "experiment_sha256": "c" * 64,
        "sensor": {"instrument": "tracee", "version": SENSOR_VERSION},
    }
    # the old run entry itself is untouched
    assert manifest["runs"][0] == old_run
    # the old manifest still merges (backward compatible at report level)
    report = merge_reports([result.manifest_path])
    (column,) = report["grids"][0]["columns"]
    assert len(column["rows"]) == 2


def test_corrupt_execution_manifest_is_refused_not_clobbered(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1"]), name="exp.yaml")
    exp_dir = tmp_path / "exp"
    exp_dir.mkdir(parents=True)
    (exp_dir / "execution.json").write_text("{not json")
    with pytest.raises(ValueError, match="refusing to overwrite"):
        execute_experiment(p, run_executor=FakeRunExecutor(), out_root=tmp_path)
    # the corrupt file is still there, byte for byte
    assert (exp_dir / "execution.json").read_text() == "{not json"


# --- 2. sensor-less key stamping in the merged report --------------------------------


def test_sensorless_run_is_keyed_absent_and_splits_grids(tmp_path):
    # one manifest holding a sensor run and a sensor-less run of the same
    # design: separate grids by default; the sensor component is named
    sensor_run = run_entry("run-sensor", run_dir=str(tmp_path / "run-sensor"))
    sensorless_run = run_entry(
        "run-degraded", run_dir=str(tmp_path / "run-degraded"),
        evidence_class="self-reported", degraded=["sensor-absent"])
    path = write_execution(tmp_path, "exp", execution_manifest(
        [sensor_run, sensorless_run]))
    report = merge_reports([path])
    assert len(report["grids"]) == 2
    keys = {g["key"]["kernel_sensor_version"] for g in report["grids"]}
    # the sensor-less run is keyed "absent", never the pinned version
    assert keys == {SENSOR_VERSION, report_mod.SENSOR_ABSENT_KEY}
    # the split warning names the sensor component (not a generic label)
    assert any("kernel_sensor_version" in w for w in report["warnings"])


def test_sensorless_non_comparable_reason_names_the_sensor_component(tmp_path):
    sensor_run = run_entry("run-sensor", run_dir=str(tmp_path / "run-sensor"))
    sensorless_run = run_entry(
        "run-degraded", run_dir=str(tmp_path / "run-degraded"),
        evidence_class="self-reported", degraded=["sensor-absent"])
    path = write_execution(tmp_path, "exp", execution_manifest(
        [sensor_run, sensorless_run]))
    report = merge_reports([path], allow_incomparable=True)
    # one forced grid; the sensor-less row carries a per-cell mark naming
    # the sensor component and its "absent" value (visible, never averaged)
    (grid,) = report["grids"]
    marked = [r for c in grid["columns"] for r in c["rows"]
              if r.get("non_comparable")]
    assert len(marked) == 1
    assert any("kernel_sensor_version" in reason
               for reason in marked[0]["non_comparable"])
    assert any(report_mod.SENSOR_ABSENT_KEY in reason
               for reason in marked[0]["non_comparable"])


def test_self_reported_evidence_class_alone_keys_the_sensor_absent(tmp_path):
    # the degraded marker and the evidence class are two ways the execution
    # summary says sensor-less (DESIGN.md 9); either is enough to key
    # "absent" — a run labeled self-reported must never share a grid key
    # with a kernel-verified run
    sensor_run = run_entry("run-sensor", run_dir=str(tmp_path / "run-sensor"))
    self_reported = run_entry(
        "run-self-reported", run_dir=str(tmp_path / "run-self-reported"),
        evidence_class="self-reported")
    path = write_execution(tmp_path, "exp", execution_manifest(
        [sensor_run, self_reported]))
    report = merge_reports([path])
    assert len(report["grids"]) == 2
    degraded_grid = next(g for g in report["grids"]
                        if g["key"]["kernel_sensor_version"]
                        == report_mod.SENSOR_ABSENT_KEY)
    (column,) = degraded_grid["columns"]
    assert column["rows"][0]["run_id"] == "run-self-reported"


def test_sensor_run_key_still_uses_the_pinned_sensor_version(tmp_path):
    # a sensor run's key component is the manifest's pinned sensor version,
    # exactly as before (only sensor-less runs are re-keyed)
    sensor_run = run_entry("run-sensor", run_dir=str(tmp_path / "run-sensor"))
    path = write_execution(tmp_path, "exp",
                           execution_manifest([sensor_run]))
    report = merge_reports([path])
    assert report["grids"][0]["key"]["kernel_sensor_version"] == SENSOR_VERSION


# --- 3. the example experiment files validate ---------------------------------------


def test_example_files_load_and_resolve():
    for name in ("t2-pi", "t3-pi", "t4-pi", "t5-pi", "t1-openclaw"):
        experiment = load_experiment(ROOT / "examples" / f"{name}.yaml")
        plan = resolve(experiment)
        assert len(plan.runs) == 1
        assert experiment.workload == "baseline-15"


def test_example_t5_pairs_pi_with_the_gateway():
    # the first-validated pairing: pi + agt-gateway + t5 — the harness
    # chain (harness-intrinsic) plus the selected gateway (DESIGN.md 7)
    experiment = load_experiment(ROOT / "examples" / "t5-pi.yaml")
    assert experiment.control == "agt-gateway"
    assert experiment.harness == "pi"
    assert experiment.designs == ["t5"]
    plan = resolve(experiment)
    assert plan.runs[0].control_binding == "selected"
    assert report_mod.ORIGIN_LABELS["t5"] == ["selected", "harness-intrinsic"]


def test_example_t4_selects_no_control():
    # t4's permission chain is harness-intrinsic: control null, the
    # natural expression of T4 (DESIGN.md 6)
    experiment = load_experiment(ROOT / "examples" / "t4-pi.yaml")
    assert experiment.control is None
    assert experiment.designs == ["t4"]
    plan = resolve(experiment)
    assert plan.runs[0].control_binding == "harness-intrinsic"


def test_cli_validate_examples(tmp_path, capsys):
    for name in ("t2-pi", "t3-pi", "t4-pi", "t5-pi", "t1-openclaw"):
        assert cli_main(["validate",
                         str(ROOT / "examples" / f"{name}.yaml")]) == 0
