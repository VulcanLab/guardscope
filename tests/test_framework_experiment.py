"""Framework experiment tests (M1 pass 2): experiment-file loading and
semantic validation (DESIGN.md 6) — the four user fields, defaults recorded
as facts, every inapplicable pairing a load-time error naming the conflict,
composition gating, and plan expansion to run descriptors.

Run from the repo root:  python3 -m pytest tests/test_framework_experiment.py -v
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import framework.contracts as contracts  # noqa: E402
from framework.experiment import (  # noqa: E402
    DEFAULT_HARNESS, DEFAULT_WORKLOAD, ExperimentError, load_experiment,
    resolve,
)
from framework.cli import main as cli_main  # noqa: E402


def write_experiment(tmp_path: Path, doc: dict, name: str = "e.yaml",
                     as_json: bool = False) -> Path:
    p = tmp_path / (name + (".json" if as_json else ""))
    if as_json:
        p.write_text(json.dumps(doc))
    else:
        import yaml
        p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return p


def base_doc(**overrides) -> dict:
    doc = {"schema": 1, "control": None, "designs": ["t0"]}
    doc.update(overrides)
    return doc


# --- the four user fields ------------------------------------------------------

def test_all_four_fields_explicit(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1", "t3"], harness="pi",
        workload="baseline-15"))
    exp = load_experiment(p)
    assert exp.control == "agt-gateway"
    assert exp.designs == ["t1", "t3"]
    assert exp.harness == "pi"
    assert exp.workload == "baseline-15"
    assert exp.defaults_applied == {}      # nothing was filled in
    assert exp.off_matrix is False


def test_defaults_recorded_as_facts(tmp_path):
    p = write_experiment(tmp_path, base_doc(designs=["t4"]))
    exp = load_experiment(p)
    assert exp.harness == DEFAULT_HARNESS == "pi"
    assert exp.workload == DEFAULT_WORKLOAD == "baseline-15"
    # DESIGN.md 6: recorded defaults are facts, not requested choices
    assert exp.defaults_applied == {"harness": "pi",
                                    "workload": "baseline-15"}


def test_bare_schema_stamp_required(tmp_path):
    p = write_experiment(tmp_path, base_doc(schema="experiment/1"))
    with pytest.raises(ExperimentError, match="bare literal 1"):
        load_experiment(p)


def test_two_controls_are_inexpressible(tmp_path):
    # DESIGN.md 3: no run-level syntax may name two controls
    p = write_experiment(tmp_path, {"schema": 1,
                                    "control": ["gateway-a", "gateway-b"],
                                    "designs": ["t1"]})
    with pytest.raises(ExperimentError):
        load_experiment(p)


# --- inapplicable pairings are load-time errors ----------------------------------

def test_gateway_control_cannot_occupate_t4(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1", "t4"]))
    with pytest.raises(ExperimentError) as exc:
        load_experiment(p)
    msg = str(exc.value)
    assert "design t4 not applicable to 'agt-gateway'" in msg
    assert "requires harness-intrinsic enforcement" in msg
    assert "occupies gateway slots" in msg


def test_null_control_with_gateway_designs_errors(tmp_path):
    # DESIGN.md 6: control:null is the natural expression of t4/t6 only
    for design in ("t1", "t2", "t3", "t5"):
        p = write_experiment(tmp_path, base_doc(designs=[design]))
        with pytest.raises(ExperimentError) as exc:
            load_experiment(p)
        assert "no control occupies the gateway slot" in str(exc.value)


def test_null_control_with_t4_requires_hostable_harness(tmp_path):
    # pi declares hostable enforcement points: t4/t6 with control:null pass
    p = write_experiment(tmp_path, base_doc(designs=["t4", "t6"],
                                            harness="pi"))
    exp = load_experiment(p)
    assert exp.designs == ["t4", "t6"]

    # a harness declaring no hostable points fails the same request
    plugin = tmp_path / "h-nohost"
    plugin.mkdir(parents=True)
    (plugin / "manifest.json").write_text(json.dumps({
        "schema": 1, "id": "h-nohost", "version": "1",
        "kind": "harness-adapter", "supported_designs": ["t0", "t4", "t6"]}))
    import framework.experiment as experiment_mod
    real_dir = contracts.PLUGINS_DIR
    contracts.PLUGINS_DIR = tmp_path
    try:
        p2 = write_experiment(tmp_path, base_doc(designs=["t4"],
                                                 harness="h-nohost"))
        with pytest.raises(ExperimentError) as exc:
            experiment_mod.load_experiment(p2)
        assert "requires a harness manifest declaring hostable enforcement" \
               " points" in str(exc.value)
    finally:
        contracts.PLUGINS_DIR = real_dir


def test_designs_checked_against_harness_t_modes(tmp_path):
    # pi supports t0-t7 (t7 since 0.2.0); openclaw has no t4 fixture
    p = write_experiment(tmp_path, base_doc(designs=["t4"],
                                            harness="openclaw"))
    with pytest.raises(ExperimentError) as exc:
        load_experiment(p)
    assert "design t4 not supported by harness 'openclaw'" in str(exc.value)
    assert "supported t-modes" in str(exc.value)


def test_control_and_harness_kind_mismatches(tmp_path):
    p = write_experiment(tmp_path, base_doc(control="pi", designs=["t1"]))
    with pytest.raises(ExperimentError, match="kind is 'harness-adapter'"):
        load_experiment(p)
    p = write_experiment(tmp_path, base_doc(harness="agt-gateway",
                                            designs=["t0"]))
    with pytest.raises(ExperimentError, match="kind is 'control'"):
        load_experiment(p)


def test_unknown_control_or_harness(tmp_path):
    p = write_experiment(tmp_path, base_doc(control="nope", designs=["t1"]))
    with pytest.raises(ExperimentError, match="no plugin manifest"):
        load_experiment(p)
    p = write_experiment(tmp_path, base_doc(harness="nope", designs=["t0"]))
    with pytest.raises(ExperimentError, match="no plugin manifest"):
        load_experiment(p)


# --- composition + fixture overrides (DESIGN.md 6, 7) -----------------------------

def composition_doc(**overrides) -> dict:
    doc = base_doc(designs=["t5"], fixture={
        "name": "my-two-gateway-stack",
        "composition": [{"plugin": "gateway-a", "position": "front"},
                        {"plugin": "gateway-b", "position": "back"}]})
    doc.update(overrides)
    return doc


def test_composition_requires_null_control(tmp_path):
    p = write_experiment(tmp_path, composition_doc(control="agt-gateway"))
    with pytest.raises(ExperimentError) as exc:
        load_experiment(p)
    assert "requires control: null" in str(exc.value)


def test_composition_auto_sets_off_matrix(tmp_path):
    # the default harness (pi) must resolve under the patched plugins dir too
    (tmp_path / "pi").mkdir()
    (tmp_path / "pi" / "manifest.json").write_text(
        (ROOT / "plugins" / "pi" / "manifest.json").read_text())
    plugin = tmp_path / "gateway-a"
    plugin.mkdir(parents=True)
    (plugin / "manifest.json").write_text(json.dumps({
        "schema": 1, "id": "gateway-a", "version": "1", "kind": "control",
        "slot_kinds": ["container"], "record_source": "native",
        "can_enforce": "enforce",
        "observable_action_classes": ["http_tool_call"],
        "supported_designs": ["t1", "t5"]}))
    plugin = tmp_path / "gateway-b"
    plugin.mkdir(parents=True)
    (plugin / "manifest.json").write_text(json.dumps({
        "schema": 1, "id": "gateway-b", "version": "1", "kind": "control",
        "slot_kinds": ["container"], "record_source": "native",
        "can_enforce": "enforce",
        "observable_action_classes": ["http_tool_call"],
        "supported_designs": ["t1", "t5"]}))
    real_dir = contracts.PLUGINS_DIR
    contracts.PLUGINS_DIR = tmp_path
    try:
        p = write_experiment(tmp_path, composition_doc())
        exp = load_experiment(p)
        # DESIGN.md 6: the flag need not be written; it is set automatically
        assert exp.off_matrix is True
        assert exp.fixture["composition"][0]["plugin"] == "gateway-a"
    finally:
        contracts.PLUGINS_DIR = real_dir


def test_named_custom_fixture_is_off_matrix(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1"],
        fixture={"name": "my-custom-rig"}))
    exp = load_experiment(p)
    assert exp.off_matrix is True


# --- plan expansion (one run per requested design) --------------------------------

def test_plan_expands_one_run_per_design(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1", "t3"]))
    plan = resolve(load_experiment(p))
    assert [r.design for r in plan.runs] == ["t1", "t3"]
    for run in plan.runs:
        assert run.control == "agt-gateway"
        assert run.control_binding == "selected"   # DESIGN.md 3 emission test
        assert run.harness == "pi"
        assert run.workload == "baseline-15"
        assert run.off_matrix is False
    # DESIGN.md 7 base+overlay: a control-bearing design's fixture id names
    # the composition (base design + bound control)
    assert [r.fixture for r in plan.runs] == \
        ["reference-rig/t1+agt-gateway", "reference-rig/t3+agt-gateway"]
    # the overlay bundle is resolved from the control's plugin dir and
    # passes the on-matrix validation (no problems => stays on-matrix)
    assert [r.overlay for r in plan.runs] == [
        "plugins/agt-gateway/overlay/t1.yaml",
        "plugins/agt-gateway/overlay/t3.yaml"]
    assert all(r.overlay_problems == [] for r in plan.runs)


def test_plan_binding_for_null_control(tmp_path):
    p = write_experiment(tmp_path, base_doc(designs=["t0", "t4", "t6"]))
    plan = resolve(load_experiment(p))
    by_design = {r.design: r for r in plan.runs}
    assert by_design["t0"].control_binding == "none"
    assert by_design["t4"].control_binding == "harness-intrinsic"
    assert by_design["t6"].control_binding == "harness-intrinsic"


def test_plan_flags_t7_observation_only(tmp_path):
    # pi does not support t7; use a synthetic harness that does
    plugin = tmp_path / "h-kernel"
    plugin.mkdir(parents=True)
    (plugin / "manifest.json").write_text(json.dumps({
        "schema": 1, "id": "h-kernel", "version": "1",
        "kind": "harness-adapter",
        "supported_designs": ["t0", "t7"]}))
    real_dir = contracts.PLUGINS_DIR
    contracts.PLUGINS_DIR = tmp_path
    try:
        p = write_experiment(tmp_path, base_doc(designs=["t0", "t7"],
                                                harness="h-kernel"))
        plan = resolve(load_experiment(p))
        by_design = {r.design: r for r in plan.runs}
        # DESIGN.md 7: t7 is the kernel observation row
        assert by_design["t7"].observation_only is True
        assert by_design["t7"].fixture == "reference-rig/t7"
        assert by_design["t0"].observation_only is False
    finally:
        contracts.PLUGINS_DIR = real_dir


def test_t7_control_bound_is_a_kernel_placement(tmp_path):
    """0.2.0: a control-bound t7 run composes the kernel slot — the
    composed fixture id, the binding overlay, and NOT the observation-row
    flag (that stays the control:null expression)."""
    p = write_experiment(tmp_path, base_doc(control="actplane",
                                            designs=["t7"]))
    plan = resolve(load_experiment(p))
    assert len(plan.runs) == 1
    run = plan.runs[0]
    assert run.control_binding == "selected"
    assert run.fixture == "reference-rig/t7+actplane"
    assert run.overlay == "plugins/actplane/overlay/t7.yaml"
    assert run.overlay_problems == []
    assert run.off_matrix is False
    assert run.observation_only is False


def test_t7_example_file_resolves(tmp_path):
    p = ROOT / "examples" / "t7-actplane.yaml"
    plan = resolve(load_experiment(p))
    assert len(plan.runs) == 1
    assert plan.runs[0].design == "t7"
    assert plan.runs[0].observation_only is False


def test_kernel_slot_control_requires_interference_declaration(tmp_path):
    """A control binding kernel slots without the kernel_interference
    declaration is refused at load (DESIGN.md 3 eBPF-enforcing controls)."""
    plugin = tmp_path / "k9"
    plugin.mkdir(parents=True)
    (plugin / "manifest.json").write_text(json.dumps({
        "schema": 1, "id": "k9", "version": "1", "kind": "control",
        "slot_kinds": ["kernel"], "record_source": "ingested",
        "can_enforce": "enforce", "observable_action_classes": ["process_spawn"],
        "supported_designs": ["t7"]}))
    real_dir = contracts.PLUGINS_DIR
    contracts.PLUGINS_DIR = tmp_path
    try:
        with pytest.raises(ExperimentError, match="kernel_interference"):
            load_experiment(
                write_experiment(tmp_path, base_doc(control="k9",
                                                    designs=["t7"])))
    finally:
        contracts.PLUGINS_DIR = real_dir


def test_plan_records_fixture_override_and_off_matrix(tmp_path):
    p = write_experiment(tmp_path, base_doc(
        control="agt-gateway", designs=["t1"],
        fixture={"name": "my-custom-rig"}))
    plan = resolve(load_experiment(p))
    assert plan.runs[0].fixture == "my-custom-rig"
    assert plan.runs[0].off_matrix is True


# --- CLI --------------------------------------------------------------------------

def test_cli_validate_prints_resolved_plan(tmp_path, capsys):
    p = write_experiment(tmp_path, base_doc(designs=["t4"]))
    assert cli_main(["validate", str(p)]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["experiment"]["harness"] == "pi"
    assert out["experiment"]["defaults_applied"]["harness"] == "pi"
    assert out["experiment"]["workload"] == "baseline-15"
    assert out["experiment"]["defaults_applied"]["workload"] == "baseline-15"
    assert [r["design"] for r in out["runs"]] == ["t4"]


def test_cli_validate_reports_load_time_error(tmp_path, capsys):
    p = write_experiment(tmp_path, base_doc(control="agt-gateway",
                                             designs=["t4"]))
    assert cli_main(["validate", str(p)]) == 1
    err = capsys.readouterr().err
    assert "not applicable to 'agt-gateway'" in err


def test_cli_plan_prints_run_descriptors(tmp_path, capsys):
    p = write_experiment(tmp_path, base_doc(control="agt-gateway",
                                             designs=["t1", "t3"]))
    assert cli_main(["plan", str(p)]) == 0
    runs = json.loads(capsys.readouterr().out)
    assert [r["design"] for r in runs] == ["t1", "t3"]
    assert runs[0]["control_binding"] == "selected"
    assert runs[1]["fixture"] == "reference-rig/t3+agt-gateway"
    # plan prints the merged fixture id + both hashes (base compose +
    # control-binding overlay; DESIGN.md 7, 10)
    fp = runs[1]["fixture_fingerprint"]
    assert fp["id"] == "reference-rig/t3+agt-gateway"
    assert fp["compose"]["path"] == "compose/t3.yaml"
    assert fp["overlay"]["path"] == "plugins/agt-gateway/overlay/t3.yaml"
    assert len(fp["compose"]["sha256"]) == 64
    assert len(fp["overlay"]["sha256"]) == 64


def test_cli_accepts_json_experiment_files(tmp_path, capsys):
    p = write_experiment(tmp_path, base_doc(designs=["t0"]), as_json=True)
    assert cli_main(["validate", str(p)]) == 0
    assert json.loads(capsys.readouterr().out)["experiment"]["designs"] == ["t0"]
