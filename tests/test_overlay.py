"""Fixture-overlay mechanism tests (DESIGN.md 7: placeholder base +
control-binding overlay).

Covers the pieces the base+overlay split added:

  - the slot descriptors (compose/slots/<design>.yaml sidecars) load and
    the no-slot designs (t0/t4/t6) declare none;
  - the on-matrix rule (framework/overlay.py validate_overlay): the
    structure-preserving pass for every shipped agt-gateway overlay (the
    4 real-design pairs + the 3 mock pairs), and each violation class:
    missing overlay file, missing slot service, undeclared service,
    auxiliary control-* off the slot's network, modified base service,
    extra top-level structure, slot service without image/build;
  - the custom-fixture flag: a violating overlay flags the run
    off_matrix with the problems recorded (never a load error);
  - the missing-overlay load-time error (a supported design whose
    binding overlay does not exist);
  - fingerprint composition: base hash + overlay hash recorded
    separately; changing either moves the fingerprint; the same pair is
    stable;
  - compose merge validity: every gateway-bearing pair's merged config
    parses (skip when docker is absent, like the existing compose tests)
    and the base alone fails loudly;
  - example resolution: the example experiment files resolve to composed
    fixture ids (reference-rig/<design>+<control>).

Run from the repo root:  python3 -m pytest tests/test_overlay.py -v
"""

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import framework.contracts as contracts  # noqa: E402
from framework import overlay as overlay_mod  # noqa: E402
from framework.cli import main as cli_main  # noqa: E402
from framework.execute import fixture_fingerprint  # noqa: E402
from framework.experiment import (  # noqa: E402
    ExperimentError, load_experiment, resolve,
)
from framework.overlay import (  # noqa: E402
    OverlayError, has_slot, load_slot, overlay_abs_path, overlay_rel_path,
    validate_overlay,
)

AGT = "agt-gateway"
OVERLAY_DIR = ROOT / "plugins" / AGT / "overlay"

# every gateway-bearing (design, fixture) pair: the 4 real designs + the 3
# mock-fixture variants (t5 has no mock fixture: the mock harness supports
# t0..t3 only)
REAL_PAIRS = [("t1", "pi"), ("t2", "pi"), ("t3", "pi"), ("t5", "pi")]
MOCK_PAIRS = [("t1", "mock-harness"), ("t2", "mock-harness"),
             ("t3", "mock-harness")]
ALL_PAIRS = REAL_PAIRS + MOCK_PAIRS

DOCKER = shutil.which("docker") is not None


def write_experiment(tmp_path: Path, doc: dict, name: str = "e.yaml") -> Path:
    p = tmp_path / name
    p.write_text(yaml.safe_dump(doc, sort_keys=False))
    return p


def base_doc(**overrides) -> dict:
    doc = {"schema": 1, "control": None, "designs": ["t0"]}
    doc.update(overrides)
    return doc


def fake_control_plugins(tmp_path: Path, control_id: str,
                         designs=("t1",), overlay_text: str | None = None,
                         mock: bool = False) -> None:
    """A scratch plugin tree: the pi + mock-harness harness manifests (any
    harness the experiment resolves must exist under the patched plugins
    dir) + one control whose binding overlay is `overlay_text` (None =
    ship no overlay file)."""
    for harness in ("pi", "mock-harness"):
        (tmp_path / harness).mkdir()
        (tmp_path / harness / "manifest.json").write_text(
            (ROOT / "plugins" / harness / "manifest.json").read_text())
    plugin = tmp_path / control_id
    plugin.mkdir(parents=True)
    (plugin / "manifest.json").write_text(json.dumps({
        "schema": 1, "id": control_id, "version": "1", "kind": "control",
        "slot_kinds": ["container"], "record_source": "native",
        "can_enforce": "enforce",
        "observable_action_classes": ["http_tool_call"],
        "supported_designs": list(designs)}))
    if overlay_text is not None:
        (plugin / "overlay").mkdir()
        name = "t1-mock.yaml" if mock else "t1.yaml"
        (plugin / "overlay" / name).write_text(overlay_text)


# --- slot descriptors ------------------------------------------------------------

@pytest.mark.parametrize("design", ["t1", "t2", "t3", "t5"])
def test_slot_descriptors_load(design):
    slot = load_slot(design)
    assert slot.design == design
    assert slot.name == "gateway"
    assert slot.service == "gateway"
    assert slot.network == f"{design}net"
    assert slot.log_volume == "gateway-logs"
    # the env convention the base's harness services use to reach the slot
    env = slot.doc.get("harness_env") or {}
    assert ("MCP_GATEWAY_URL" in env) == (design == "t5")
    assert ("GATEWAY_URL" in env) == (design in ("t1", "t2", "t3"))


@pytest.mark.parametrize("design", ["t0", "t4", "t6", "t7"])
def test_no_slot_designs_declare_none(design):
    # t0/t4/t6/t7 have no control slot (DESIGN.md 7): single-file fixtures
    assert has_slot(design) is False
    with pytest.raises(OverlayError, match="no slot descriptor"):
        load_slot(design)


# --- the shipped overlays pass the on-matrix rule ---------------------------------

@pytest.mark.parametrize("design, harness", ALL_PAIRS)
def test_shipped_overlays_are_on_matrix(design, harness):
    """The shipped agt-gateway binding overlays preserve the structure for
    every gateway-bearing pair: exactly the declared slot service, nothing
    else, no base service touched (DESIGN.md 7 on-matrix rule)."""
    rel = overlay_rel_path(AGT, design, harness)
    ok, problems = validate_overlay(design, overlay_abs_path(rel),
                                    harness=harness)
    assert (ok, problems) == (True, [])


def test_real_pairs_resolve_on_matrix(tmp_path):
    for design, harness in ALL_PAIRS:
        doc = {"schema": 1, "control": AGT, "designs": [design]}
        if harness != "pi":
            doc["harness"] = harness
        p = write_experiment(tmp_path, doc,
                             name=f"{design}-{harness}.yaml")
        plan = resolve(load_experiment(p))
        run = plan.runs[0]
        assert run.off_matrix is False
        assert run.overlay_problems == []
        assert run.overlay == overlay_rel_path(AGT, design, harness)
        assert run.fixture == f"reference-rig/{design}+{AGT}"


# --- violation classes ----------------------------------------------------------

def good_overlay(slot_network: str = "t1net") -> str:
    return f"""services:
  gateway:
    image: my-gateway
    networks: [{slot_network}]
    volumes:
      - gateway-logs:/var/log/gateway
"""


def test_violation_missing_file(tmp_path):
    ok, problems = validate_overlay("t1", tmp_path / "nope.yaml")
    assert ok is False
    assert any("no overlay file" in p for p in problems)


def test_violation_missing_slot_service(tmp_path):
    p = tmp_path / "o.yaml"
    p.write_text("services:\n  control-sidecar:\n    image: busybox\n"
                 "    networks: [t1net]\n")
    ok, problems = validate_overlay("t1", p)
    assert ok is False
    assert any("does not define the declared slot service 'gateway'"
               in pr for pr in problems)


def test_violation_undeclared_service(tmp_path):
    p = tmp_path / "o.yaml"
    p.write_text(good_overlay() +
                 "  sidecar:\n    image: busybox\n    networks: [t1net]\n")
    ok, problems = validate_overlay("t1", p)
    assert ok is False
    assert any("undeclared service 'sidecar'" in pr for pr in problems)


def test_violation_auxiliary_service_off_the_slot_network(tmp_path):
    p = tmp_path / "o.yaml"
    # a control-* auxiliary attached to a network the slot does not use
    p.write_text(good_overlay() +
                 "  control-sidecar:\n    image: busybox\n"
                 "    networks: [othernet]\n")
    ok, problems = validate_overlay("t1", p)
    assert ok is False
    assert any("auxiliary service 'control-sidecar' must attach" in pr
               for pr in problems)


def test_auxiliary_control_service_on_slot_netns_passes(tmp_path):
    p = tmp_path / "o.yaml"
    p.write_text(good_overlay() +
                 "  control-sidecar:\n    image: busybox\n"
                 '    network_mode: "service:gateway"\n')
    ok, problems = validate_overlay("t1", p)
    assert (ok, problems) == (True, [])


def test_violation_modifies_base_service(tmp_path):
    p = tmp_path / "o.yaml"
    # redeclaring a base service (pi) is the "modify a base service" class
    p.write_text(good_overlay() +
                 "  pi:\n    image: evil/pi\n    networks: [t1net]\n")
    ok, problems = validate_overlay("t1", p)
    assert ok is False
    assert any("modifies base service(s) ['pi']" in pr for pr in problems)


def test_violation_extra_top_level_structure(tmp_path):
    p = tmp_path / "o.yaml"
    p.write_text(good_overlay() + "\nnetworks:\n  othernet: {}\n")
    ok, problems = validate_overlay("t1", p)
    assert ok is False
    assert any("top-level key(s) ['networks']" in pr for pr in problems)


def test_violation_slot_service_without_image_or_build(tmp_path):
    p = tmp_path / "o.yaml"
    p.write_text("services:\n  gateway:\n    networks: [t1net]\n")
    ok, problems = validate_overlay("t1", p)
    assert ok is False
    assert any("neither image nor build" in pr for pr in problems)


def test_violation_unparseable_overlay(tmp_path):
    p = tmp_path / "o.yaml"
    p.write_text("services:\n  gateway: [unclosed\n")
    ok, problems = validate_overlay("t1", p)
    assert ok is False
    assert any("not parseable YAML" in pr for pr in problems)


def test_violation_design_without_slot(tmp_path):
    p = tmp_path / "o.yaml"
    p.write_text(good_overlay())
    ok, problems = validate_overlay("t4", p)
    assert ok is False
    assert any("no slot descriptor for design 't4'" in pr
               for pr in problems)


def test_violations_flag_the_run_off_matrix_not_an_error(tmp_path):
    """A violating overlay is a custom fixture (DESIGN.md 7): off_matrix with
    the problems recorded, never a load-time error; full fidelity runs."""
    bad_overlay = good_overlay() + \
        "  sidecar:\n    image: busybox\n    networks: [t1net]\n"
    fake_control_plugins(tmp_path, "gateway-x", overlay_text=bad_overlay)
    real_dir = contracts.PLUGINS_DIR
    contracts.PLUGINS_DIR = tmp_path
    try:
        p = write_experiment(tmp_path,
                             base_doc(control="gateway-x", designs=["t1"]))
        plan = resolve(load_experiment(p))   # loads fine: not an error
        run = plan.runs[0]
        assert run.off_matrix is True
        assert run.overlay == "plugins/gateway-x/overlay/t1.yaml"
        assert any("undeclared service 'sidecar'" in pr
                   for pr in run.overlay_problems)
        # the composed fixture id and the overlay binding still resolve
        assert run.fixture == "reference-rig/t1+gateway-x"
    finally:
        contracts.PLUGINS_DIR = real_dir


def test_missing_overlay_for_a_supported_design_is_a_load_error(tmp_path):
    """A manifest claim with no binding behind it fails at load time,
    naming the missing file (DESIGN.md 7)."""
    fake_control_plugins(tmp_path, "gateway-x", overlay_text=None)
    real_dir = contracts.PLUGINS_DIR
    contracts.PLUGINS_DIR = tmp_path
    try:
        p = write_experiment(tmp_path,
                             base_doc(control="gateway-x", designs=["t1"]))
        with pytest.raises(ExperimentError) as exc:
            load_experiment(p)
        assert "ships no binding overlay at " \
               "plugins/gateway-x/overlay/t1.yaml" in str(exc.value)
    finally:
        contracts.PLUGINS_DIR = real_dir


def test_missing_mock_overlay_is_a_load_error(tmp_path):
    """The mock fixture's binding is the <design>-mock variant; a control
    shipping only the real-design overlay fails mock-harness runs at load
    time, naming the missing mock overlay."""
    fake_control_plugins(tmp_path, "gateway-x", overlay_text=good_overlay())
    real_dir = contracts.PLUGINS_DIR
    contracts.PLUGINS_DIR = tmp_path
    try:
        p = write_experiment(tmp_path, base_doc(control="gateway-x",
                                                designs=["t1"],
                                                harness="mock-harness"))
        with pytest.raises(ExperimentError) as exc:
            load_experiment(p)
        assert "plugins/gateway-x/overlay/t1-mock.yaml" in str(exc.value)
    finally:
        contracts.PLUGINS_DIR = real_dir


# --- fingerprint composition (base hash + overlay hash) --------------------------

@pytest.mark.parametrize("design, harness", ALL_PAIRS)
def test_fingerprint_records_base_and_overlay_hashes(design, harness,
                                                      tmp_path):
    doc = {"schema": 1, "control": AGT, "designs": [design]}
    if harness != "pi":
        doc["harness"] = harness
    plan = resolve(load_experiment(write_experiment(
        tmp_path, doc, name=f"{design}-{harness.replace('/', '_')}.yaml")))
    run = plan.runs[0]
    fp = fixture_fingerprint(run)
    assert fp["id"] == f"reference-rig/{design}+{AGT}"
    base_name = f"{design}-mock.yaml" if harness == "mock-harness" \
        else f"{design}.yaml"
    assert fp["compose"]["path"] == f"compose/{base_name}"
    assert fp["compose"]["sha256"] == hashlib.sha256(
        (ROOT / "compose" / base_name).read_bytes()).hexdigest()
    assert fp["overlay"]["path"] == overlay_rel_path(AGT, design, harness)
    assert fp["overlay"]["sha256"] == hashlib.sha256(
        overlay_abs_path(fp["overlay"]["path"]).read_bytes()).hexdigest()
    # the two hashes are recorded separately (a design restructure and a
    # control version bump are each visible on their own)
    assert fp["compose"]["sha256"] != fp["overlay"]["sha256"]


def test_overlay_change_moves_the_fingerprint(tmp_path):
    """Changing the overlay (a control version bump) moves the fingerprint
    without touching the base hash; the same pair is otherwise stable."""
    fake_control_plugins(tmp_path, "gateway-x",
                         overlay_text=good_overlay())
    real_dir = contracts.PLUGINS_DIR
    contracts.PLUGINS_DIR = tmp_path
    try:
        p = write_experiment(tmp_path,
                             base_doc(control="gateway-x", designs=["t1"]))

        def fp() -> dict:
            return fixture_fingerprint(
                resolve(load_experiment(p)).runs[0])

        first, again = fp(), fp()
        assert first == again                 # same pair: stable
        assert first["compose"]["sha256"] == hashlib.sha256(
            (ROOT / "compose" / "t1.yaml").read_bytes()).hexdigest()
        overlay_file = tmp_path / "gateway-x" / "overlay" / "t1.yaml"
        overlay_file.write_text(good_overlay() +
                                "    environment:\n"
                                "      GATEWAY_AGENT_ID: v2\n")
        bumped = fp()
        assert bumped["overlay"]["sha256"] != first["overlay"]["sha256"]
        # the base side is untouched by the control bump
        assert bumped["compose"]["sha256"] == first["compose"]["sha256"]
        assert bumped["enforcement_config"] == first["enforcement_config"]
    finally:
        contracts.PLUGINS_DIR = real_dir


def test_control_null_runs_carry_no_overlay_in_the_fingerprint(tmp_path):
    p = write_experiment(tmp_path, base_doc(designs=["t4"]))
    run = resolve(load_experiment(p)).runs[0]
    fp = fixture_fingerprint(run)
    assert run.overlay is None
    assert "overlay" not in fp
    assert fp["id"] == "reference-rig/t4"


# --- compose merge validity (skip when docker is absent) -------------------------

@pytest.mark.skipif(not DOCKER, reason="docker not available locally")
@pytest.mark.parametrize("design, harness", ALL_PAIRS)
def test_merged_pair_config_parses(design, harness):
    """docker compose config accepts every gateway-bearing base+overlay
    pair (parse-level validation; building/starting the topology is the
    live pass)."""
    base = overlay_mod.base_compose_path(design, harness)
    rel = overlay_rel_path(AGT, design, harness)
    proc = subprocess.run(
        ["docker", "compose", "-f", str(base), "-f",
         str(overlay_abs_path(rel)), "config", "--quiet"],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr


@pytest.mark.skipif(not DOCKER, reason="docker not available locally")
@pytest.mark.parametrize("design, harness", ALL_PAIRS)
def test_base_alone_fails_loudly(design, harness):
    """A base with a declared slot is NOT a validatable unit on its own
    (DESIGN.md 7): compose validation fails loudly, naming the missing slot
    service."""
    base = overlay_mod.base_compose_path(design, harness)
    proc = subprocess.run(
        ["docker", "compose", "-f", str(base), "config", "--quiet"],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode != 0
    assert "depends on undefined service \"gateway\"" in proc.stderr


@pytest.mark.skipif(not DOCKER, reason="docker not available locally")
@pytest.mark.parametrize("design, harness", ALL_PAIRS)
def test_merged_build_context_resolves_to_the_repo_root(design, harness):
    """The overlay's relative build context resolves against the FIRST
    compose file's directory (the base must come first), so the merged
    gateway builds from the repo root, exactly as the single-file fixture
    did."""
    base = overlay_mod.base_compose_path(design, harness)
    rel = overlay_rel_path(AGT, design, harness)
    proc = subprocess.run(
        ["docker", "compose", "-f", str(base), "-f",
         str(overlay_abs_path(rel)), "config", "--format", "json"],
        capture_output=True, text=True, timeout=60)
    assert proc.returncode == 0, proc.stderr
    doc = json.loads(proc.stdout)
    assert doc["services"]["gateway"]["build"]["context"] == str(ROOT)


# --- example resolution: composed fixture ids -------------------------------------

@pytest.mark.parametrize("name, design", [
    ("t1-pi.yaml", "t1"),
    ("t1-openclaw.yaml", "t1"),
    ("t2-pi.yaml", "t2"),
    ("t3-pi.yaml", "t3"),
    ("t5-pi.yaml", "t5"),
    ("t1-mock.yaml", "t1"),
    ("t2-mock.yaml", "t2"),
    ("t3-mock.yaml", "t3"),
])
def test_examples_resolve_to_composed_fixture_ids(name, design, capsys):
    """The example experiment files resolve to the merged fixture ids
    (reference-rig/<design>+agt-gateway) with the overlay binding exercised
    by validate (DESIGN.md 7)."""
    path = ROOT / "examples" / name
    assert cli_main(["validate", str(path)]) == 0
    out = json.loads(capsys.readouterr().out)
    (run,) = out["runs"]
    assert run["fixture"] == f"reference-rig/{design}+{AGT}"
    assert run["overlay_problems"] == []
    assert run["overlay"].startswith(f"plugins/{AGT}/overlay/")


@pytest.mark.parametrize("name", ["t0-pi.yaml", "t0-mock.yaml", "t4-pi.yaml",
                                  "t6-pi.yaml"])
def test_no_slot_examples_stay_plain(name, capsys):
    """The no-slot designs keep the plain per-design fixture id and carry
    no overlay (single-file fixtures, DESIGN.md 7)."""
    path = ROOT / "examples" / name
    assert cli_main(["validate", str(path)]) == 0
    (run,) = json.loads(capsys.readouterr().out)["runs"]
    assert run["overlay"] is None
    assert "+" not in run["fixture"]
