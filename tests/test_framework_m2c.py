"""M2c tests: the conformance kit (framework/conformance.py, DESIGN.md 3
L1/L2), the registry (framework/registry.py + registry/, DESIGN.md 11), and
the report-level derived summary rows (framework/report.py, DESIGN.md 10).

Docker-free: L1 runs over the recorded live t1 golden set (the trimmed
live-run fixture under tests/fixtures/live-runs/t1-pi-t1-2, whose log is the
actual recorded gateway decisions.jsonl — its sha256 matches the artifact
hash in the run's own manifest); L2 drives the reference InProcessControl
through the full lifecycle (framework/contracts). The registry is exercised
against both the seeded open-tier data and synthetic registry roots.

Run from the repo root:  python3 -m pytest tests/test_framework_m2c.py -v
"""

import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from framework import registry as registry_mod  # noqa: E402
from framework import report as report_mod  # noqa: E402
from framework.cli import main as cli_main  # noqa: E402
from framework.conformance import (  # noqa: E402
    FORMAT_V0, KIT_VERSION, SUITE_VERSION, T1_EXPECTED_OUTCOMES,
    golden_fixture_hash, golden_log_set_from_run_dir, run_l1, run_l2,
    suite_golden_fixture_hash, suite_golden_log_set,
)
from framework.contracts import CONTROL_CONTRACT_VERSION  # noqa: E402
from framework.contracts import InProcessControl, READINESS_TOOL  # noqa: E402
from framework.records import map_audit_entries, make_dispatch_record  # noqa: E402
from framework.report import merge_reports  # noqa: E402
from framework.registry import (  # noqa: E402
    RegistryError, current_keys, eligible_for_main_grid, is_verdict_current,
    load_fact_docs, load_verdict_docs, record_facts, record_verdict,
)

LIVE_RUNS = ROOT / "tests" / "fixtures" / "live-runs"
T1_RUN_DIR = LIVE_RUNS / "t1-pi-t1-2"
T1_EXEC = LIVE_RUNS / "t1-pi" / "execution.json"
T0_EXEC = LIVE_RUNS / "t0-pi" / "execution.json"

AGT_PLUGIN_ID = "agt-gateway"
AGT_PLUGIN_VERSION = "0.1.0"


# --- shared helpers -------------------------------------------------------------------


def live_t1_golden_set() -> dict:
    return golden_log_set_from_run_dir(T1_RUN_DIR, plugin_id=AGT_PLUGIN_ID)


def l1_over_live_t1(**overrides):
    kwargs = dict(golden_log_set=live_t1_golden_set(),
                  expected_outcomes=T1_EXPECTED_OUTCOMES,
                  plugin_id=AGT_PLUGIN_ID, plugin_version=AGT_PLUGIN_VERSION,
                  suite_version=SUITE_VERSION)
    kwargs.update(overrides)
    return run_l1(**kwargs)


def write_registry_copy(tmp_path) -> Path:
    """A copy of the seeded registry (so tests never mutate the repo data)."""
    root = tmp_path / "registry"
    shutil.copytree(ROOT / "registry", root)
    return root


# ================================================================ L1 (DESIGN.md 3)


def test_l1_passes_over_the_live_t1_golden_set():
    verdict = l1_over_live_t1()
    assert verdict["status"] == "pass"
    assert verdict["level"] == "L1"
    assert verdict["findings"] == []
    assert [(c["id"], c["status"]) for c in verdict["checks"]] == [
        ("L1-parse", "pass"), ("L1-format", "pass"), ("L1-schema", "pass"),
        ("L1-producer", "pass"), ("C1-parse", "pass"), ("C2-accounted", "pass"),
        ("C4-inspected-only", "pass"), ("C3-evaluated", "pass"),
        ("L1-outcomes", "pass")]
    # the golden set auto-detected as v0 AuditEntry lines and mapped through
    # the reader-side mapping (DESIGN.md 4)
    assert verdict["golden_set"]["format"] == FORMAT_V0
    assert verdict["golden_set"]["records"] == 8
    # 4 http checked + 11 bypassed (the brief's expected outcomes for t1)
    assert verdict["derived_outcomes"]["http_tool_call"] == \
        {"checked-allowed": 4}
    assert sum(v.get("bypassed", 0)
               for v in verdict["derived_outcomes"].values()) == 11
    # the verdict carries the registry key components (DESIGN.md 11)
    assert verdict["kit_version"] == KIT_VERSION
    assert verdict["suite_version"] == SUITE_VERSION
    assert verdict["contract_version"] == CONTROL_CONTRACT_VERSION
    assert verdict["plugin_id"] == AGT_PLUGIN_ID
    assert verdict["plugin_version"] == AGT_PLUGIN_VERSION


def test_l1_golden_log_is_the_recorded_live_artifact():
    # the trimmed fixture log is byte-identical to the recorded live
    # decisions.jsonl: its sha256 matches the artifact hash the run's own
    # manifest recorded (no golden set was invented in the trimming)
    manifest = json.loads((T1_RUN_DIR / "manifest.json").read_text())
    recorded = manifest["artifacts"]["gateway-decisions"]["sha256"]
    actual = hashlib.sha256(
        (T1_RUN_DIR / "decisions.jsonl").read_bytes()).hexdigest()
    assert actual == recorded


def test_l1_outcomes_match_the_recorded_live_outcomes():
    # cross-check against the run's own outcomes.json (not just the constant)
    outcomes = json.loads((T1_RUN_DIR / "outcomes.json").read_text())
    verdict = l1_over_live_t1()
    derived = verdict["derived_outcomes"]
    for cls, counts in derived.items():
        for outcome, n in counts.items():
            recorded = sum(1 for row in outcomes["per_action"]
                           if row["class"] == cls and row["outcome"] == outcome)
            assert n == recorded, (cls, outcome)
    assert outcomes["counts"]["bypassed"] == 11
    assert outcomes["checked_total"] == 4


def test_l1_window_scopes_the_warmup_lines():
    # the recorded log carries 4 warmup lines from the previous run (the
    # gateway volume persisted across runs); the manifest's measurement
    # window scopes them out — without it, C2 fails
    verdict = l1_over_live_t1()
    assert verdict["status"] == "pass"
    golden = live_t1_golden_set()
    golden["window"] = None
    verdict = run_l1(golden, T1_EXPECTED_OUTCOMES, plugin_id=AGT_PLUGIN_ID,
                     plugin_version=AGT_PLUGIN_VERSION,
                     suite_version=SUITE_VERSION)
    assert verdict["status"] == "fail"
    failed = {c["id"] for c in verdict["findings"]}
    assert "C2-accounted" in failed


def test_l1_schema_invalid_record_fails():
    # a decision-record/1 golden set with one schema-invalid record: the
    # verdict fails naming the line, never a silent skip
    records = map_audit_entries(
        live_t1_golden_set()["lines"],
        run_id="t1-pi-t1-2", stream_id="t1-pi-t1-2:gateway",
        product_version="3.7.0", plugin_version=AGT_PLUGIN_VERSION,
        plugin=AGT_PLUGIN_ID)
    del records[2]["policy"]          # a required field gone (the format
                                     # detection keys on 'decision', so the
                                     # /1 shape is still detected first)
    verdict = run_l1({"lines": records, "format": "auto",
                      "run_id": "t1-pi-t1-2", "design": "t1",
                      "window": live_t1_golden_set()["window"]},
                     T1_EXPECTED_OUTCOMES, plugin_id=AGT_PLUGIN_ID,
                     plugin_version=AGT_PLUGIN_VERSION,
                     suite_version=SUITE_VERSION)
    assert verdict["status"] == "fail"
    schema = next(c for c in verdict["findings"] if c["id"] == "L1-schema")
    assert "line 3" in schema["detail"]


def test_l1_outcome_shaped_key_in_a_record_fails():
    # a record carrying a reconciler-only key (DESIGN.md 4: outcomes are
    # derived only by the reconciler) fails schema validation
    records = map_audit_entries(
        live_t1_golden_set()["lines"],
        run_id="t1-pi-t1-2", stream_id="t1-pi-t1-2:gateway",
        product_version="3.7.0", plugin_version=AGT_PLUGIN_VERSION,
        plugin=AGT_PLUGIN_ID)
    records[0]["verdict"] = "allowed"
    verdict = run_l1({"lines": records, "format": "auto",
                      "run_id": "t1-pi-t1-2", "design": "t1",
                      "window": live_t1_golden_set()["window"]},
                     T1_EXPECTED_OUTCOMES, plugin_id=AGT_PLUGIN_ID,
                     plugin_version=AGT_PLUGIN_VERSION,
                     suite_version=SUITE_VERSION)
    assert verdict["status"] == "fail"
    assert any(c["id"] == "L1-schema" for c in verdict["findings"])


def test_l1_wrong_expected_outcomes_fail():
    # the same golden set, a wrong expectation: checked-denied where the
    # records allowed -> fail naming the class
    wrong = dict(T1_EXPECTED_OUTCOMES)
    wrong["http_tool_call"] = "checked-denied"
    verdict = l1_over_live_t1(expected_outcomes=wrong)
    assert verdict["status"] == "fail"
    outcomes = next(c for c in verdict["findings"]
                    if c["id"] == "L1-outcomes")
    assert "http_tool_call" in outcomes["detail"]
    # a missing class in the expectations fails too (exact comparison)
    wrong = {k: v for k, v in T1_EXPECTED_OUTCOMES.items()
             if k != "stdio_tool_call"}
    verdict = l1_over_live_t1(expected_outcomes=wrong)
    assert verdict["status"] == "fail"


def test_l1_accepts_decision_record_lines_and_detects_v0():
    # the same golden set as decision-record/1 lines (mapped first): the
    # auto-detection picks the /1 shape and the verdict still passes
    golden = live_t1_golden_set()
    records = map_audit_entries(
        golden["lines"], run_id=golden["run_id"],
        stream_id=f"{golden['run_id']}:gateway", product_version="3.7.0",
        plugin_version=AGT_PLUGIN_VERSION, plugin=AGT_PLUGIN_ID)
    verdict = run_l1({"lines": records, "format": "auto",
                      "run_id": golden["run_id"], "design": "t1",
                      "window": golden["window"]},
                     T1_EXPECTED_OUTCOMES, plugin_id=AGT_PLUGIN_ID,
                     plugin_version=AGT_PLUGIN_VERSION,
                     suite_version=SUITE_VERSION)
    assert verdict["status"] == "pass"
    assert verdict["golden_set"]["format"] == "decision-record/1"
    # the explicit count form works too
    expected = {"http_tool_call": {"checked-allowed": 4},
                "stdio_tool_call": {"bypassed": 3},
                "direct_network": {"bypassed": 2},
                "process_spawn": {"bypassed": 2},
                "file_write": {"bypassed": 2},
                "credential_access": {"bypassed": 2}}
    verdict = run_l1({"lines": records, "format": "auto",
                      "run_id": golden["run_id"], "design": "t1",
                      "window": golden["window"]},
                     expected, plugin_id=AGT_PLUGIN_ID,
                     plugin_version=AGT_PLUGIN_VERSION,
                     suite_version=SUITE_VERSION)
    assert verdict["status"] == "pass"


def test_l1_mixed_formats_fail():
    golden = live_t1_golden_set()
    records = map_audit_entries(
        golden["lines"], run_id=golden["run_id"],
        stream_id=f"{golden['run_id']}:gateway", product_version="3.7.0",
        plugin_version=AGT_PLUGIN_VERSION, plugin=AGT_PLUGIN_ID)
    mixed = list(records) + list(golden["lines"])
    verdict = run_l1({"lines": mixed, "format": "auto", "design": "t1"},
                     T1_EXPECTED_OUTCOMES, plugin_id=AGT_PLUGIN_ID,
                     plugin_version=AGT_PLUGIN_VERSION,
                     suite_version=SUITE_VERSION)
    assert verdict["status"] == "fail"
    fmt = next(c for c in verdict["findings"] if c["id"] == "L1-format")
    assert "mixed" in fmt["detail"]


def test_l1_verdicts_are_deterministic():
    # no wall-clock time inside a verdict: the same golden set reproduces
    # the same verdict byte-for-byte (registry ingestion relies on this)
    first = l1_over_live_t1()
    second = l1_over_live_t1()
    assert first == second
    assert first["golden_fixture_hash"] == suite_golden_fixture_hash()


def test_l1_run_dir_path_form():
    # the golden set accepted as the recorded run dir path
    verdict = run_l1(T1_RUN_DIR, T1_EXPECTED_OUTCOMES,
                     plugin_id=AGT_PLUGIN_ID, plugin_version=AGT_PLUGIN_VERSION,
                     suite_version=SUITE_VERSION)
    assert verdict["status"] == "pass"


# ================================================================ L2 (DESIGN.md 3)


def wired_control(cls=InProcessControl, plugin_id="test-control",
                  plugin_version="1"):
    """A control (InProcessControl by default) plus the fidelity seams
    wired through THAT instance."""
    control = cls(plugin_id=plugin_id, plugin_version=plugin_version)

    def issuer(transport, action_id, attempt):
        control.evaluate({"tool": "post_hook", "class": "http_tool_call",
                          "protocol": "http", "action_id": action_id,
                          "attempt": attempt, "parameters": {}})

    def collector():
        return control.collect()["records"]

    return control, issuer, collector


def run_l2_default(control, issuer, collector, **overrides):
    kwargs = dict(golden_log_set=suite_golden_log_set(),
                  expected_outcomes=T1_EXPECTED_OUTCOMES,
                  suite_version=SUITE_VERSION)
    kwargs.update(overrides)
    return run_l2(control, issuer=issuer, collector=collector, **kwargs)


def test_l2_full_lifecycle_passes_with_inprocess_control():
    control, issuer, collector = wired_control()
    verdict = run_l2_default(control, issuer, collector)
    assert verdict["status"] == "pass"
    assert verdict["level"] == "L2"
    assert verdict["findings"] == []
    ids = [c["id"] for c in verdict["checks"]]
    # the full lifecycle per DESIGN.md 3: provision, configure, ready
    # (enforcement proof), replay, collect, teardown
    assert ["L2-describe", "L2-provision", "L2-configure", "L2-ready-proof",
            "L2-ready", "L2-window", "L2-replay", "L2-collect",
            "L2-policy-fingerprint", "L2-fidelity", "L2-teardown"] == ids
    # the canonical replay drove the design's inspected class only
    assert verdict["lifecycle"]["driven_actions"] == 4
    assert verdict["lifecycle"]["records_collected"] == 4
    # L1 over the collected records passed with the expected outcomes
    assert verdict["l1"]["status"] == "pass"
    assert verdict["l1"]["derived_outcomes"]["http_tool_call"] == \
        {"checked-allowed": 4}
    # the fidelity check published per-transport capability flags
    assert verdict["fidelity"]["status"] == "pass"
    assert verdict["capability_flags"] == {"preserves_meta": True,
                                           "preserves_header": True}
    # teardown ran and left the control torn down
    assert control.state == "torn_down"
    # the verdict carries the registry key components (DESIGN.md 11)
    assert verdict["plugin_id"] == "test-control"
    assert verdict["plugin_version"] == "1"
    assert verdict["golden_fixture_hash"] == suite_golden_fixture_hash()


def test_l2_enforcement_ready_failure_fails_the_verdict():
    # a control whose enforcement point allows the readiness test action:
    # enforcement is not proven, the verdict fails (a started container is
    # not ready; DESIGN.md 3)
    class AllowAllControl(InProcessControl):
        def evaluate(self, action):
            record = super().evaluate(action)
            record["decision"] = "allow"
            return record

    control, issuer, collector = wired_control(AllowAllControl)
    verdict = run_l2_default(control, issuer, collector)
    assert verdict["status"] == "fail"
    proof = next(c for c in verdict["findings"]
                 if c["id"] == "L2-ready-proof")
    assert "deny decision record" in proof["detail"]


def test_l2_policy_fingerprint_mismatch_fails_the_verdict():
    # DESIGN.md 3 configure(): the returned fingerprint must match
    # policy.policy_hash in emitted records
    class BadHashControl(InProcessControl):
        def evaluate(self, action):
            record = super().evaluate(action)
            record["policy"]["policy_hash"] = "0" * 64
            return record

    control, issuer, collector = wired_control(BadHashControl)
    verdict = run_l2_default(control, issuer, collector)
    assert verdict["status"] == "fail"
    check = next(c for c in verdict["findings"]
                if c["id"] == "L2-policy-fingerprint")
    assert "fingerprint" in check["detail"]


def test_l2_fidelity_strip_fails_the_verdict():
    # a control that strips the marked ids on inspectable traffic is a
    # reportable defect (DESIGN.md 5): the fidelity check fails, so L2 fails
    class StripControl(InProcessControl):
        def evaluate(self, action):
            action = dict(action, action_id=None)
            return super().evaluate(action)

    control, issuer, collector = wired_control(StripControl)
    verdict = run_l2_default(control, issuer, collector)
    assert verdict["status"] == "fail"
    assert verdict["fidelity"]["status"] == "fail"
    assert next(c for c in verdict["findings"]
                if c["id"] == "L2-fidelity")
    assert verdict["capability_flags"]["preserves_meta"] is False


def test_l2_native_badge_requires_harness_run_evidence():
    control, issuer, collector = wired_control()
    # no evidence: badge denied with a reason, the verdict is still recorded
    verdict = run_l2_default(control, issuer, collector)
    assert verdict["status"] == "pass"          # the badge is not the status
    assert verdict["badge"]["native"] is False
    assert "harness-run" in verdict["badge"]["reason"]
    assert verdict["badge"]["evidence"] is None

    # empty evidence dir: denied with a reason naming the stream
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        empty_dir = Path(td)
        control, issuer, collector = wired_control()
        verdict = run_l2_default(control, issuer, collector,
                                 harness_run_evidence=empty_dir)
        assert verdict["badge"]["native"] is False
        assert "dispatch stream" in verdict["badge"]["reason"]
        assert verdict["status"] == "pass"      # still recorded, still pass

        # a run dir with a non-empty dispatch stream: the badge is earned
        run_dir = empty_dir / "run-with-harness"
        run_dir.mkdir()
        (run_dir / "dispatch-records.jsonl").write_text(
            json.dumps(make_dispatch_record(
                run_id="harness-run", action_id="a011",
                carrier_used="mcp_meta",
                result={"status": "dispatched"})) + "\n")
        control, issuer, collector = wired_control()
        verdict = run_l2_default(control, issuer, collector,
                                 harness_run_evidence=run_dir)
        assert verdict["badge"]["native"] is True
        assert "dispatch record" in verdict["badge"]["reason"]
        assert verdict["status"] == "pass"

        # a dispatch file with no VALID dispatch records does not count
        bad_dir = empty_dir / "run-bad"
        bad_dir.mkdir()
        (bad_dir / "dispatch-records.jsonl").write_text(
            "not json at all\n{\"schema\": 1}\n")
        control, issuer, collector = wired_control()
        verdict = run_l2_default(control, issuer, collector,
                                 harness_run_evidence=bad_dir)
        assert verdict["badge"]["native"] is False
        assert "no valid dispatch-record/1" in verdict["badge"]["reason"]


def test_l2_publishes_fidelity_flags_to_plugin_dir(tmp_path):
    # when the plugin ships a manifest, the measured capability flags are
    # published to plugins/<id>/fidelity.json (framework/fidelity)
    plugins_dir = tmp_path / "plugins"
    plugin_dir = plugins_dir / "test-control"
    plugin_dir.mkdir(parents=True)
    manifest = json.loads((ROOT / "plugins" / "agt-gateway" /
                          "manifest.json").read_text())
    manifest.update({"id": "test-control", "kind": "control"})
    (plugin_dir / "manifest.json").write_text(json.dumps(manifest))
    control, issuer, collector = wired_control()
    verdict = run_l2_default(control, issuer, collector,
                             plugins_dir=plugins_dir)
    assert verdict["status"] == "pass"
    published = json.loads((plugin_dir / "fidelity.json").read_text())
    assert published["preserves_meta"] is True
    assert published["preserves_header"] is True


# ==================================================== the registry (DESIGN.md 11)


def seeded_verdict() -> dict:
    return json.loads((ROOT / "registry" / "open" / "agt-gateway.json")
                      .read_text())["entries"][0]["verdict"]


def test_seed_verdict_file_is_valid_and_honest():
    docs = load_verdict_docs()
    assert set(docs["curated"]) == set()          # no curated verdict exists
    doc = docs["open"]["agt-gateway"]
    assert doc["tier"] == "open"
    (entry,) = doc["entries"]
    assert entry["attestation"] == "self-attested"
    # the recorded limitation is stated in the data, not hidden
    assert any("no framework CI exists" in lim
               for lim in entry["limitations"])
    # as_of records what the verdict was verified against (DESIGN.md 11)
    assert entry["as_of"] == {c: entry["verdict"][c] for c in
                              registry_mod.VERDICT_KEY}
    # the seed is a real pass verdict under the suite's golden fixture
    assert entry["verdict"]["status"] == "pass"
    assert entry["verdict"]["golden_fixture_hash"] == \
        suite_golden_fixture_hash()


def test_seed_verdict_reproduces_from_a_fresh_l1_run():
    # the recorded verdict is what a fresh in-test L1 run actually produces
    verdict = seeded_verdict()
    fresh = l1_over_live_t1()
    assert fresh["status"] == verdict["status"] == "pass"
    for component in registry_mod.VERDICT_KEY:
        assert fresh[component] == verdict[component]


def test_facts_file_validates_and_carries_provenance():
    facts = load_fact_docs()
    doc = facts["agt-gateway"]
    assert doc["provenance"]["source"]
    assert doc["expires_with"]            # facts expire (DESIGN.md 11)
    # every capability fact names its source; unverified claims are labeled
    for fact in doc["capability_facts"]:
        assert fact["source"]
    assert any("claim" in f["source"]
               for f in doc["capability_facts"])


def test_is_verdict_current_expires_on_every_key_component(tmp_path):
    # DESIGN.md 11: any key-component change makes the verdict stale —
    # one flip per component, each staleness names the component
    verdict = seeded_verdict()
    keys = current_keys(AGT_PLUGIN_ID)
    ok, reasons = is_verdict_current(verdict, current_keys=keys)
    assert ok and reasons == []
    for component in registry_mod.VERDICT_KEY:
        bumped = dict(keys)
        bumped[component] = "bumped-" + component
        ok, reasons = is_verdict_current(verdict, current_keys=bumped)
        assert not ok
        assert any(r.startswith(component) for r in reasons), component
    # a component the current keys cannot supply is unverifiable => stale
    ok, reasons = is_verdict_current(verdict,
                                     current_keys={k: v for k, v in keys.items()
                                                   if k != "suite_version"})
    assert not ok
    assert any("suite_version" in r for r in reasons)


def test_eligible_open_tier_is_labeled_not_eligible():
    # the seeded open-tier verdict is current but open: not main-grid
    # eligible, returned labeled (never hidden; DESIGN.md 11)
    result = eligible_for_main_grid(AGT_PLUGIN_ID, AGT_PLUGIN_VERSION)
    assert result["eligible"] is False
    assert result["tier"] == "open"
    assert result["current"] is True
    assert "self-attested, appendix-only" in result["label"]
    assert result["verdicts"]            # the verdict is returned
    assert result["as_of"]["plugin_version"] == AGT_PLUGIN_VERSION


def test_eligible_curated_current(tmp_path):
    # a curated + current verdict is main-grid eligible
    root = write_registry_copy(tmp_path)
    curated = root / "curated"
    curated.mkdir(exist_ok=True)
    doc = json.loads((root / "open" / "agt-gateway.json").read_text())
    doc["tier"] = "curated"
    doc["entries"][0]["attestation"] = "framework-ci"
    (curated / "agt-gateway.json").write_text(json.dumps(doc))
    result = eligible_for_main_grid(AGT_PLUGIN_ID, AGT_PLUGIN_VERSION,
                                    registry_root=root)
    assert result["eligible"] is True
    assert result["tier"] == "curated"
    assert result["current"] is True
    assert result["as_of"]


def test_eligible_curated_stale_shows_as_of_not_eligible(tmp_path):
    # a stale curated verdict: not eligible, displayed with what it was
    # verified against (staleness downgrades display, never hides)
    root = write_registry_copy(tmp_path)
    curated = root / "curated"
    curated.mkdir(exist_ok=True)
    doc = json.loads((root / "open" / "agt-gateway.json").read_text())
    doc["tier"] = "curated"
    doc["entries"][0]["attestation"] = "framework-ci"
    (curated / "agt-gateway.json").write_text(json.dumps(doc))
    # stale via a suite-version bump (any key component, DESIGN.md 11)
    stale_keys = dict(current_keys(AGT_PLUGIN_ID), suite_version="2")
    result = eligible_for_main_grid(AGT_PLUGIN_ID, AGT_PLUGIN_VERSION,
                                    registry_root=root, keys=stale_keys)
    assert result["eligible"] is False
    assert result["tier"] == "curated"
    assert result["current"] is False
    assert result["stale_reasons"]
    assert result["as_of"]["plugin_version"] == AGT_PLUGIN_VERSION   # as-of display


def test_eligible_no_verdict(tmp_path):
    result = eligible_for_main_grid("unknown-plugin", "1", registry_root=tmp_path)
    assert result["eligible"] is False
    assert result["label"].startswith("no verdict")


def test_record_verdict_refuses_curated_framework_ci():
    # honesty rule: no framework CI exists, so no curated verdict may be
    # recorded at all (DESIGN.md 11 curated = CI re-verified), under either
    # attestation
    verdict = l1_over_live_t1()
    with pytest.raises(RegistryError, match="no framework CI exists"):
        record_verdict(verdict, tier="curated", recorded_by="x",
                       verified_by="y", attestation="framework-ci",
                       registry_root=Path("/nonexistent-registry-root"))
    with pytest.raises(RegistryError, match="no framework CI exists"):
        record_verdict(verdict, tier="curated", recorded_by="x",
                       verified_by="y", attestation="self-attested",
                       registry_root=Path("/nonexistent-registry-root"))
    with pytest.raises(RegistryError, match="unknown tier"):
        record_verdict(verdict, tier="side", recorded_by="x",
                       verified_by="y")


def test_record_verdict_appends_and_validates(tmp_path):
    verdict = l1_over_live_t1()
    path = record_verdict(verdict, tier="open", recorded_by="m2c-test",
                          verified_by="an in-test L1 run",
                          registry_root=tmp_path, recorded_at="2026-10-29T00:00:00Z")
    doc = json.loads(path.read_text())
    assert len(doc["entries"]) == 1
    record_verdict(verdict, tier="open", recorded_by="m2c-test",
                   verified_by="an in-test L1 run",
                   registry_root=tmp_path, recorded_at="2026-10-29T01:00:00Z")
    doc = json.loads(path.read_text())
    assert len(doc["entries"]) == 2
    # the appended file still validates
    assert load_verdict_docs(registry_root=tmp_path)["open"]["agt-gateway"]


def test_fact_docs_schema_validated(tmp_path):
    # an invalid fact doc is rejected at load (registry facts are
    # schema-validated data; DESIGN.md 11)
    bad = {"schema": 1, "plugin": "bad-plugin"}   # missing as_of + provenance
    with pytest.raises(RegistryError, match="schema violation"):
        record_facts(bad, registry_root=tmp_path)
    facts_dir = tmp_path / "facts"
    facts_dir.mkdir(parents=True)
    (facts_dir / "broken.json").write_text("{not json")
    with pytest.raises(RegistryError):
        load_fact_docs(registry_root=tmp_path)


# --- the registry CLI -------------------------------------------------------------


def test_cli_registry_ls(capsys):
    assert cli_main(["registry", "ls"]) == 0
    out = capsys.readouterr().out
    assert "agt-gateway  tier=open" in out
    assert "status=pass" in out
    assert "current" in out           # tier + current/stale status shown
    assert "facts  last_verified=" in out


def test_cli_registry_show(capsys):
    assert cli_main(["registry", "show", "agt-gateway"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["plugin"] == "agt-gateway"
    assert doc["verdicts"]["open"]["tier"] == "open"
    assert doc["facts"]["maintainer"]


def test_cli_registry_show_unknown(capsys):
    assert cli_main(["registry", "show", "no-such-plugin"]) == 1
    assert "no registry entry" in capsys.readouterr().err


# ==================================== derived summary rows (DESIGN.md 10)


def synthetic_execution(out_root: Path, exp_id: str, runs):
    """A minimal execution.json with per-run recorded outcome counts and
    evidence classes (the merge's claim-preserving inputs)."""
    exp_dir = out_root / exp_id
    exp_dir.mkdir(parents=True, exist_ok=True)
    entries = []
    for run_id, overrides in runs.items():
        run_dir = out_root / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        doc = {
            "run_id": run_id, "design": "t1", "control": "agt-gateway",
            "control_binding": "selected", "harness": "pi",
            "workload": "baseline-15", "off_matrix": False,
            "observation_only": False, "run_dir": str(run_dir),
            "run_record": str(run_dir / "run-record.json"),
            "decision_records": {"path": "x", "count": 1},
            "fixture_fingerprint": {"id": "reference-rig/t1"},
            "evidence_class": "harness-run", "degraded": [], "status": "pass",
            "coverage": {"status": "pass"}, "coverage_consistent": True,
            "findings": [], "spec_sha256": "a" * 64,
        }
        doc.update({k: v for k, v in overrides.items() if k != "created"})
        entries.append(doc)
        (run_dir / "manifest.json").write_text(json.dumps(
            {"schema": "inspection-run-manifest/1", "run_id": run_id,
             "created": overrides.get("created",
                                      "2026-10-28T10:00:00+00:00")}))
    manifest = {
        "schema": 1, "created": "2026-10-28T10:00:00Z",
        "experiment": {"path": f"{exp_id}.yaml", "sha256": "c" * 64,
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


def test_summary_rows_derived_and_summed(tmp_path):
    # two comparable runs of one design: one summary row per design, sums of
    # counts only, labeled derived (DESIGN.md 10)
    p = synthetic_execution(tmp_path, "exp-a", {
        "run-1": {"outcome_counts": {
            "counts": {"checked-allowed": 4, "bypassed": 11},
            "per_class": {"http_tool_call": {"checked-allowed": 4}}}},
        "run-2": {"outcome_counts": {
            "counts": {"checked-allowed": 1, "bypassed": 2},
            "per_class": {"http_tool_call": {"checked-allowed": 1}}},
            "created": "2026-10-28T11:00:00+00:00"},
    })
    report = merge_reports([p])
    (grid,) = report["grids"]
    (summary,) = grid["summary_rows"]
    assert summary["design"] == "t1"
    assert summary["derived"] is True
    assert summary["label"] == "derived"
    assert summary["outcome_counts"]["counts"] == \
        {"checked-allowed": 5, "bypassed": 13}
    assert summary["outcome_counts"]["per_class"]["http_tool_call"] == \
        {"checked-allowed": 5}
    assert len(summary["contributing"]) == 2


def test_summary_row_takes_the_worst_contributing_class(tmp_path):
    # DESIGN.md 10: summary rows take the worst contributing class; a
    # self-reported row never lets a harness-run row upgrade the summary.
    # A sensor-less run no longer composes with a sensor run into one
    # grid by default (the sensor key component is "absent" for it,
    # DESIGN.md 9/10), so this merge is forced with allow_incomparable:
    # one grid, both rows contributing, the worst class still wins
    p = synthetic_execution(tmp_path, "exp-a", {
        "run-1": {"evidence_class": "harness-run"},
        "run-2": {"evidence_class": "self-reported",
                  "degraded": ["sensor-absent"],
                  "created": "2026-10-28T11:00:00+00:00"},
    })
    split = merge_reports([p])
    assert len(split["grids"]) == 2
    assert any("kernel_sensor_version" in w for w in split["warnings"])
    report = merge_reports([p], allow_incomparable=True)
    (summary,) = report["grids"][0]["summary_rows"]
    assert summary["evidence_class"] == "self-reported"
    # and derived ranks below self-reported when present
    p2 = synthetic_execution(tmp_path, "exp-b", {
        "run-3": {"evidence_class": "self-reported"},
        "run-4": {"evidence_class": "derived",
                  "created": "2026-10-28T12:00:00+00:00"},
    })
    (summary2,) = merge_reports([p2],
                                 allow_incomparable=True)["grids"][0]["summary_rows"]
    assert summary2["evidence_class"] == "derived"


def test_summary_rows_off_matrix_columns_do_not_contribute(tmp_path):
    # off-matrix columns render in the extension section and never
    # contribute to on-matrix rollups (DESIGN.md 10); a different design so
    # the off-matrix run forms its own column
    p = synthetic_execution(tmp_path, "exp-a", {
        "run-1": {},
        "run-off": {"off_matrix": True, "design": "t2",
                    "outcome_counts": {
                        "counts": {"checked-allowed": 99},
                        "per_class": {"http_tool_call":
                                      {"checked-allowed": 99}}},
                    "created": "2026-10-28T11:00:00+00:00"},
    })
    report = merge_reports([p])
    grid = report["grids"][0]
    (summary,) = grid["summary_rows"]
    assert summary["outcome_counts"]["counts"] == {}
    assert len(grid["extension_columns"]) == 1


def test_summary_rows_live_merge_has_one_per_design():
    # the live t0 + t1 merge: one summary row per design, derived
    report = merge_reports([T0_EXEC, T1_EXEC])
    (grid,) = report["grids"]
    assert [row["design"] for row in grid["summary_rows"]] == ["t0", "t1"]
    t1_summary = next(r for r in grid["summary_rows"] if r["design"] == "t1")
    assert t1_summary["derived"] is True
    assert t1_summary["evidence_class"] == "harness-run"
    assert t1_summary["outcome_counts"]["counts"]["bypassed"] == 11
    assert t1_summary["outcome_counts"]["counts"]["checked-allowed"] == 4


def test_render_summary_lists_derived_rows(tmp_path, capsys):
    p = synthetic_execution(tmp_path, "exp-a", {"run-1": {}})
    report = merge_reports([p])
    text = report_mod.render_summary(report)
    assert "[derived summary] design=t1" in text
