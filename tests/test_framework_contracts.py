"""Framework contract tests (M1 pass 2): plugin capability manifests
(capabilities-manifest/1, plugins/*/manifest.json) and the enforcement-ready
semantics of DESIGN.md 3 (readiness must prove that enforcement works: a
runner-issued test action the configured policy must deny produces its
decision record in collect()).

Run from the repo root:  python3 -m pytest tests/test_framework_contracts.py -v
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import framework.contracts as contracts  # noqa: E402
from framework.contracts import (  # noqa: E402
    ContractError, ControlContract, HarnessAdapterContract,
    InProcessControl, enforcement_ready, load_capabilities,
    readiness_test_action,
)

PLUGINS = ("exerciser", "agt-gateway", "pi", "openclaw")


# --- manifest loading + validation ----------------------------------------------

@pytest.mark.parametrize("plugin_id", PLUGINS)
def test_seed_manifests_validate(plugin_id):
    manifest = load_capabilities(plugin_id)
    assert manifest["schema"] == 1
    assert manifest["id"] == plugin_id
    assert manifest["kind"] in ("control", "harness-adapter", "workload")


def test_gateway_manifest_declares_its_capabilities():
    manifest = load_capabilities("agt-gateway")
    assert manifest["kind"] == "control"
    assert manifest["slot_kinds"] == ["container"]
    assert manifest["record_source"] == "ingested"   # v0 AuditEntry mapping
    assert manifest["can_enforce"] == "enforce"
    assert set(manifest["observable_action_classes"]) == {
        "http_tool_call", "stdio_tool_call"}
    assert manifest["supported_designs"] == ["t1", "t2", "t3", "t5"]
    assert manifest["emitted_schema_versions"] == ["decision-record/1"]


def test_harness_manifests_declare_hostable_points():
    pi = load_capabilities("pi")
    assert pi["hostable_enforcement_points"] == ["tool_call_permission_chain"]
    openclaw = load_capabilities("openclaw")
    assert openclaw["hostable_enforcement_points"] == ["dispatch_plugins"]


def test_exerciser_declares_reduced_contract_and_all_designs():
    manifest = load_capabilities("exerciser")
    assert manifest["kind"] == "harness-adapter"
    assert manifest["supported_designs"] == [f"t{i}" for i in range(8)]
    assert "hostable_enforcement_points" not in manifest
    assert "Reduced form" in manifest["notes"]


def test_version_mismatch_refused():
    # DESIGN.md 11: the runner refuses version mismatches rather than guessing
    load_capabilities("pi", version="1.0.4")
    with pytest.raises(ContractError, match="version"):
        load_capabilities("pi", version="9.9.9")


def test_unknown_plugin_rejected():
    with pytest.raises(ContractError, match="no plugin manifest"):
        load_capabilities("does-not-exist")


def _write_manifest(plugin_dir: Path, doc: dict) -> None:
    plugin_dir.mkdir(parents=True)
    (plugin_dir / "manifest.json").write_text(json.dumps(doc))


def test_invalid_manifests_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(contracts, "PLUGINS_DIR", tmp_path)

    # control kind must carry its describe() fields (DESIGN.md 3)
    _write_manifest(tmp_path / "x-control", {
        "schema": 1, "id": "x-control", "version": "1", "kind": "control"})
    with pytest.raises(ContractError, match="control kind requires"):
        load_capabilities("x-control")

    # harness-adapter kind must declare supported t-modes
    _write_manifest(tmp_path / "x-harness", {
        "schema": 1, "id": "x-harness", "version": "1",
        "kind": "harness-adapter"})
    with pytest.raises(ContractError, match="supported_designs"):
        load_capabilities("x-harness")

    # a position may not claim designs the plugin does not support
    _write_manifest(tmp_path / "x-control2", {
        "schema": 1, "id": "x-control2", "version": "1", "kind": "control",
        "slot_kinds": ["container"], "record_source": "native",
        "can_enforce": "enforce", "observable_action_classes": [],
        "supported_designs": ["t1"],
        "positions": [{"id": "gateway", "designs": ["t1", "t4"]}]})
    with pytest.raises(ContractError, match="outside supported_designs"):
        load_capabilities("x-control2")

    # manifest-level outcome claims are rejected like record-level ones
    _write_manifest(tmp_path / "x-control3", {
        "schema": 1, "id": "x-control3", "version": "1", "kind": "control",
        "slot_kinds": ["container"], "record_source": "native",
        "can_enforce": "enforce", "observable_action_classes": [],
        "supported_designs": ["t1"], "outcome": "bypassed"})
    with pytest.raises(ContractError, match="reconciler-only field"):
        load_capabilities("x-control3")


# --- the reference in-process lifecycle ------------------------------------------

def make_control(deny_tools=None) -> InProcessControl:
    control = InProcessControl()
    control.provision({"id": "embedded-1", "stream_id": "s-1",
                       "run_id": "run-1"})
    control.configure({"policy_id": "p1", "policy_version": "1",
                       "deny_tools": deny_tools or []})
    return control


def test_inprocess_control_implements_the_contract():
    control = make_control()
    assert isinstance(control, ControlContract)
    # the contracts are the public six-operation surfaces (DESIGN.md 3)
    assert set(ControlContract.__protocol_attrs__) == {
        "describe", "provision", "configure", "ready", "collect", "teardown"}
    assert set(HarnessAdapterContract.__protocol_attrs__) == {
        "describe", "configure", "ready", "inject", "collect", "teardown"}
    # describe() carries the DESIGN.md 3 manifest fields
    d = control.describe()
    assert d["record_source"] == "native"
    assert d["can_enforce"] == "enforce"
    assert d["emitted_schema_versions"] == ["decision-record/1"]


def test_provision_returns_handle_and_attach():
    control = InProcessControl()
    out = control.provision({"id": "embedded-1", "stream_id": "s-1",
                             "run_id": "run-1"})
    assert out["handle"] == "inprocess:embedded-1"
    # DESIGN.md 3: the attach descriptor carries the runner-assigned stream_id
    assert out["attach"] == {"stream_id": "s-1"}
    with pytest.raises(ContractError):
        control.provision({"id": "no-stream"})  # stream_id is required


def test_configure_is_idempotent_and_fingerprints():
    control = InProcessControl()
    control.provision({"id": "embedded-1", "stream_id": "s-1",
                       "run_id": "run-1"})
    descriptor = {"policy_id": "p1", "policy_version": "1",
                  "deny_tools": ["dangerous"]}
    fp1 = control.configure(descriptor)
    fp2 = control.configure(dict(descriptor))  # idempotent
    assert fp1 == fp2
    # the fingerprint must match policy.policy_hash in emitted records
    record = control.evaluate({"action_id": "a-1", "tool": "safe",
                               "class": "stdio_tool_call", "parameters": {}})
    assert record["policy"]["policy_hash"] == fp1
    # reversible: re-configuring replaces the policy
    control.configure({"policy_id": "p2", "policy_version": "1",
                       "deny_tools": []})
    assert control.evaluate({"action_id": "a-2", "tool": "dangerous",
                              "class": "stdio_tool_call",
                              "parameters": {}})["decision"] == "allow"


def test_collect_flushes_then_reports():
    control = make_control(deny_tools=["dangerous"])
    control.evaluate({"action_id": "a-1", "tool": "safe",
                     "class": "stdio_tool_call", "parameters": {}})
    control.evaluate({"action_id": "a-2", "tool": "dangerous",
                     "class": "stdio_tool_call", "parameters": {}})
    report = control.collect()
    # DESIGN.md 3: {stream_locator, record_count, seq_range, flush_ack}
    assert report["record_count"] == 2
    assert report["seq_range"] == [0, 1]
    assert report["flush_ack"] is True
    assert [r["decision"] for r in report["records"]] == ["allow", "deny"]
    assert control.collect()["record_count"] == 0  # flushed
    # one record per decision, per-stream monotonic seq
    control.evaluate({"action_id": "a-3", "tool": "safe",
                      "class": "stdio_tool_call", "parameters": {}})
    assert control.collect()["seq_range"] == [2, 2]


def test_teardown_is_idempotent_and_leaves_nothing():
    control = make_control()
    control.evaluate({"action_id": "a-1", "tool": "safe",
                      "class": "stdio_tool_call", "parameters": {}})
    control.teardown()
    control.teardown()  # idempotent
    assert control.state == "torn_down"
    assert control.collect()["record_count"] == 0
    with pytest.raises(ContractError):
        control.evaluate({"action_id": "a-2", "tool": "safe",
                          "class": "stdio_tool_call", "parameters": {}})


# --- enforcement-ready semantics (DESIGN.md 3 ready()) -----------------------------

def test_ready_passes_only_when_test_action_is_denied_and_recorded():
    control = make_control(deny_tools=["dangerous"])
    # the runner issues a test action the loaded policy must deny
    test_action = {"action_id": "ta-1", "tool": "dangerous",
                   "class": "stdio_tool_call", "parameters": {}}
    issued = []

    def issue(action):
        issued.append(action)
        return control.evaluate(action)   # the runner routes through the point

    assert enforcement_ready(control, issue, test_action=test_action)
    assert issued == [test_action]       # exactly one test action issued


def test_ready_fails_when_the_policy_allows_the_test_action():
    control = make_control(deny_tools=[])  # allow-everything policy
    test_action = {"action_id": "ta-1", "tool": "anything",
                   "class": "stdio_tool_call", "parameters": {}}
    assert not enforcement_ready(control, lambda a: control.evaluate(a),
                                 test_action=test_action)


def test_ready_fails_when_no_decision_record_appears():
    # the enforcement point never evaluated the action: no record in collect()
    control = make_control(deny_tools=["dangerous"])
    test_action = {"action_id": "ta-1", "tool": "dangerous",
                   "class": "stdio_tool_call", "parameters": {}}
    assert not enforcement_ready(control, lambda action: None,
                                 test_action=test_action)


def test_reference_readiness_uses_the_reserved_deny_tool():
    control = make_control(deny_tools=[])
    action = readiness_test_action()
    assert action["tool"] == contracts.READINESS_TOOL
    # the reserved tool is denied even by an allow-everything reference policy
    assert enforcement_ready(control, lambda a: control.evaluate(a),
                             test_action=action)
    assert control.ready()   # the contract operation gates on the same check


def test_ready_false_before_configuration():
    control = InProcessControl()
    assert not control.ready()   # provision/configure must come first
