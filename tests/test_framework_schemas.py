"""Framework schema tests (M1 pass 2): the user-facing schema set
(framework/schemas/) — draft 2020-12 validity, the bare `schema: 1` stamp,
and the MUST-NOT-CONTAIN rules of DESIGN.md 4 (outcome-shaped keys are
reconciler-only and rejected; unknown-field tolerance never applies to them).

Run from the repo root:  python3 -m pytest tests/test_framework_schemas.py -v
"""

import sys
from pathlib import Path

import jsonschema
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from framework.schemas import SCHEMA_TYPES, load_schema, schema_path  # noqa: E402
from framework.records import (  # noqa: E402
    RecordValidationError, make_decision_record, make_dispatch_record,
)
def test_all_schemas_are_valid_draft2020():
    for name in SCHEMA_TYPES:
        doc = load_schema(name)
        assert doc["$schema"] == "https://json-schema.org/draft/2020-12/schema"
        jsonschema.Draft202012Validator.check_schema(doc)


def test_ids_carry_full_type_identity():
    # DESIGN.md 4: full identity (type + version) lives only in the $id
    for name in SCHEMA_TYPES:
        doc = load_schema(name)
        assert doc["$id"] == f"https://guardscope.dev/schemas/{name}/1"


# --- decision-record/1 ---------------------------------------------------------

def valid_decision_record(**overrides) -> dict:
    base = dict(
        run_id="run-1", stream_id="s-gateway", seq=0,
        ts="2026-10-28T10:00:00.000Z",
        enforcement_point={"slot_id": "gateway", "product": "p",
                           "product_version": "1"},
        producer={"plugin": "agt-gateway", "plugin_version": "0.1.0",
                  "record_source": "native"},
        action_class="http_tool_call", protocol="http", tool="post_hook",
        target={"kind": "opaque", "value": "http://mcp-http:8091/hook"},
        parameters_digest="0" * 64,
        action_id=None, attempt=0, correlation_transport="none",
        decision="allow",
        policy={"policy_id": "t1", "policy_version": "1",
                "policy_hash": "0" * 64},
    )
    base.update(overrides)
    return make_decision_record(**base)


def test_decision_record_minimum_valid():
    record = valid_decision_record()
    assert record["schema"] == 1          # DESIGN.md 4: bare stamp
    assert record["attempt"] == 0         # DESIGN.md 5: attempt default 0
    assert len(record["record_id"]) == 26  # ULID


def test_bare_stamp_no_type_names():
    # DESIGN.md 4: no type names inside data files; the stamp is literal 1
    with pytest.raises(RecordValidationError, match="bare literal 1"):
        valid_decision_record(schema="decision-record/1")
    with pytest.raises(RecordValidationError, match="bare literal 1"):
        make_dispatch_record(run_id="r", action_id="a", carrier_used="none",
                             result={}, schema="dispatch-record/1")


def test_outcome_shaped_keys_rejected():
    # DESIGN.md 1, 4: outcomes/verdicts/attribution/confidence are
    # reconciler-only; unknown-field tolerance does NOT apply to them
    for key, value in [("outcome", "bypassed"), ("verdict", "checked"),
                       ("attribution_method", "id"), ("confidence", "0.9")]:
        with pytest.raises(RecordValidationError,
                           match="reconciler-only field"):
            valid_decision_record(**{key: value})


def test_outcome_key_rejected_at_any_depth():
    with pytest.raises(RecordValidationError, match="reconciler-only field"):
        valid_decision_record(ids={"debug": {"bypassed": True}})
    with pytest.raises(RecordValidationError, match="reconciler-only field"):
        make_dispatch_record(run_id="r", action_id="a", carrier_used="none",
                             result={"detail": {"checked": 1}})


def test_unknown_fields_rejected():
    with pytest.raises(RecordValidationError):
        valid_decision_record(made_up_field="x")


def test_evidence_mandatory_when_ingested_and_on_deny():
    # DESIGN.md 4: evidence mandatory when ingested and when decision == deny
    with pytest.raises(RecordValidationError):
        valid_decision_record(
            producer={"plugin": "agt-gateway", "plugin_version": "0.1.0",
                      "record_source": "ingested"})
    with pytest.raises(RecordValidationError):
        valid_decision_record(decision="deny")


def test_transform_requires_transformed_target():
    with pytest.raises(RecordValidationError):
        valid_decision_record(decision="transform")
    record = valid_decision_record(
        decision="transform",
        transformed_target={"kind": "opaque", "value": "http://x"})
    assert record["transformed_target"]["kind"] == "opaque"


def test_six_class_and_decision_enums():
    with pytest.raises(RecordValidationError):
        valid_decision_record(action_class="shell_command")
    with pytest.raises(RecordValidationError):
        valid_decision_record(decision="bypassed")


# --- dispatch-record/1 -----------------------------------------------------------

def test_dispatch_record_result_xor_error():
    # DESIGN.md 4: `result` or `error`, exactly one
    record = make_dispatch_record(run_id="r", action_id="a1",
                                  carrier_used="none",
                                  result={"status": "ok"})
    assert record["schema"] == 1 and record["attempt"] == 0
    err = make_dispatch_record(run_id="r", action_id="a1",
                                carrier_used="none",
                                error={"message": "transport closed"})
    assert err["error"]["message"] == "transport closed"
    with pytest.raises(RecordValidationError):
        make_dispatch_record(run_id="r", action_id="a1", carrier_used="none",
                             result={"status": "ok"},
                             error={"message": "both present"})
    with pytest.raises(RecordValidationError):
        make_dispatch_record(run_id="r", action_id="a1", carrier_used="none")


def test_dispatch_rejects_outcome_and_unknown_fields():
    with pytest.raises(RecordValidationError, match="reconciler-only field"):
        make_dispatch_record(run_id="r", action_id="a1", carrier_used="none",
                             result={"status": "ok"}, outcome="prevented")
    with pytest.raises(RecordValidationError):
        make_dispatch_record(run_id="r", action_id="a1", carrier_used="none",
                             result={"status": "ok"}, grid="x")


# --- experiment/1 -----------------------------------------------------------------

def _experiment_doc(**overrides) -> dict:
    doc = {"schema": 1, "control": None, "designs": ["t0"]}
    doc.update(overrides)
    return doc


def test_experiment_validates_minimal():
    validator = jsonschema.Draft202012Validator(load_schema("experiment"))
    validator.validate(_experiment_doc())


def test_experiment_two_controls_inexpressible():
    # DESIGN.md 3: one selected control per run; no run-level syntax may
    # name two controls. `control` is a single nullable string, never a list
    validator = jsonschema.Draft202012Validator(load_schema("experiment"))
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(_experiment_doc(control=["gateway-a", "gateway-b"]))
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(_experiment_doc(grid={"controls": ["a", "b"]}))


def test_experiment_designs_required_and_explicit():
    validator = jsonschema.Draft202012Validator(load_schema("experiment"))
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({"schema": 1, "control": None})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({"schema": 1, "control": None, "designs": []})
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({"schema": 1, "control": None,
                            "designs": ["t1", "t1"]})


def test_experiment_composition_block():
    validator = jsonschema.Draft202012Validator(load_schema("experiment"))
    good = _experiment_doc(fixture={
        "name": "stack", "composition": [{"plugin": "a"}, {"plugin": "b"}]})
    validator.validate(good)
    # a single-control "composition" is not a composition (DESIGN.md 6)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(_experiment_doc(fixture={
            "name": "stack", "composition": [{"plugin": "a"}]}))
    # off_matrix is auto-set, never a user field (DESIGN.md 6)
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(_experiment_doc(off_matrix=True))


def test_experiment_bare_stamp_only():
    validator = jsonschema.Draft202012Validator(load_schema("experiment"))
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({"schema": "experiment/1", "control": None,
                            "designs": ["t0"]})


# --- capabilities-manifest/1 -------------------------------------------------------

def manifest_doc(**overrides) -> dict:
    doc = {
        "schema": 1, "id": "x-control", "version": "1.0", "kind": "control",
        "slot_kinds": ["container"], "record_source": "native",
        "can_enforce": "enforce",
        "observable_action_classes": ["http_tool_call"],
        "emitted_schema_versions": ["decision-record/1"],
        "correlation": {"echoes_meta": False, "echoes_header": False},
        "supported_designs": ["t1", "t3"],
        "positions": [{"id": "gateway", "designs": ["t1", "t3"]}],
    }
    doc.update(overrides)
    return doc


def test_capabilities_manifest_valid():
    validator = jsonschema.Draft202012Validator(
        load_schema("capabilities-manifest"))
    validator.validate(manifest_doc())


def test_capabilities_manifest_slot_and_enforce_enums():
    validator = jsonschema.Draft202012Validator(
        load_schema("capabilities-manifest"))
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(manifest_doc(slot_kinds=["vm"]))
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(manifest_doc(can_enforce="block"))
    with pytest.raises(jsonschema.ValidationError):
        validator.validate(manifest_doc(record_source="imported"))


def test_schema_files_live_under_framework_schemas():
    # the layout the registry and run manifest reference
    for name in SCHEMA_TYPES:
        assert schema_path(name).name == "1.schema.json"
