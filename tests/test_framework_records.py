"""Framework record tests (M1 pass 2): decision-record/1 and
dispatch-record/1 constructors, and the v0 AuditEntry reader-side mapping
(DESIGN.md 4): a mapped decisions.jsonl line set must produce the same C1-C4
outcomes from the existing runner/coverage.py computation as the raw lines.

Run from the repo root:  python3 -m pytest tests/test_framework_records.py -v
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from framework.records import (  # noqa: E402
    RecordValidationError, audit_entry_to_decision_record,
    map_audit_entries, make_decision_record, make_dispatch_record,
    new_ulid, now_rfc3339_ms, parameters_digest,
)
from framework.reconcile import decision_records_to_log_entries  # noqa: E402

# the existing runner coverage module (now a thin wrapper over
# framework/reconcile.py), loaded the same way tests/test_coverage.py loads it
COVERAGE_PATH = ROOT / "runner" / "coverage.py"


def _load_coverage():
    spec = importlib.util.spec_from_file_location("coverage", COVERAGE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


cov = _load_coverage()
sys.path.insert(0, str(ROOT / "runner"))
import reconcile as rec_mod  # noqa: E402

SPEC = rec_mod.load_spec(ROOT / "trace" / "traces" / "baseline.yaml")

WIN_START = 1_789_030_000_000_000_000  # epoch ns; entries use epoch seconds
WIN_END = WIN_START + 5_000_000_000


# --- constructors -----------------------------------------------------------

def base_fields(**overrides) -> dict:
    fields = dict(
        run_id="run-1", stream_id="s-gateway", seq=0, ts=now_rfc3339_ms(),
        enforcement_point={"slot_id": "gateway", "product": "p",
                           "product_version": "1"},
        producer={"plugin": "x", "plugin_version": "1",
                  "record_source": "native"},
        action_class="http_tool_call", protocol="http", tool="post_hook",
        target={"kind": "opaque"}, parameters_digest=parameters_digest({}),
        action_id=None, attempt=0, correlation_transport="none",
        decision="allow",
        policy={"policy_id": "t1", "policy_version": "1", "policy_hash": "h"},
    )
    fields.update(overrides)
    return fields


def test_constructor_stamps_and_defaults():
    record = make_decision_record(**base_fields())
    assert record["schema"] == 1
    assert record["attempt"] == 0
    assert len(record["record_id"]) == 26
    # a caller-supplied record_id is preserved
    rid = new_ulid()
    assert make_decision_record(**base_fields(record_id=rid))["record_id"] == rid


def test_constructor_rejects_missing_required():
    fields = base_fields()
    del fields["policy"]
    with pytest.raises(RecordValidationError):
        make_decision_record(**fields)


def test_dispatch_constructor():
    record = make_dispatch_record(run_id="r", action_id="a1",
                                  carrier_used="mcp_meta",
                                  result={"status": "ok"})
    assert record["schema"] == 1 and record["attempt"] == 0
    with pytest.raises(RecordValidationError):
        make_dispatch_record(run_id="r", action_id="a1", carrier_used="none")


def test_ulids_are_distinct_and_well_formed():
    ulids = [new_ulid() for _ in range(100)]
    assert len(set(ulids)) == 100
    assert all(len(u) == 26 for u in ulids)
    assert all(c in "0123456789ABCDEFGHJKMNPQRSTVWXYZ" for u in ulids
               for c in u)
    # the millisecond timestamp is the leading field (the first 10 Crockford
    # chars decode to it exactly, zero-padded), so a ULID is time-anchored
    now_ms = __import__("time").time_ns() // 1_000_000
    crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
    for u in ulids:
        stamp_ms = 0
        for c in u[:10]:
            stamp_ms = stamp_ms * 32 + crockford.index(c)
        assert abs(stamp_ms - now_ms) < 10_000   # within 10 s of now


# --- v0 AuditEntry mapping (DESIGN.md 4) ----------------------------------------

def entry(ts_s: float, tool: str = "post_hook", allowed: bool = True,
          params: dict | None = None, tool_call_id: str | None = None) -> dict:
    e = {"timestamp": ts_s, "agent_id": "t1-replay", "tool_name": tool,
         "allowed": allowed, "reason": "in allowed_tools",
         "approval_status": None, "parameters": params or {}}
    if tool_call_id is not None:
        e["tool_call_id"] = tool_call_id
    return e


def t1_line_set() -> list[dict]:
    """The 4 in-window AuditEntry lines a T1 replay produces (a011-a014),
    epoch-second timestamps inside the window."""
    base = WIN_START / 1e9
    return [
        entry(base + 0.5, "post_hook", params={"body": "tool-call payload"}),
        entry(base + 1.5, "get_health"),
        entry(base + 2.5, "put_state", params={"body": "k=v"}),
        entry(base + 3.5, "post_hook", allowed=False,
              params={"body": "policy-deny probe"}),
    ]


def t3_line_set() -> list[dict]:
    """T3: fs tools proxied behind the gateway plus the http tools."""
    base = WIN_START / 1e9
    return t1_line_set() + [
        entry(base + 0.2, "write_file",
              params={"path": "/workspace/out/a.txt",
                      "data": "hello from mcp fs"}),
        entry(base + 1.0, "read_file",
              params={"path": "/workspace/out/a.txt"}),
        entry(base + 1.4, "list_directory",
              params={"path": "/workspace/out"}),
    ]


MAP_KWARGS = dict(run_id="run-t1", stream_id="gw-1", product_version="3.7.0",
                  plugin_version="0.1.0", source="decisions.jsonl")


def test_mapped_record_shape():
    records = map_audit_entries(t1_line_set(), start_seq=5, **MAP_KWARGS)
    first = records[0]
    assert first["schema"] == 1
    assert first["seq"] == 5                      # per-stream monotonic
    assert first["producer"]["record_source"] == "ingested"
    assert first["source_schema"] == "agt-gateway-audit-entry/0"
    # DESIGN.md 4/5: v0 carries no correlation ids; never learned from config
    assert first["action_id"] is None
    assert first["correlation_transport"] == "none"
    # evidence points back at the original line (the shim raw_ref, DESIGN.md 3)
    assert first["evidence"][0]["kind"] == "v0-audit-entry"
    assert first["evidence"][0]["locator"]["source"] == "decisions.jsonl"
    assert first["ids"]["agent_id"] == "t1-replay"
    assert first["ids"]["v0_timestamp"] == t1_line_set()[0]["timestamp"]
    assert first["method"] == "POST" and first["path"] == "/hook"
    # fs tools map onto the stdio class; unknown tools default to http
    assert audit_entry_to_decision_record(
        entry(1.0, "write_file"), **{**MAP_KWARGS, "seq": 0}
    )["action_class"] == "stdio_tool_call"
    assert audit_entry_to_decision_record(
        entry(1.0, "nope"), **{**MAP_KWARGS, "seq": 0}
    )["action_class"] == "http_tool_call"


def test_mapper_rejects_malformed_entries():
    with pytest.raises(RecordValidationError):
        audit_entry_to_decision_record({"tool_name": "post_hook"},
                                      **{**MAP_KWARGS, "seq": 0})
    with pytest.raises(RecordValidationError):
        audit_entry_to_decision_record(entry("not-a-time"),
                                      **{**MAP_KWARGS, "seq": 0})


# --- the equivalence: mapped records drive the same C1-C4 as raw lines --------

@pytest.mark.parametrize("design,line_set", [
    ("t1", t1_line_set()),
    ("t3", t3_line_set()),
    ("t4", [dict(e, tool_name=f"mcp__toy-mcp-fs__{e['tool_name']}")
            for e in t3_line_set()]),
])
def test_c1c4_identical_from_mapped_records(design, line_set):
    """The existing runner/coverage.py C1-C4 computation must produce the
    same report from the mapped decision records as from the raw lines."""
    raw_report = cov.compute(SPEC, line_set, [], design,
                             (WIN_START, WIN_END))
    records = [audit_entry_to_decision_record(
        e, seq=i, line=i + 1, **MAP_KWARGS)
        for i, e in enumerate(line_set)]
    mapped_entries = decision_records_to_log_entries(records)
    mapped_report = cov.compute(SPEC, mapped_entries, [], design,
                                 (WIN_START, WIN_END))
    assert mapped_report == raw_report


def test_c1c4_equivalence_holds_on_failure_paths_too():
    """C2 (unknown tool) and window exclusion must behave identically
    through the mapping."""
    line_set = t1_line_set() + [entry(WIN_START / 1e9 + 4.0, "nope"),
                                entry(WIN_START / 1e9 - 3600)]
    raw_report = cov.compute(SPEC, line_set, [], "t1",
                             (WIN_START, WIN_END))
    records = [audit_entry_to_decision_record(
        e, seq=i, line=i + 1, **MAP_KWARGS)
        for i, e in enumerate(line_set)]
    mapped_report = cov.compute(
        SPEC, decision_records_to_log_entries(records), [], "t1",
        (WIN_START, WIN_END))
    assert mapped_report == raw_report
    assert mapped_report["status"] == "fail"   # the unknown tool trips C2


def test_round_trip_preserves_timestamps_and_refs():
    line_set = t1_line_set()
    line_set[0]["tool_call_id"] = "tc-1"
    records = map_audit_entries(line_set, **MAP_KWARGS)
    entries = decision_records_to_log_entries(records)
    # the log view carries exactly the fields the C1-C4 computation consumes
    assert entries == [
        {"timestamp": e["timestamp"], "tool_name": e["tool_name"],
         "allowed": e["allowed"], "parameters": e["parameters"],
         "tool_call_id": e["tool_call_id"]}
        if "tool_call_id" in e else
        {"timestamp": e["timestamp"], "tool_name": e["tool_name"],
         "allowed": e["allowed"], "parameters": e["parameters"]}
        for e in line_set
    ]
