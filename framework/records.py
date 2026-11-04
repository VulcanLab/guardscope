"""Record constructors and validation for decision-record/1 and
dispatch-record/1 (DESIGN.md 4).

Two rules from the design drive everything here:

- Bare stamps (DESIGN.md 4, 'Stamps and versioning'): no type names inside
  data files. The `schema` field carries the literal integer 1; the full
  type identity lives only in the JSON Schema $id and in the run manifest.
  The constructors stamp `schema: 1` themselves and reject any other value.
- Outcomes are reconciler-only (DESIGN.md 1, 4): a record must never contain
  an outcome, verdict, attribution or confidence. Unknown-field tolerance
  (mandatory in every consumer for additive minor bumps) does NOT apply to
  outcome-shaped keys: they are on a validation-time reject list and fail
  with a specific error, at any nesting depth, in both record types.

Also here: the v0 AuditEntry reader-side mapping (DESIGN.md 4: "v0
AuditEntry (the gateway decisions.jsonl format) remains a valid input via a
declared reader-side mapping; existing data remains readable"). The v0
emitter is the AGT-style MCP gateway (gateway/server.py); a mapped record
carries producer.record_source 'ingested' and an evidence entry pointing
back at the original decisions.jsonl line (the shim raw_ref, DESIGN.md 3).
"""

import hashlib
import json
import os
import time
from datetime import datetime, timezone

import jsonschema

from framework.schemas import load_schema
from framework.reconcile import GATEWAY_TOOL_ROUTES, ts_to_epoch_ns

_DECISION_VALIDATOR = jsonschema.Draft202012Validator(load_schema("decision-record"))
_DISPATCH_VALIDATOR = jsonschema.Draft202012Validator(load_schema("dispatch-record"))

# DESIGN.md 1 and 4: outcomes/verdicts/attribution/confidence are derived
# only by the reconciler. Any key of this shape, at any depth, is rejected
# before/independent of schema validation, under every version.
OUTCOME_REJECT_KEYS = frozenset({
    "outcome", "verdict", "bypassed", "checked", "prevented",
    "attribution", "attribution_method", "evidence_class", "confidence",
    "degraded", "expected_decision",
})


class RecordValidationError(ValueError):
    """A record failed the reject list or its JSON Schema."""


def _check_outcome_keys(node, path="") -> None:
    """Reject outcome-shaped keys anywhere in the record (DESIGN.md 4)."""
    if isinstance(node, dict):
        for key, value in node.items():
            here = f"{path}.{key}" if path else str(key)
            if key in OUTCOME_REJECT_KEYS:
                raise RecordValidationError(
                    f"{here}: reconciler-only field {key!r} must not appear "
                    f"in a record (outcomes are derived only by the "
                    f"reconciler, DESIGN.md 4)")
            _check_outcome_keys(value, here)
    elif isinstance(node, list):
        for i, item in enumerate(node):
            _check_outcome_keys(item, f"{path}[{i}]")


def _validate(validator, record, what: str) -> None:
    _check_outcome_keys(record)
    error = jsonschema.exceptions.best_match(validator.iter_errors(record))
    if error is not None:
        raise RecordValidationError(f"{what}: {error.message}")


def validate_decision_record(record: dict) -> None:
    """Validate one decision record against decision-record/1 (DESIGN.md 4)."""
    _validate(_DECISION_VALIDATOR, record, "decision-record/1")


def validate_dispatch_record(record: dict) -> None:
    """Validate one dispatch record against dispatch-record/1 (DESIGN.md 4)."""
    _validate(_DISPATCH_VALIDATOR, record, "dispatch-record/1")


# --- stamps (DESIGN.md 4: bare literal 1, no type names in data files) --------

def _stamp(fields: dict, what: str) -> dict:
    schema = fields.pop("schema", None)
    if schema is not None and schema != 1:
        raise RecordValidationError(
            f"{what}: the schema stamp is the bare literal 1 (DESIGN.md 4); "
            f"got {schema!r} (type names never appear inside data files)")
    return {"schema": 1, **fields}


# --- ULID (DESIGN.md 4: record_id is a ULID) ----------------------------------

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def new_ulid() -> str:
    """26-character ULID: 48-bit millisecond timestamp + 80 random bits."""
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(os.urandom(10), "big")
    value = (ms << 80) | rand
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(out))


# --- decision-record/1 constructor --------------------------------------------

def make_decision_record(**fields) -> dict:
    """Construct and validate a decision-record/1 record (DESIGN.md 4).

    Required keyword arguments are the schema's required fields except
    `schema` (stamped here, bare 1) and `record_id` (a fresh ULID when
    omitted). `attempt` defaults to 0 (DESIGN.md 5). Raises
    RecordValidationError on the outcome reject list, a bad stamp, or any
    schema violation.
    """
    fields.setdefault("record_id", new_ulid())
    fields.setdefault("attempt", 0)
    record = _stamp(fields, "decision-record/1")
    validate_decision_record(record)
    return record


# --- dispatch-record/1 constructor --------------------------------------------

def make_dispatch_record(**fields) -> dict:
    """Construct and validate a dispatch-record/1 record (DESIGN.md 4).

    Required keyword arguments: run_id, action_id, carrier_used, and exactly
    one of result / error. `attempt` defaults to 0, `dispatched_at` to the
    current time (RFC3339 ms). Raises RecordValidationError as above.
    """
    fields.setdefault("attempt", 0)
    fields.setdefault("dispatched_at", now_rfc3339_ms())
    record = _stamp(fields, "dispatch-record/1")
    validate_dispatch_record(record)
    return record


def now_rfc3339_ms() -> str:
    """Current time as RFC3339 with millisecond precision (the ts format)."""
    return epoch_ns_to_rfc3339_ms(time.time_ns())


def epoch_ns_to_rfc3339_ms(epoch_ns: int) -> str:
    dt = datetime.fromtimestamp(int(epoch_ns) / 1e9, tz=timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


def parameters_digest(parameters: dict) -> str:
    """sha256 over the canonical JSON form of the (redacted) parameters."""
    return hashlib.sha256(
        json.dumps(parameters, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")).hexdigest()


# --- v0 AuditEntry reader-side mapping (DESIGN.md 4) --------------------------

# The v0 format identifier carried in mapped records' source_schema field.
V0_AUDIT_ENTRY_SCHEMA = "agt-gateway-audit-entry/0"

# The v0 emitter's identity (gateway/server.py; the plugin manifest id is
# agt-gateway, the deployed product is the agent-governance-toolkit gateway).
V0_DEFAULT_PRODUCT = "agent-governance-gateway"
V0_DEFAULT_PLUGIN = "agt-gateway"

# The fs tools the gateway can route in T3 (gateway/server.py FS_TOOLS);
# these cross the gateway as stdio-class tool calls.
V0_FS_TOOLS = ("write_file", "read_file", "list_directory")

# The v0 AuditEntry carries no policy identity; the runner passes the
# deployed gateway policy descriptor. This default marks the fields
# unmapped rather than inventing values.
V0_UNMAPPED_POLICY = {
    "policy_id": "unmapped", "policy_version": "unmapped",
    "policy_hash": "unmapped",
}


def _v0_action_class(tool: str, default: str) -> str:
    if tool in GATEWAY_TOOL_ROUTES:
        return "http_tool_call"
    if tool in V0_FS_TOOLS:
        return "stdio_tool_call"
    return default


def audit_entry_to_decision_record(entry: dict, *, run_id: str, stream_id: str,
                                   seq: int, product_version: str,
                                   plugin_version: str,
                                   slot_id: str = "gateway",
                                   product: str = V0_DEFAULT_PRODUCT,
                                   plugin: str = V0_DEFAULT_PLUGIN,
                                   protocol: str = "http",
                                   default_action_class: str = "http_tool_call",
                                   policy: dict | None = None,
                                   source: str = "decisions.jsonl",
                                   line: int | None = None) -> dict:
    """Map one v0 AuditEntry (a gateway decisions.jsonl line) to a
    decision-record/1 record (DESIGN.md 4: the v0 format stays a valid input
    via a declared reader-side mapping).

    The mapped record carries producer.record_source 'ingested' (the v0
    emitter is the gateway itself, read back through this mapping), an
    evidence entry pointing at the original line (the shim raw_ref,
    DESIGN.md 3), and the original timestamp in ids so the round trip back
    to the C1-C4 log view (framework/reconcile.py
    decision_records_to_log_entries) is exact. action_id is null: the v0
    format carries no correlation ids, and a control must never record an
    id learned from configuration (DESIGN.md 5). The action class is derived
    from the gateway routing table (http tools, fs tools) with
    default_action_class for tools outside it.
    """
    if "tool_name" not in entry:
        raise RecordValidationError("v0 AuditEntry has no tool_name")
    allowed = entry.get("allowed")
    if not isinstance(allowed, bool):
        raise RecordValidationError(
            f"v0 AuditEntry 'allowed' must be a boolean, got {allowed!r}")
    ts_ns = ts_to_epoch_ns(entry.get("timestamp"))
    if ts_ns is None:
        raise RecordValidationError("v0 AuditEntry timestamp unparseable")

    tool = entry["tool_name"]
    # decision-record/1 streams (framework/reconcile.py load_decisions'
    # schema-1 branch) carry the class + structured target + protocol the
    # v0 AuditEntry never had: preserve them through the mapping (found
    # live 2026-11-03: re-deriving the class from the tool routing table
    # mislabeled the kernel position's records and dropped the target the
    # kernel join needs)
    entry_class = entry.get("action_class")
    entry_target = entry.get("target_value")
    entry_target_kind = entry.get("target_kind")
    entry_protocol = entry.get("protocol")
    parameters = entry.get("parameters") or {}
    ids = {k: entry[k] for k in ("agent_id", "tool_call_id",
                                "approval_status") if entry.get(k) is not None}
    # the raw v0 timestamp is carried along for the exact round trip (see docstring)
    ids["v0_timestamp"] = entry.get("timestamp")

    fields = {
        "record_id": new_ulid(),
        "run_id": run_id,
        "stream_id": stream_id,
        "seq": seq,
        "ts": epoch_ns_to_rfc3339_ms(ts_ns),
        "enforcement_point": {"slot_id": slot_id, "product": product,
                             "product_version": product_version},
        "producer": {"plugin": plugin, "plugin_version": plugin_version,
                     "record_source": "ingested"},
        "action_class": (entry_class
                        if isinstance(entry_class, str) and entry_class
                        else _v0_action_class(tool, default_action_class)),
        "protocol": (entry_protocol
                     if isinstance(entry_protocol, str) and entry_protocol
                     else protocol),
        "tool": tool,
        "target": ({"kind": (entry_target_kind
                           if isinstance(entry_target_kind, str)
                           else "kernel_path_or_endpoint"),
                    "value": entry_target,
                    "note": "decision-record/1 reader-side mapping: the "
                            "structured target value is preserved"}
                   if isinstance(entry_target, str) and entry_target
                   else {"kind": "unknown",
                         "note": "v0 AuditEntry carries no structured "
                                 "target"}),
        "parameters_digest": parameters_digest(parameters),
        "action_id": None,
        "attempt": 0,
        "correlation_transport": "none",
        "decision": "allow" if allowed else "deny",
        "policy": dict(policy or V0_UNMAPPED_POLICY),
        **({"decision_detail": entry["reason"]}
           if entry.get("reason") is not None else {}),
        "parameters": parameters,
        "evidence": [{"kind": "v0-audit-entry",
                      "locator": {"source": source, **({"line": line}
                                                       if line else {})}}],
        "source_schema": V0_AUDIT_ENTRY_SCHEMA,
        "ids": ids,
    }
    # HTTP route fields when the gateway routing table knows the tool
    if tool in GATEWAY_TOOL_ROUTES:
        method, path = GATEWAY_TOOL_ROUTES[tool]
        fields["method"] = method
        fields["path"] = path
    record = _stamp(fields, "decision-record/1")
    validate_decision_record(record)
    return record


def map_audit_entries(entries, *, start_seq: int = 0, **kwargs) -> list[dict]:
    """Map a sequence of v0 AuditEntry lines (dicts) to decision records,
    assigning per-stream monotonic seq from start_seq (DESIGN.md 4). The
    keyword arguments are audit_entry_to_decision_record's, minus seq."""
    records = []
    for i, entry in enumerate(entries):
        records.append(audit_entry_to_decision_record(
            entry, seq=start_seq + i, **kwargs))
    return records
