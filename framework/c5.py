"""C5: id consistency (DESIGN.md 9, "Id consistency: echoed ids match the
carriers the harness dispatched; fabrication, duplication, and stripping are
detected").

C5 compares, per run, the ids the harness adapter dispatched (dispatch
records, dispatch-record/1) against the ids the decision records echo
(DESIGN.md 5: ids are echoed from the protocol carrier, never minted):

  fabrication  a decision echoes an (action_id, attempt) that no dispatch
               record carried — the control invented an id it could only
               have learned from configuration (workload-blindness,
               DESIGN.md 5)
  duplication  two decisions echo the same (action_id, attempt) at one
               enforcement point (one stream_id) — one dispatch cannot
               ground two decisions at the same point
  stripping    a dispatch says the ids travelled on a carrier
               (carrier_used != none) but no decision echoes them — the
               fidelity-relevant defect class (DESIGN.md 5: "a control that
               strips ids on inspectable traffic is a reportable defect")

Records without carriers are skipped, never findings (DESIGN.md 5: null
means traffic from outside the workload; its volume is reported, never
dropped silently): v0-ingested decision records (action_id null) and
dispatches whose carrier_used is none carry no ids to check.

Scope. The join key is (run_id, stream_id, action_id, attempt) (DESIGN.md 5);
C5 works at the run level (dispatch records name no stream) and groups
duplication per stream_id. Decision records are scoped by run_id when any
record carries the run's id; otherwise by the measurement window (native
streams accumulate on the enforcement-point volume across runs, the same
way the v0 decisions.jsonl does); with neither, every record is used.
"""

from framework.records import RecordValidationError, validate_dispatch_record
from framework.reconcile import ts_to_epoch_ns

C5_ID = "C5"


def _pair(record: dict) -> tuple[str, int]:
    return (record.get("action_id"), int(record.get("attempt", 0) or 0))


def run_c5(dispatch_records, decision_records, *, run_id=None,
           window=None, window_tolerance_ns: int = 1_000_000_000,
           inspected_action_ids=None) -> dict:
    """Run the C5 id-consistency check over one run's two record streams.

    dispatch_records: dispatch-record/1 dicts (one per attempt, DESIGN.md 4).
    decision_records: decision-record/1 dicts (the native stream; v0-mapped
    records carry action_id null and are skipped). run_id/window scope the
    decision records (see the module docstring); window is
    (start_epoch_ns, end_epoch_ns) with window_tolerance_ns tolerance, the same
    convention the C1-C4 window uses.

    Returns {"id": "C5", "status": "pass"|"fail", "scope", "counts",
    "skipped", "findings"}; findings are check-shaped dicts
    ({"id", "status": "fail", "detail"}) so they merge into the run's
    findings list unchanged.
    """
    findings: list[dict] = []
    skipped = {"dispatch_invalid": 0, "dispatch_carrier_none": 0,
               "decision_null_action_id": 0,
               "dispatch_not_inspected": 0}

    # --- dispatch side: the ids the harness carried (DESIGN.md 5) -----------
    # Every dispatch record names its (action_id, attempt) and the carrier it
    # travelled on. Invalid records are findings (a dispatch stream that does
    # not validate cannot ground any id accounting); carrier-less dispatches
    # (carrier_used "none") are skipped, not findings.
    dispatched: dict[tuple[str, int], str] = {}
    dispatch_count = 0
    for record in dispatch_records:
        if not isinstance(record, dict):
            skipped["dispatch_invalid"] += 1
            findings.append({
                "id": "C5-dispatch-invalid", "status": "fail",
                "detail": "a dispatch-record stream line is not an object",
            })
            continue
        try:
            validate_dispatch_record(record)
        except RecordValidationError as exc:
            skipped["dispatch_invalid"] += 1
            findings.append({
                "id": "C5-dispatch-invalid", "status": "fail",
                "detail": f"dispatch record fails dispatch-record/1: {exc}",
            })
            continue
        dispatch_count += 1
        pair = _pair(record)
        carrier = record.get("carrier_used", "none")
        if pair in dispatched and dispatched[pair] != carrier:
            # two dispatch attempts of the same pair on different carriers:
            # not one of the three named defects, but recorded for audit
            findings.append({
                "id": "C5-dispatch-ambiguous", "status": "fail",
                "detail": (f"action_id {pair[0]!r} attempt {pair[1]} was "
                           f"dispatched on carriers {dispatched[pair]!r} "
                           f"and {carrier!r}"),
            })
        dispatched[pair] = carrier
        if carrier == "none":
            skipped["dispatch_carrier_none"] += 1

    # --- decision side: the ids the controls echoed --------------------------
    records = [r for r in decision_records if isinstance(r, dict)]
    scope_method = "all"
    if run_id is not None and any(r.get("run_id") == run_id for r in records):
        records = [r for r in records if r.get("run_id") == run_id]
        scope_method = "run_id"
    elif window is not None:
        lo = int(window[0]) - window_tolerance_ns
        hi = int(window[1]) + window_tolerance_ns
        records = [r for r in records
                   if (ns := ts_to_epoch_ns(r.get("ts"))) is not None
                   and lo <= ns <= hi]
        scope_method = "window"

    echoed: dict[tuple[str, int], list[dict]] = {}
    per_stream: dict[tuple, list[dict]] = {}
    for record in records:
        if record.get("action_id") is None:
            skipped["decision_null_action_id"] += 1
            continue
        pair = _pair(record)
        echoed.setdefault(pair, []).append(record)
        per_stream.setdefault((record.get("stream_id"),) + pair,
                              []).append(record)

    # (a) fabrication: an echoed id no dispatch carried
    for pair in sorted(echoed):
        if pair not in dispatched:
            findings.append({
                "id": "C5-fabrication", "status": "fail",
                "detail": (f"a decision record echoes action_id {pair[0]!r} "
                           f"attempt {pair[1]}, which no dispatch record "
                           f"carried (DESIGN.md 5: ids are echoed, never "
                           f"minted or learned from configuration)"),
            })

    # (b) duplication: one (action_id, attempt) echoed twice at one point
    for key in sorted(per_stream, key=repr):
        recs = per_stream[key]
        if len(recs) > 1:
            findings.append({
                "id": "C5-duplication", "status": "fail",
                "detail": (f"{len(recs)} decision records echo action_id "
                           f"{key[1]!r} attempt {key[2]} at one enforcement "
                           f"point (stream_id {key[0]!r})"),
            })

    # (c) stripping: a carrier-carried dispatch on INSPECTABLE traffic that
    # no decision echoes (DESIGN.md 5: stripping is a defect on inspectable
    # traffic only). Dispatches outside the design's inspected classes
    # cannot cross an enforcement point, so their missing echo is expected.
    for pair in sorted(dispatched, key=lambda p: (str(p[0]), p[1])):
        if dispatched[pair] == "none":
            continue   # carrier-less dispatch: skipped, not a finding
        if inspected_action_ids is not None and pair[0] not in inspected_action_ids:
            skipped["dispatch_not_inspected"] += 1
            continue   # the design does not inspect this class
        if pair not in echoed:
            findings.append({
                "id": "C5-stripping", "status": "fail",
                "detail": (f"the harness dispatched action_id {pair[0]!r} "
                           f"attempt {pair[1]} on carrier "
                           f"{dispatched[pair]!r} but no decision record "
                           f"echoes it (DESIGN.md 5: a control that strips "
                           f"ids on inspectable traffic is a reportable "
                           f"defect)"),
            })

    return {
        "id": C5_ID,
        "status": "fail" if findings else "pass",
        "scope": {"method": scope_method,
                  "decision_records": len(records),
                  "dispatch_records": dispatch_count},
        "echoed_pairs": len(echoed),
        "carried_pairs": sum(1 for c in dispatched.values() if c != "none"),
        "skipped": skipped,
        "findings": findings,
    }
