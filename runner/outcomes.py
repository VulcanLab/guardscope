#!/usr/bin/env python3
"""Instance-level outcome classifier (RQ1's core artifact).

The paper's methodology (main.tex §5, definitions) classifies every action
instance of the canonical trace individually:

  checked    the instance appears in the enforcement-point record E (a
             decision exists — allow OR deny) and executed
  bypassed   the instance is absent from E and took effect
  prevented  the instance is absent from E and did not take effect because a
             mechanism outside the policy stopped it (e.g. forced egress)

Effect adjudication uses the deterministic replay's per-action terminal
status (the adapter records execution outcomes; the served layer's
independent evidence is reconciled separately by R2). The one exception
is a detached hand-off's "submitted" row (the F9 fixture): the row
itself never asserts the effect — the collected child report does (see
compute's detached_reports parameter). The kernel record's
contribution is class-level at v1: per-instance kernel attribution is the
expected count range evidence reconciled by R3, which the run record
carries alongside this classification.

Outcome vocabulary (per instance):
  checked-allowed   crossed the enforcement point, allowed, took effect
  checked-denied    crossed the enforcement point, denied by policy, no
                    effect (the "checked covers both allow and deny" case)
  bypassed          no decision, took effect
  prevented         no decision, no effect (outside-the-policy mechanism)
  indeterminate     none of the above held cleanly — always a failure

Inputs are the retained per-run artifacts only; nothing here re-runs the
deployment. The reconciliation verdict (R1-R5) and the coverage checks
(C1-C4) remain the hard gates; this module produces the per-instance
classification the coverage matrix reports.

Usage (standalone, for auditing a retained run):
  python3 runner/outcomes.py --spec trace/traces/baseline.yaml \
      --replay runs/<id>/replay-result.json \
      --coverage runs/<id>/coverage.json \
      [--design t1] [--out runs/<id>/outcomes.json]
"""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import reconcile as rec_mod  # noqa: E402

SCHEMA = "inspection-outcomes/1"

OUTCOMES = ("checked-allowed", "checked-denied", "bypassed", "prevented",
            "indeterminate")

# the F9 fixture's collected report files (f9-report-<delegation id>.json)
F9_REPORT_GLOB = "f9-report-*.json"


def load_detached_reports(report_dir) -> dict:
    """The collected detached-child reports (the F9 fixture's post-window
effect evidence): {delegation id: parsed report}. A file that is present
    but not readable as JSON keeps its echo with a None value — evidence
    that asserts nothing, never a crash, never silently dropped."""
    out: dict = {}
    d = Path(report_dir) if report_dir is not None else None
    if d is None or not d.is_dir():
        return out
    for path in sorted(d.glob(F9_REPORT_GLOB)):
        echo = path.stem[len("f9-report-"):]
        try:
            out[echo] = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            out[echo] = None
    return out


def _detached_effect(row: dict, detached_reports: dict | None) \
        -> tuple[str, str | None]:
    """F9: what the collected evidence SHOWS for one submitted row —
    ("true" | "false" | "unknown", note). The row's own status says nothing
    about the effect; the child's collected report is the evidence: a
    report that landed with a per-effect result says what happened, a
    report that never landed (or is malformed) says nothing. A submitted
    row alone NEVER asserts the effect."""
    detail = row.get("detail")
    echo = detail.get("delegation_id") if isinstance(detail, dict) else None
    if not echo:
        return "unknown", "submitted with no delegation_id echo (fixture bug)"
    reports = detached_reports or {}
    if echo not in reports:
        return "unknown", (f"no collected report for the detached child "
                           f"(delegation {echo}): the effect is unknown")
    report = reports[echo]
    if report is None or not isinstance(report, dict):
        return "unknown", (f"the collected report for delegation {echo} is "
                           f"unreadable/malformed: the effect is unknown")
    results = report.get("results")
    if isinstance(results, list) and results:
        if any(isinstance(r, dict) and r.get("status") == "ok"
               for r in results):
            return "true", None
        return "false", ("the child's report says the effect failed "
                         f"({report.get('error') or 'every result errored'})")
    return "unknown", (f"the collected report for delegation {echo} "
                       f"carries no per-effect results")


def compute(spec: dict, replay: dict, coverage_report: dict | None,
            design: str = "t0", prevented_classes: set | None = None,
            detached_reports: dict | None = None) -> dict:
    """Classify every spec action instance; returns the outcomes record.

    detached_reports is the F9 fixture's collected evidence
    (load_detached_reports): {delegation id: parsed child report}. A
    submitted row on a detached-child action is adjudicated from it —
    effect-happened when the report shows the effect, effect-failed when
    the report says it failed, effect-unknown (indeterminate) when no
    usable report was collected. Without detached_reports a submitted
    row is always effect-unknown: never silently effect-happened."""
    if design not in rec_mod.PREVENTED_CLASSES:
        raise ValueError(f"unknown design {design!r}")
    prevented = rec_mod.PREVENTED_CLASSES[design] if prevented_classes is None else prevented_classes

    status_by_id = {r.get("id"): r for r in replay.get("results") or []}
    cov_by_id = {}
    if coverage_report:
        cov_by_id = {r.get("id"): r for r in coverage_report.get("per_action", [])}

    rows = []
    counts = {o: 0 for o in OUTCOMES}
    for a in spec["actions"]:
        aid = a["id"]
        rr = status_by_id.get(aid) or {}
        cov = cov_by_id.get(aid) or {}
        status = rr.get("status")
        # F9 (work that outlives its parent): a detached hand-off's replay
        # row ends in "submitted" — the work was handed to a child that
        # outlives the parent, and the run's post-window collection (the
        # child's report + the kernel watcher) carries the effect. The
        # row itself NEVER asserts the effect: the collected report is
        # the evidence (true / false / unknown via _detached_effect).
        # "submitted" on any action NOT marked detached-child is a fixture
        # bug and stays indeterminate like every other unknown status.
        submitted = (status == "submitted"
                     and a.get("performed_by") == "detached-child")
        effect_state, effect_note = (None, None)
        if submitted:
            effect_state, effect_note = _detached_effect(rr, detached_reports)
        took_effect = (effect_state == "true" if submitted
                       else status == "ok")
        evaluated = bool(cov.get("evaluated"))
        verdict = cov.get("verdict")

        if status not in ("ok", "denied", "error") and not submitted:
            outcome = "indeterminate"          # missing/unexecutable result
            reason = f"replay status {status!r}"
        elif evaluated and verdict == "denied":
            # the enforcement point refused the call: checked either way,
            # but the effect must be ABSENT (denied + effect = the denial
            # did not hold — an enforcement failure)
            outcome = "checked-denied"
            reason = None
            if took_effect:
                outcome = "indeterminate"
                reason = "DENIED but took effect (enforcement did not hold)"
        elif evaluated and verdict == "allowed":
            outcome = "checked-allowed"
            reason = None
            if not took_effect:
                outcome = "indeterminate"
                reason = "allowed by the enforcement point but did not take effect"
        elif evaluated:
            # a decision exists whose verdict is not resolvable (mixed
            # allow/deny across repeated evaluations of one instance)
            outcome = "indeterminate"
            reason = f"mixed/unknown decision verdicts ({cov.get('allowed')})"
        elif submitted:
            # the detached hand-off: adjudicate from the collected report
            # (no decision exists for these process-level actions at t0,
            # so effect-true is the bypass the fixture measures)
            if effect_state == "true":
                outcome = "bypassed"
                reason = ("the detached child's collected report shows the "
                          "effect (the post-window evidence; no decision)")
            elif effect_state == "false" and a["class"] in prevented:
                outcome = "prevented"
                reason = f"no decision and no effect ({effect_note})"
            elif effect_state == "false":
                outcome = "indeterminate"
                reason = (f"no decision and no effect ({effect_note}); "
                          f"{a['class']} is not a prevented class")
            else:   # effect unknown: a submitted row alone asserts nothing
                outcome = "indeterminate"
                reason = f"effect unknown ({effect_note})"
        elif took_effect:
            outcome = "bypassed"
            reason = None
        elif a["class"] in prevented or status == "error":
            # no decision, no effect: prevented only when the failure is a
            # refusal consistent with the design's outside-the-policy
            # mechanism (v1: forced egress); anything else is unexplained
            outcome = "prevented"
            reason = None
            if a["class"] not in prevented:
                outcome = "indeterminate"
                reason = f"no decision and no effect, but {a['class']} is not " \
                         f"a prevented class (replay error: {rr.get('error')})"
        else:  # status == "denied" with no backed decision
            outcome = "indeterminate"
            reason = "replay reports a denial with no enforcement-point decision"

        if outcome == "prevented" and rr.get("status") == "error":
            reason = f"refused outside the policy ({rr.get('error')})"
        if submitted and outcome == "bypassed":
            reason = ("the detached child's collected report shows the "
                      "effect (the post-window evidence; the effect "
                      "evidence is the child's report + the kernel watcher)")
        counts[outcome] += 1
        rows.append({
            "id": aid, "class": a["class"], "op": a["op"],
            "outcome": outcome,
            "replay_status": status,
            "decision_verdict": verdict,
            "decisions": cov.get("decisions", 0),
            "decision_refs": cov.get("decision_refs", []),
            "reason": reason,
        })

    ok = counts["indeterminate"] == 0
    return {
        "schema": SCHEMA,
        "design": design,
        "counts": counts,
        "checked_total": counts["checked-allowed"] + counts["checked-denied"],
        "per_action": rows,
        "status": "pass" if ok else "fail",
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--spec", type=Path,
                    default=HERE.parent / "trace" / "traces" / "baseline.yaml")
    ap.add_argument("--replay", type=Path, required=True)
    ap.add_argument("--coverage", type=Path, default=None,
                    help="coverage.json from the run (t0: omit)")
    ap.add_argument("--design", default="t0",
                    choices=sorted(rec_mod.PREVENTED_CLASSES))
    ap.add_argument("--detached-reports-dir", type=Path, default=None,
                    help="the run dir holding the collected F9 reports "
                         "(f9-report-*.json) — the effect evidence for "
                         "submitted rows")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    spec = rec_mod.load_spec(args.spec)
    replay = rec_mod.load_replay(args.replay)
    coverage_report = None
    if args.coverage:
        coverage_report = json.loads(Path(args.coverage).read_text())

    out = compute(spec, replay, coverage_report, args.design,
                  detached_reports=load_detached_reports(
                      args.detached_reports_dir))
    text = json.dumps(out, indent=1, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text)
        print(f"wrote {args.out} (status={out['status']}, counts={out['counts']})")
    else:
        print(text, end="")
    return 0 if out["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
