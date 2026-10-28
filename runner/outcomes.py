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
independent evidence is reconciled separately by R2). The kernel record's
contribution is class-level at v1: per-instance kernel attribution is the
multiplicity-envelope evidence reconciled by R3, which the run record
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


def compute(spec: dict, replay: dict, coverage_report: dict | None,
            design: str = "t0", prevented_classes: set | None = None) -> dict:
    """Classify every spec action instance; returns the outcomes record."""
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
        took_effect = status == "ok"
        evaluated = bool(cov.get("evaluated"))
        verdict = cov.get("verdict")

        if status not in ("ok", "denied", "error"):
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
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    spec = rec_mod.load_spec(args.spec)
    replay = rec_mod.load_replay(args.replay)
    coverage_report = None
    if args.coverage:
        coverage_report = json.loads(Path(args.coverage).read_text())

    out = compute(spec, replay, coverage_report, args.design)
    text = json.dumps(out, indent=1, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text)
        print(f"wrote {args.out} (status={out['status']}, counts={out['counts']})")
    else:
        print(text, end="")
    return 0 if out["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
