#!/usr/bin/env python3
"""Per-call latency overhead analysis (RQ4, empirical half).

For each design and harness, extracts the per-action dispatch latencies from
the retained replay results and reports the overhead against the T0 baseline
on the same deterministic workload (no model in the loop).

Latency definition per replay path:
  T0-T3  the adapter executes the actions itself: duration = per-action
         started_ns..ended_ns around the full execution (adapter executor).
  T4-T6  the calls cross pi's real tool pipeline: duration = the tool_call
         hook boundary .. the tool_result boundary (dispatch + execution).
The overhead against T0 therefore isolates the marginal cost of the
enforcement point plus the execution-path difference — reported per class
with the caveat that the two families' dispatch boundaries differ (within a
family the comparison is clean).

Structural caveats carried in the report (not silently averaged away):
  - a001 (the first stdio tool call) in T0/T1/T2 includes the MCP server
    child spawn + initialize handshake (the session is opened lazily at the
    first call). T3 has no MCP child; T4-T6 pre-connect at pi startup. The
    per-class aggregate therefore EXCLUDES a001's session-establishment
    component by reporting the stdio class median over a002/a003, with
    a001's raw duration listed separately.
  - T6's denied instance (a014) never executes: its duration is the hook's
    policy-evaluation time only, reported as the deny-latency measurement.

Inputs are the retained run dirs (runs/<id>/); only runs whose run record
reconciles pass are included.

Usage:
  python3 runner/latency.py [--runs-dir runs] [--out runs/latency-report.json]
                            [--markdown]
"""

import argparse
import json
import statistics
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import reconcile as rec_mod  # noqa: E402

SCHEMA = "inspection-latency/1"
SIX_CLASSES = rec_mod.SIX_CLASSES
# the stdio class median excludes the session-establishing first call
# (see module docstring); the raw a001 duration is reported separately
STDIO_SESSION_CALL = "a001"
DENY_CASE = "a014"


def _durations_ms(run_dir: Path) -> dict[str, float] | None:
    """Per-action durations (ms) from one run's replay result; None when the
    run does not reconcile pass or carries no timestamps."""
    rec_path = run_dir / "run-record.json"
    rep_path = run_dir / "replay-result.json"
    if not rec_path.is_file() or not rep_path.is_file():
        return None
    record = json.loads(rec_path.read_text())
    if record["reconciliation"]["status"] != "pass":
        return None
    replay = json.loads(rep_path.read_text())
    out = {}
    for r in replay.get("results") or []:
        st, en = r.get("started_ns"), r.get("ended_ns")
        if st is None or en is None:
            return None  # design family without per-call timestamps
        out[r["id"]] = max(0.0, (en - st) / 1e6)
    return out


def collect(runs_dir: Path) -> dict[str, dict[str, dict[str, float]]]:
    """design -> harness -> {run_id: {action_id: duration_ms}} over
    reconciliation-passing runs."""
    data: dict[str, dict[str, dict[str, float]]] = {}
    for d in sorted(Path(runs_dir).iterdir()):
        f = d / "run-record.json"
        if not d.is_dir() or not f.is_file():
            continue
        record = json.loads(f.read_text())
        if (record.get("design") or "t0") not in SIX_CLASSES and \
                record.get("design") not in ("t0", "t1", "t2", "t3", "t4", "t5", "t6"):
            continue
        durs = _durations_ms(d)
        if durs is None:
            continue
        design = record.get("design") or "t0"
        harness = record["harness"]
        data.setdefault(design, {}).setdefault(harness, {})[d.name] = durs
    return data


def median_map(runs: dict[str, dict[str, float]]) -> dict[str, float]:
    """Per-action median duration across runs."""
    ids = sorted({k for r in runs.values() for k in r})
    return {k: statistics.median(r[k] for r in runs.values() if k in r)
            for k in ids}


def overheads(data: dict[str, dict[str, dict[str, float]]]) -> dict:
    """Overhead table per harness: per design, the per-action medians and
    the delta against the same harness's T0 baseline, plus the WITHIN-FAMILY
    marginals that isolate the ADDED enforcement point from the execution-
    path difference (gateway family: t2-t1, t3-t1; harness-native family:
    t5-t4, t6-t4 — same dispatch path, only the enforcement mechanism
    differs)."""
    marginals = {"t2": "t1", "t3": "t1", "t5": "t4", "t6": "t4"}
    out = {}
    for harness in ("pi", "openclaw"):
        if "t0" not in data or harness not in data["t0"]:
            continue
        base = median_map(data["t0"][harness])
        per_design = {}
        for design in ("t0", "t1", "t2", "t3", "t4", "t5", "t6"):
            if design not in data or harness not in data[design]:
                continue
            runs = data[design][harness]
            med = median_map(runs)
            deltas = {k: med[k] - base[k] for k in med if k in base}
            # per-action spread across runs (the pool state makes single
            # HTTP timings noisy at the tens-of-ms level)
            spread = {}
            for k in sorted(med):
                vals = [r[k] for r in runs.values() if k in r]
                spread[k] = {"median": round(med[k], 3),
                             "min": round(min(vals), 3),
                             "max": round(max(vals), 3)}
            rows = {}
            for cls in SIX_CLASSES:
                ids = [a["id"] for a in rec_mod.load_spec(
                    HERE.parent / "trace" / "traces" / "baseline.yaml")["actions"]
                    if a["class"] == cls]
                if cls == "stdio_tool_call":
                    ids = [i for i in ids if i != STDIO_SESSION_CALL]
                vals = [deltas[i] for i in ids if i in deltas]
                if not vals:
                    continue
                entry = {"median_overhead_ms": round(statistics.median(vals), 3),
                         "per_action_ms": {i: round(deltas[i], 3) for i in ids if i in deltas}}
                if cls == "stdio_tool_call":
                    entry["note"] = (f"excludes {STDIO_SESSION_CALL} "
                                     f"(session establishment: "
                                     f"{med.get(STDIO_SESSION_CALL, float('nan')):.1f} ms "
                                     f"vs baseline {base.get(STDIO_SESSION_CALL, float('nan')):.1f} ms)")
                if design == "t6" and DENY_CASE in med:
                    entry["deny_case_ms"] = round(med[DENY_CASE], 3)
                rows[cls] = entry
            entry_d = {
                "n_runs": len(runs),
                "per_action_median_ms": {k: round(v, 3) for k, v in sorted(med.items())},
                "per_action_spread_ms": spread,
                "overhead_vs_t0_ms": {k: round(v, 3) for k, v in sorted(deltas.items())},
                "per_class": rows,
            }
            # within-family marginal: the added enforcement point's cost on
            # an unchanged dispatch path
            ref = marginals.get(design)
            if ref and ref in data and harness in data[ref]:
                ref_med = median_map(data[ref][harness])
                marg = {k: med[k] - ref_med[k] for k in med if k in ref_med}
                mrows = {}
                for cls in SIX_CLASSES:
                    ids = [a["id"] for a in rec_mod.load_spec(
                        HERE.parent / "trace" / "traces" / "baseline.yaml")["actions"]
                        if a["class"] == cls]
                    vals = [marg[i] for i in ids if i in marg]
                    if vals:
                        mrows[cls] = {"median_ms": round(statistics.median(vals), 3),
                                      "per_action_ms": {i: round(marg[i], 3) for i in ids if i in marg}}
                entry_d["marginal_vs_t" + ref[1:]] = {
                    "median_ms": {k: round(v, 3) for k, v in sorted(marg.items())},
                    "per_class": mrows,
                }
            per_design[design] = entry_d
        out[harness] = {"t0_baseline_ms": {k: round(v, 3) for k, v in sorted(base.items())},
                        "designs": per_design}
    return out


def render_markdown(report: dict) -> str:
    lines = ["# Per-call latency overhead vs the T0 baseline (deterministic replay)",
             "",
             "Medians over reconciliation-passing runs; per-class overhead excludes",
             "a001's MCP session establishment (reported separately). Units: ms.", ""]
    for harness, h in report["analysis"].items():
        lines += [f"## {harness}", "",
                  "| design | " + " | ".join(
                      c.replace("_", " ") for c in SIX_CLASSES) + " |",
                  "|" + "---|" * (1 + len(SIX_CLASSES))]
        for design, dd in h["designs"].items():
            cells = []
            for cls in SIX_CLASSES:
                e = dd["per_class"].get(cls)
                if e is None:
                    cells.append("-")
                else:
                    cells.append(f"{e['median_overhead_ms']:+.1f}")
            lines.append(f"| {design} | " + " | ".join(cells) + " |")
        lines += ["", "Within-family marginals (the added point's cost on an", "unchanged dispatch path):", ""]
        for design, dd in h["designs"].items():
            for key, m in dd.items():
                if key.startswith("marginal_vs_"):
                    cells = [f"{m['per_class'][c]['median_ms']:+.1f}" if c in m['per_class'] else "-"
                             for c in SIX_CLASSES]
                    lines.append(f"- {design.upper()} vs T{key.split('_')[-1][1:]}: " + " | ".join(cells))
        lines.append("")
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--runs-dir", type=Path, default=HERE.parent / "runs")
    ap.add_argument("--out", type=Path, default=None)
    ap.add_argument("--markdown", action="store_true")
    args = ap.parse_args()

    data = collect(args.runs_dir)
    analysis = overheads(data)
    report = {"schema": SCHEMA, "runs_dir": str(args.runs_dir),
              "analysis": analysis}
    text = json.dumps(report, indent=1, sort_keys=True) + "\n"
    if args.out:
        args.out.write_text(text)
        print(f"wrote {args.out}")
    if args.markdown:
        print(render_markdown(report))
    if not args.out and not args.markdown:
        print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
