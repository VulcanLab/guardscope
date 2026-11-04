#!/usr/bin/env python3
"""Enforcement-point sensor + inspection-coverage computation (T1-4) — CLI wrapper.

The C1-C4 checks and the coverage computation now live in
framework/reconcile.py (the core-science re-home, M1 pass 2); this file keeps
the CLI and re-exports the library surface unchanged for its existing
callers (runner/runrecord.py, runner/run.py, the tests). See
framework/reconcile.py for the computation documentation.

Usage:
  python3 runner/coverage.py --spec trace/traces/baseline.yaml \
      --design t1 --decisions runs/<id>/gateway/decisions.jsonl \
      [--replay runs/<id>/replay-result.json] \
      [--out runs/<id>/coverage.json]

Exit codes: 0 pass, 1 coverage failed (report still written), 2 usage.
"""

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE))            # framework package (core science)
sys.path.insert(0, str(HERE / "runner")) # runner modules (reconcile, spec loading)

import reconcile as rec_mod  # noqa: E402
from framework.reconcile import (  # noqa: E402,F401  (re-exported surface)
    SCHEMA,
    GATEWAY_TOOL_ROUTES,
    INSPECTED_CLASSES,
    SIX_CLASSES,
    PREVENTED_CLASSES,
    ts_to_epoch_ns,
    load_decisions,
    compute,
    _route_action,
    _tool_for,
    _params_match,
    decision_records_to_log_entries,
)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--spec", type=Path, required=True)
    ap.add_argument("--design", required=True, choices=sorted(INSPECTED_CLASSES))
    ap.add_argument("--decisions", type=Path, required=True)
    ap.add_argument("--replay", type=Path, default=None,
                   help="replay-result.json; supplies the measurement window")
    ap.add_argument("--window-tolerance-ns", type=int, default=1_000_000_000)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    spec = rec_mod.load_spec(args.spec)
    decisions, problems = load_decisions(args.decisions)
    window = None
    replay_doc = None
    if args.replay:
        replay_doc = rec_mod.load_replay(args.replay)
        w = replay_doc.get("window_epoch_ns") or {}
        window = (int(w["start"]), int(w["end"]))
    report = compute(spec, decisions, problems, args.design, window,
                     args.window_tolerance_ns,
                     replay=replay_doc if args.replay else None)

    payload = json.dumps(report, indent=1, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload)
    print(payload, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
