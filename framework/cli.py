"""guardscope CLI (experiment-file side): validate, plan, and run.

Usage:
  python -m framework.cli validate <experiment-file>
      Load and validate the experiment file (DESIGN.md 6); print the
      resolved plan (defaults recorded as facts) or the load-time error.
  python -m framework.cli plan <experiment-file>
      Print the expanded run descriptors (one per requested design) as JSON.
  python -m framework.cli run <experiment-file> [--out-root runs]
      Execute the experiment (DESIGN.md 9): one live run per requested
      design, then the framework run manifest (decision records mapped to
      decision-record/1, recomputed C1-C4 coverage with the consistency
      assertion, C5 id consistency when dispatch records and the native
      decision stream are present, findings, evidence class) written to
      <out-root>/<experiment-id>/execution.json. Requires the Linux
      testbed host (Docker, compose, arm64); prints one summary line per
      design.
  python -m framework.cli fidelity <config-file>
      Validate a correlation-fidelity-check config (DESIGN.md 5: the marked
      tools/call per transport through a control) and print the plan.
      Requires a running topology to execute, so this validates the inputs
      only; the live issuer/collector wiring lands in a later pass.

Exit codes: 0 ok, 1 load-time validation error or failed run, 2 usage.
"""

import argparse
import json
import sys

from framework.experiment import ExperimentError, load_experiment, resolve


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="guardscope", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("validate", "plan", "run"):
        p = sub.add_parser(name)
        p.add_argument("file", help="experiment file (YAML or JSON)")
        if name == "run":
            p.add_argument("--out-root", default="runs",
                           help="root for run artifacts and execution.json")
    p = sub.add_parser("fidelity")
    p.add_argument("file", help="fidelity-check config (YAML or JSON)")
    args = ap.parse_args(argv)

    if args.command == "fidelity":
        from framework.fidelity import (FidelityConfigError,
                                        load_fidelity_config)
        try:
            cfg = load_fidelity_config(args.file)
        except (FidelityConfigError, OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        # The live check issues one marked tools/call per transport against
        # the compose stack and collects the emitted decision records; that
        # requires a running topology (later pass). Inputs are validated;
        # nothing is executed here.
        print(json.dumps({**cfg, "status": "not-run",
                          "note": ("executing the fidelity check requires a "
                                   "running topology (compose stack with the "
                                   "control provisioned); not implemented "
                                   "this pass")}, indent=1, sort_keys=True))
        return 0

    try:
        experiment = load_experiment(args.file)
        plan = resolve(experiment)
    except (ExperimentError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.command == "run":
        from framework.execute import execute_experiment
        try:
            result = execute_experiment(args.file, out_root=args.out_root)
        except (ExperimentError, OSError, RuntimeError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        summaries = [{
            "run_id": s.run_id,
            "design": s.design,
            "fixture": s.fixture,
            "control": s.control,
            "status": s.status,
            "coverage": (s.coverage or {}).get("status"),
            "coverage_consistent": s.coverage_consistent,
            "decision_records": s.decision_record_count,
            "evidence_class": s.evidence_class,
            "degraded": s.degraded,
            "c5": (s.c5 or {}).get("status"),
            "findings": [f.get("id") for f in s.findings],
            "run_dir": s.run_dir,
        } for s in result.runs]
        print(json.dumps(summaries, indent=1, sort_keys=True))
        print(f"execution manifest: {result.manifest_path}", file=sys.stderr)
        # a run is ok when it reconciled pass, its recomputed coverage
        # passes, and the consistency assertion held (degraded flags do
        # not fail the execution; they are recorded, never silent)
        ok = all(s.status == "pass"
                 and (s.coverage or {}).get("status", "pass") == "pass"
                 and s.coverage_consistent is not False
                 and not s.findings
                 for s in result.runs)
        return 0 if ok else 1

    if args.command == "validate":
        print(json.dumps(plan.to_dict(), indent=1, sort_keys=True))
    else:
        print(json.dumps([r.to_dict() for r in plan.runs],
                         indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
