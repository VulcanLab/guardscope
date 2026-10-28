"""guardscope CLI (experiment-file side): validate and plan.

Usage:
  python -m framework.cli validate <experiment-file>
      Load and validate the experiment file (DESIGN.md 6); print the
      resolved plan (defaults recorded as facts) or the load-time error.
  python -m framework.cli plan <experiment-file>
      Print the expanded run descriptors (one per requested design) as JSON.

Exit codes: 0 ok, 1 load-time validation error, 2 usage.
"""

import argparse
import json
import sys

from framework.experiment import ExperimentError, load_experiment, resolve


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="guardscope", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("validate", "plan"):
        p = sub.add_parser(name)
        p.add_argument("file", help="experiment file (YAML or JSON)")
    args = ap.parse_args(argv)

    try:
        experiment = load_experiment(args.file)
        plan = resolve(experiment)
    except (ExperimentError, OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    if args.command == "validate":
        print(json.dumps(plan.to_dict(), indent=1, sort_keys=True))
    else:
        print(json.dumps([r.to_dict() for r in plan.runs],
                         indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
