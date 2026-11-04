"""guardscope CLI (experiment-file side): validate, plan, run, and report.

Usage:
  python -m framework.cli validate <experiment-file>
      Load and validate the experiment file (DESIGN.md 6); print the
      resolved plan (defaults recorded as facts) or the load-time error.
  python -m framework.cli plan <experiment-file> [--workdir DIR]
      Print the expanded run descriptors (one per requested design) as
      JSON; the resolved artifact paths (workdir, out root, replay
      staging) go to stderr.
  python -m framework.cli run <experiment-file> [--out-root runs]
      [--workdir DIR] [--no-sensor]
      Execute the experiment (DESIGN.md 9): one live run per requested
      design, then the framework run manifest (decision records mapped to
      decision-record/1, recomputed C1-C4 coverage with the consistency
      assertion, C5 id consistency when dispatch records and the native
      decision stream are present, C6 denial effectiveness when kernel
      evidence exists, findings, outcome counts with the verified flag,
      evidence class) written to <out-root>/<experiment-id>/execution.json.
      Requires the Linux testbed host (Docker, compose, arm64); prints one
      summary line per design. --no-sensor is the degraded no-eBPF mode
      (DESIGN.md 9): the sensor is not brought up (compose without
      --profile sensor), every output is labeled self-reported, and C6 is
      skipped with a note.
  python -m framework.cli report <execution.json>... [--runs-root runs]
      [--strict] [--allow-incomparable] [--out merged.json]
      Merge single-control execution manifests into report-level grids
      (DESIGN.md 10): columns are (control, design) runs, grouped by the
      comparability key; the JSON report is the contract and a short human
      summary is printed to stdout (to stderr when the JSON itself goes to
      stdout, i.e. when --out is omitted).
  python -m framework.cli fidelity <config-file>
      Validate a correlation-fidelity-check config (DESIGN.md 5: the marked
      tools/call per transport through a control) and print the plan.
      Requires a running topology to execute, so this validates the inputs
      only; the live issuer/collector wiring arrives in a later pass.
  python -m framework.cli registry ls
      List registry entries with their tier and current/stale status
      (DESIGN.md 11: staleness downgrades the display, never hides it).
  python -m framework.cli registry show <plugin_id>
      Print the plugin's registry verdict entries (both tiers) and its
      selection-rule facts as JSON.

Exit codes: 0 ok, 1 load-time validation error or failed run, 2 usage.
"""

import argparse
import json
import sys
from pathlib import Path

from framework.experiment import ExperimentError, load_experiment, resolve
from framework.workdir import resolve_workdir, staging_dir


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="guardscope", description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="command", required=True)
    for name in ("validate", "plan", "run"):
        p = sub.add_parser(name)
        p.add_argument("file", help="experiment file (YAML or JSON)")
        if name == "run":
            p.add_argument("--out-root", default=None,
                           help="root for run artifacts and execution.json "
                                "(default: <workdir>/runs)")
            p.add_argument("--workdir", default=None,
                           help="writable root for run artifacts: replay "
                                "staging, run outputs, compile cache "
                                "(default: GUARDSCOPE_WORKDIR or the cwd; "
                                "framework/workdir.py)")
            p.add_argument("--no-sensor", action="store_true",
                           help="degraded no-eBPF mode (DESIGN.md 9): run "
                                "without the sensor (compose up WITHOUT "
                                "--profile sensor); outputs are labeled "
                                "self-reported")
        if name == "plan":
            p.add_argument("--workdir", default=None,
                           help="resolve the artifact paths against this "
                                "writable root (default: GUARDSCOPE_WORKDIR "
                                "or the cwd); the resolved paths are "
                                "printed to stderr")
    p = sub.add_parser(
        "batch",
        help="expand + execute a batch plan (DESIGN.md 6: the only file "
             "that names many controls/designs; one warm-up run per "
             "measurement, excluded from the merge set)")
    p.add_argument("file", help="batch plan file (YAML)")
    p.add_argument("--out-root", default=None,
                   help="root for the expanded experiment files, run "
                        "artifacts, and batch-manifest.json "
                        "(default: <workdir>/runs)")
    p.add_argument("--workdir", default=None,
                   help="writable root for run artifacts "
                        "(default: GUARDSCOPE_WORKDIR or the cwd)")
    p.add_argument("--rows", default=None,
                   help="comma-separated row ids to run (default: all)")
    p.add_argument("--dry-run", action="store_true",
                   help="expand + validate every row, execute nothing")
    p.add_argument("--include-pending", action="store_true",
                   help="also run rows marked ready: false (measurements "
                        "whose fixture is not built yet)")
    p.add_argument("--no-sensor", action="store_true",
                   help="degraded no-eBPF mode for every row (DESIGN.md 9)")
    p.add_argument("--merge", action="store_true",
                   help="after the runs, also write the merged report "
                        "over the real runs' execution manifests")
    p = sub.add_parser(
        "report",
        help="merge execution manifests into report-level grids "
             "(DESIGN.md 10)")
    p.add_argument("manifests", nargs="*",
                   help="execution.json manifest path(s)")
    p.add_argument("--runs-root", default=None,
                   help="convenience: glob <runs-root>/*/execution.json")
    p.add_argument("--strict", action="store_true",
                   help="hard-fail on any comparability-key mismatch")
    p.add_argument("--allow-incomparable", action="store_true",
                   help="force one grid; affected columns are marked "
                        "non-comparable per cell (DESIGN.md 10)")
    p.add_argument("--out", type=Path, default=None,
                   help="write the merged JSON report here (default: stdout)")
    p = sub.add_parser("fidelity")
    p.add_argument("file", help="fidelity-check config (YAML or JSON)")
    reg = sub.add_parser(
        "registry",
        help="the plugin registry (DESIGN.md 11: two tiers, expiring "
             "verdicts, selection-rule facts)")
    rsub = reg.add_subparsers(dest="registry_command", required=True)
    ls = rsub.add_parser("ls", help="list entries with tier + current/stale "
                                    "status")
    ls.add_argument("--registry-root", default=None,
                   help="use a different registry directory (default: "
                        "the repo's registry/)")
    show = rsub.add_parser("show", help="print a plugin's registry entries "
                                        "and facts as JSON")
    show.add_argument("plugin_id")
    show.add_argument("--registry-root", default=None,
                      help="use a different registry directory (default: "
                           "the repo's registry/")
    args = ap.parse_args(argv)

    if args.command == "registry":
        from framework import registry as reg_mod
        try:
            docs = reg_mod.load_verdict_docs(
                registry_root=args.registry_root)
            facts = reg_mod.load_fact_docs(
                registry_root=args.registry_root)
        except reg_mod.RegistryError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        if args.registry_command == "ls":
            lines = []
            for tier in reg_mod.TIERS:
                for plugin_id, doc in sorted(docs[tier].items()):
                    for entry in doc.get("entries") or []:
                        verdict = entry.get("verdict") or {}
                        # Current keys from the repo's state, NOT from the
                        # verdict: pinning plugin_version from the verdict
                        # would make a manifest version bump invisible to
                        # the staleness display (DESIGN.md 11: staleness
                        # downgrades the display, never hides it)
                        keys = reg_mod.current_keys(plugin_id)
                        current, reasons = reg_mod.is_verdict_current(
                            verdict, current_keys=keys)
                        state = ("current" if current
                                 else "stale: " + "; ".join(reasons))
                        lines.append(
                            f"{plugin_id}  tier={tier}  "
                            f"level={verdict.get("level")}  "
                            f"status={verdict.get("status")}  "
                            f"plugin_version={verdict.get("plugin_version")}  "
                            f"{state}")
            for plugin_id, doc in sorted(facts.items()):
                lines.append(
                    f"{plugin_id}  facts  "
                    f"last_verified={doc.get("last_verified") or 'unknown'}  "
                    f"maintainer={doc.get("maintainer") or 'unknown'}")
            print("\n".join(lines) if lines else "registry is empty")
            return 0
        # show
        found = {tier: docs[tier].get(args.plugin_id) for tier in
                 reg_mod.TIERS}
        if not any(found.values()) and args.plugin_id not in facts:
            print(f"error: no registry entry or facts for plugin "
                  f"{args.plugin_id!r}", file=sys.stderr)
            return 1
        print(json.dumps({"plugin": args.plugin_id,
                          "verdicts": found, "facts": facts.get(
                              args.plugin_id)},
                         indent=1, sort_keys=True))
        return 0


    if args.command == "report":
        from framework.report import MergeError, merge_reports, render_summary
        paths = [Path(m) for m in args.manifests]
        if args.runs_root:
            paths += sorted(Path(args.runs_root).glob("*/execution.json"))
        if not paths:
            print("error: report needs execution.json manifest path(s) "
                  "or --runs-root", file=sys.stderr)
            return 2
        missing = [str(p) for p in paths if not p.is_file()]
        if missing:
            print(f"error: no such execution manifest: "
                  f"{', '.join(missing)}", file=sys.stderr)
            return 1
        try:
            report = merge_reports(paths, strict=args.strict,
                                   allow_incomparable=args.allow_incomparable)
        except MergeError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        text = json.dumps(report, indent=1, sort_keys=True) + "\n"
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(text, encoding="utf-8")
            print(render_summary(report))          # the human summary
        else:
            print(text, end="")                   # the JSON contract
            print(render_summary(report), file=sys.stderr)
        return 0

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

    # the experiment-file commands share the load+resolve prelude; batch
    # is NOT one of them (its file is a batch plan, not an experiment file)
    if args.command == "batch":
        from framework.batch import (BatchError, merge_command, run_batch)
        rows = ([r for r in args.rows.split(",") if r]
                if args.rows else None)
        try:
            batch = run_batch(args.file, out_root=args.out_root,
                              workdir=args.workdir, rows=rows,
                              include_pending=args.include_pending,
                              dry_run=args.dry_run,
                              sensor=not args.no_sensor)
        except (BatchError, ExperimentError, OSError, ValueError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
        for r in batch.rows:
            if r.executed and not r.reason:
                st = [f"{u['kind']}:{u.get('run_statuses')}"
                      for u in r.runs]
                print(f"[batch] {r.row_id}: {' '.join(st)}")
            else:
                print(f"[batch] {r.row_id}: skipped ({r.reason})")
        print(f"batch manifest: {batch.out_root}/batch-manifest.json",
              file=sys.stderr)
        print(f"merge ({len(batch.merge_set)} real runs): "
              f"{' '.join(map(str, merge_command(batch)))}",
              file=sys.stderr)
        if args.merge and batch.merge_set:
            from framework.report import merge_reports as merge_manifests
            report = merge_manifests(batch.merge_set)
            out = batch.out_root / "batch-merged.json"
            out.write_text(json.dumps(report, indent=1) + "\n",
                            encoding="utf-8")
            print(f"merged report: {out}", file=sys.stderr)
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
            result = execute_experiment(args.file, out_root=args.out_root,
                                        sensor=not args.no_sensor,
                                        workdir=args.workdir)
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
            "c6": (s.c6 or {}).get("status"),
            "outcome_counts_verified": (s.outcome_counts or {}).get("verified"),
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
        # the plan carries the base+overlay composition per run: the merged
        # fixture id, the overlay bundle path, and the on-matrix overlay
        # validation (framework/overlay.py validate_overlay; violations
        # show as overlay_problems and flag the run off_matrix, DESIGN.md 7)
        print(json.dumps(plan.to_dict(), indent=1, sort_keys=True))
    else:
        # plan: print the expanded run descriptors (stdout, the contract)
        # and the resolved artifact paths (stderr, so piping stdout stays
        # machine-readable). Each run carries the merged fixture id and the
        # fixture fingerprint's two hashes (base compose + control-binding
        # overlay; DESIGN.md 7 base+overlay, DESIGN.md 10 comparability key).
        from framework.execute import fixture_fingerprint
        wd = resolve_workdir(getattr(args, "workdir", None))
        print(f"workdir: {wd}", file=sys.stderr)
        print(f"out root: {wd / 'runs'}", file=sys.stderr)
        print(f"replay staging: {staging_dir(wd)}", file=sys.stderr)
        runs = [{**r.to_dict(), "fixture_fingerprint": fixture_fingerprint(r)}
                for r in plan.runs]
        print(json.dumps(runs, indent=1, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
