"""The workload field's mapping to canonical trace specs (the minimal
workload selection).

The experiment file's `workload` field (framework/experiment.py, DESIGN.md
6) names a workload. Today's registry has exactly one registered pack
(baseline-15); the delegation study's fixtures exist as trace VARIANTS —
first-class, hashable spec documents (trace/traces/baseline-*.yaml) whose
per-action `performed_by` marking is the only thing that moves (the
canonical action surface — ids, classes, targets, ops — stays 1:1 with
baseline.yaml, so every coverage number keeps its denominator).

This module is the single place a workload name meets its trace file:
the runner resolves the spec to compile from here, and the execution
layer resolves the spec to assemble against from here. Nothing else
about the workload registry changes (declaring, conforming, grid keys
are out of scope for this pass).
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
TRACES_DIR = REPO_ROOT / "trace" / "traces"

# The prepared default pack (DESIGN.md 6): the canonical 15-action
# baseline. Every experiment that omits `workload` runs this one —
# unchanged behavior for every existing experiment file.
DEFAULT_WORKLOAD = "baseline-15"

# One registered workload name -> one canonical trace spec file under
# trace/traces/. The delegation fixtures (F1-F9) select their trace
# variant by name exactly the way baseline-15 selects the baseline: the
# identity lives in the document (hashed by its sidecar), never in a
# compile flag.
WORKLOAD_TRACES: dict[str, str] = {
    "baseline-15": "baseline.yaml",
    # F2 (implemented): the child-process hand-off, hop 1 and hop 2
    "baseline-f2": "baseline-f2.yaml",
    "baseline-f2h2": "baseline-f2h2.yaml",
    # F1: a role switch inside one process (channel inproc)
    "baseline-f1": "baseline-f1.yaml",
    # F3: an agent hiding inside a local tool (channel tool)
    "baseline-f3": "baseline-f3.yaml",
    # F4: an agent hiding inside a REMOTE tool, on the executor host of
    # the two-host topology (channel tool over http; machine "executor"
    # on the accepted side)
    "baseline-f4": "baseline-f4.yaml",
    # F5: a remote agent server over the A2A-style task interface (channel
    # network, protocol a2a)
    "baseline-f5": "baseline-f5.yaml",
    # F7: the restricted child (two routes to the same effect)
    "baseline-f7": "baseline-f7.yaml",
    # F9: work that outlives its parent (detached child)
    "baseline-f9": "baseline-f9.yaml",
}


class WorkloadError(ValueError):
    """The workload name has no trace spec behind it."""


def trace_spec_path(workload: str | None = None) -> Path:
    """The canonical trace spec file of a workload name (None and the
    default both resolve to baseline-15). An unknown name is an error
    naming the known ones — a typo'd workload must fail at load time,
    never silently run the baseline."""
    name = workload if workload is not None else DEFAULT_WORKLOAD
    try:
        filename = WORKLOAD_TRACES[name]
    except KeyError:
        raise WorkloadError(
            f"unknown workload {name!r} (known: {sorted(WORKLOAD_TRACES)})")
    path = TRACES_DIR / filename
    if not path.is_file():
        raise WorkloadError(f"workload {name!r}: trace spec {path} missing")
    return path
