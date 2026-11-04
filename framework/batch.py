"""Batch plans (DESIGN.md 6: "a plan file ... is the only file that names
more than one control or design: it expands into K single-control
experiment files plus a merge manifest").

The batch runner is the executable form of a study's frozen measurement
list:

  plan file ──expand──▶ K single-control experiment files
                     ──execute──▶ per row: one warm-up run + N real runs
                     ──record──▶ the batch manifest (rows, labels, run ids,
                                 the merge set)
                     ──merge──▶ the report command over the merge set

Design points, all inherited from the framework's rules:

- ONE CONTROL PER EXPANDED FILE. The plan may carry many rows with
  different controls; each row materializes exactly one experiment file,
  and that file is single-control (or control:null). The framework's
  load-time validation runs on every expanded file, so an inapplicable
  design/control pairing fails the batch at expansion time, before any
  topology is touched.
- WARM-UP RUNS ARE FIRST-CLASS (DESIGN.md 9 / the repo README: the first
  live run of a design produces leftover bookkeeping and fails the
  leftover check by design). With runs_per_measurement > 1 (default 2)
  the runner executes warmup-<row>.yaml first and excludes it from the
  merge set; only the real runs feed the report.
- LABELS RIDE ALONG, UNINTERPRETED. A row may carry a `labels:` block
  (scenario, hops, condition, policy version — study-level concepts the
  framework does not know). Labels are recorded in the batch manifest
  next to the run ids; the study's own tables join on that manifest. The
  framework's comparability keys stay exactly what they are.
- `ready: false` ROWS DO NOT RUN. A frozen list may contain measurements
  whose fixtures do not exist yet (the delegation scenarios until phase
  1 arrives). Such rows expand and validate — so the plan stays one
  artifact — but the runner skips them unless --include-pending is
  given. Nothing runs that is not listed; nothing listed runs before its
  fixture exists.

Usage (CLI): guardscope batch <plan.yaml> [--out-root DIR] [--workdir DIR]
    [--rows id1,id2] [--dry-run] [--include-pending] [--merge] [--no-sensor]

Programmatic: expand_plan(), run_batch() with an injectable executor
(unit tests drive it without Docker, like the execute path).
"""

from __future__ import annotations

import hashlib
import json
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from framework.experiment import ExperimentError, load_experiment, resolve
from framework.execute import execute_experiment

SCHEMA = "guardscope-batch-plan/1"
WARMUP_PREFIX = "warmup-"


class BatchError(ValueError):
    """The plan file is invalid (its own schema, or an expanded row fails
    the experiment-file validation)."""


@dataclass
class BatchRow:
    """One row of the plan: the measurement's experiment fields plus the
    study-level labels and readiness."""
    id: str
    experiment: dict            # the experiment/1 document body
    labels: dict
    ready: bool
    notes: str

    def experiment_doc(self, row_id: str) -> dict:
        doc = {"schema": 1, **self.experiment}
        return doc


@dataclass
class RowResult:
    row_id: str
    executed: bool
    reason: str | None = None       # skip reason when not executed
    labels: dict = field(default_factory=dict)
    notes: str = ""
    runs: list[dict] = field(default_factory=list)
    # each run: {"kind": "warmup"|"real", "stem": ..., "execution": ...,
    #            "run_statuses": ...}


@dataclass
class BatchResult:
    plan_path: Path
    plan_sha256: str
    rows: list[RowResult]
    merge_set: list[str]           # execution.json paths of the REAL runs
    out_root: Path

    def to_dict(self) -> dict:
        return {
            "schema": SCHEMA,
            "plan": {
                "path": str(self.plan_path),
                "sha256": self.plan_sha256,
            },
            "out_root": str(self.out_root),
            "rows": [vars(r) for r in self.rows],
            "merge_set": list(self.merge_set),
        }


# --- plan loading ----------------------------------------------------------------

def _load_doc(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    doc = yaml.safe_load(text)
    if not isinstance(doc, dict):
        raise BatchError(f"{path}: not a mapping at the top level")
    return doc


def load_plan(path) -> tuple[list[BatchRow], dict, str]:
    """Load and structurally validate the plan file.

    Returns (rows, plan_doc, sha256). Experiment-level validation of each
    row happens in expand_plan (each row must materialize into a file the
    framework itself accepts — the validation is the framework's, not a
    batch-side reimplementation).
    """
    path = Path(path)
    doc = _load_doc(path)
    if doc.get("schema") != 1:
        raise BatchError(
            f"{path}: the schema stamp is the bare literal 1 (DESIGN.md 4); "
            f"got {doc.get('schema')!r}")
    raw_rows = doc.get("rows")
    if not isinstance(raw_rows, list) or not raw_rows:
        raise BatchError(f"{path}: 'rows' must be a non-empty list")
    rows: list[BatchRow] = []
    seen: set[str] = set()
    for i, raw in enumerate(raw_rows):
        if not isinstance(raw, dict):
            raise BatchError(f"{path}: row {i} is not a mapping")
        rid = raw.get("id")
        if not isinstance(rid, str) or not rid:
            raise BatchError(f"{path}: row {i} has no string id")
        if rid in seen:
            raise BatchError(f"{path}: duplicate row id {rid!r}")
        seen.add(rid)
        if rid.startswith(WARMUP_PREFIX):
            raise BatchError(
                f"{path}: row id {rid!r} starts with {WARMUP_PREFIX!r} "
                f"(reserved for the warm-up run naming)")
        exp = raw.get("experiment")
        if not isinstance(exp, dict):
            raise BatchError(
                f"{path}: row {rid!r} has no 'experiment' mapping")
        if "schema" in exp:
            raise BatchError(
                f"{path}: row {rid!r}: the experiment block carries no "
                f"schema stamp (expand adds it); got one anyway")
        labels = raw.get("labels") or {}
        if not isinstance(labels, dict):
            raise BatchError(
                f"{path}: row {rid!r}: 'labels' must be a mapping")
        rows.append(BatchRow(
            id=rid, experiment=exp, labels=labels,
            ready=bool(raw.get("ready", True)),
            notes=str(raw.get("notes") or "")))
    return rows, doc, hashlib.sha256(
        path.read_bytes()).hexdigest()


# --- expansion -------------------------------------------------------------------

def expand_plan(path, out_dir, rows=None) -> list[Path]:
    """Materialize each row as ONE single-control experiment file under
    <out_dir>/experiments/ (plus warmup- variants for the warm-up runs)
    and validate each through the framework's own load_experiment +
    resolve — an invalid row fails here, before any topology is touched.

    `rows` optionally filters by row id. Returns the experiment file
    paths of the real runs (warm-up files sit next to them)."""
    plan_rows, _, _ = load_plan(path)
    out_dir = Path(out_dir) / "experiments"
    out_dir.mkdir(parents=True, exist_ok=True)
    if rows is not None:
        wanted = set(rows)
        missing = wanted - {r.id for r in plan_rows}
        if missing:
            raise BatchError(f"no such row(s): {sorted(missing)}")
        plan_rows = [r for r in plan_rows if r.id in wanted]
    written: list[Path] = []
    for row in plan_rows:
        for name in (row.id, f"{WARMUP_PREFIX}{row.id}"):
            f = out_dir / f"{name}.yaml"
            f.write_text(yaml.safe_dump(row.experiment_doc(name),
                                        sort_keys=False),
                         encoding="utf-8")
            # the framework's own validation: load + resolve (the same
            # path `guardscope validate` drives)
            try:
                plan = resolve(load_experiment(f))
            except ExperimentError as exc:
                raise BatchError(f"row {row.id!r} does not expand to a "
                                 f"valid experiment: {exc}") from exc
            written.append(f)
    return sorted(p for p in written
                  if not p.name.startswith(WARMUP_PREFIX))


# --- execution -------------------------------------------------------------------

def run_batch(path, *, out_root=None, workdir=None, rows=None,
              include_pending=False, dry_run=False, sensor=True,
              runs_per_measurement=2, merge=False,
              run_executor=None) -> BatchResult:
    """Expand + execute the plan (DESIGN.md 6): per row, the warm-up run
    first (excluded from the merge set), then the real runs; per run the
    existing execute path writes the run dir + execution.json. The batch
    manifest is written at <out_root>/batch-manifest.json.

    `runs_per_measurement` <= 1 means no warm-up run (measurements whose
    design already has a warm run from an earlier session may use 1).
    """
    from framework.workdir import resolve_workdir
    wd = resolve_workdir(workdir)
    out_root = Path(out_root) if out_root else wd / "runs"
    out_root.mkdir(parents=True, exist_ok=True)

    plan_rows, plan_doc, plan_sha = load_plan(path)
    if rows is not None:
        wanted = set(rows)
        plan_rows = [r for r in plan_rows if r.id in wanted]
    rpm = int(plan_doc.get("runs_per_measurement", runs_per_measurement))

    # expansion validates every row (pending or not): the plan stays one
    # artifact even when parts of it are not buildable yet
    expand_plan(path, out_root, rows=rows)

    results: list[RowResult] = []
    merge_set: list[str] = []
    for row in plan_rows:
        res = RowResult(row_id=row.id, executed=False,
                        labels=dict(row.labels), notes=row.notes)
        results.append(res)
        if not row.ready and not include_pending:
            res.reason = ("ready: false (the measurement's fixture is not "
                          "built yet); use --include-pending to run anyway")
            continue
        if dry_run:
            res.reason = "dry run (expanded and validated, not executed)"
            res.executed = True
            continue
        res.executed = True
        kinds = (["warmup"] * (1 if rpm > 1 else 0)) + ["real"] * max(1, rpm - (1 if rpm > 1 else 0))
        # rpm == 2 -> [warmup, real]; rpm == 1 -> [real]; rpm == 3 ->
        # [warmup, real, real]
        if rpm > 2:
            kinds = ["warmup"] + ["real"] * (rpm - 1)
        for kind in kinds:
            stem = row.id if kind == "real" else f"{WARMUP_PREFIX}{row.id}"
            exp_file = out_root / "experiments" / f"{stem}.yaml"
            try:
                result = execute_experiment(
                    exp_file, out_root=out_root, sensor=sensor,
                    workdir=workdir, run_executor=run_executor)
            except Exception as exc:  # noqa: BLE001 — a failed row must
                # not abort the batch; the failure is recorded per row
                res.runs.append({"kind": kind, "stem": stem,
                                 "status": "fail", "error": str(exc)})
                continue
            manifest = Path(result.manifest_path)
            statuses = [getattr(r, "status", "?") for r in result.runs]
            entry = {"kind": kind, "stem": stem,
                     "run_statuses": statuses,
                     "execution": str(manifest)}
            res.runs.append(entry)
            if kind == "real" and manifest.is_file():
                merge_set.append(str(manifest))
    batch = BatchResult(plan_path=Path(path), plan_sha256=plan_sha,
                        rows=results, merge_set=merge_set,
                        out_root=out_root)
    (out_root / "batch-manifest.json").write_text(
        json.dumps(batch.to_dict(), indent=1) + "\n", encoding="utf-8")
    return batch


def merge_command(batch: BatchResult) -> list[str]:
    """The report command that merges the batch's real runs (DESIGN.md
    10; the batch runner never re-implements merging — it hands the
    execution manifests to the report command)."""
    return (["guardscope", "report"]
            + [Path(p) for p in batch.merge_set])
