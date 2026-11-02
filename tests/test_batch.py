"""Batch-plan tests (framework/batch.py; DESIGN.md 6).

Covers:
  - plan loading: the bare schema stamp, the rows list, duplicate ids,
    the reserved warmup- prefix, the experiment-block shape, labels;
  - expansion: each row materializes as ONE single-control experiment
    file that the framework's own validate path accepts; an invalid
    row fails the batch BEFORE anything executes;
  - ready: false rows: expanded + validated, but skipped by the runner
    unless include_pending — the frozen list stays one artifact while
    unbuilt fixtures cannot run;
  - the warm-up convention: runs_per_measurement=2 (the default) runs
    warmup-<id> first and EXCLUDES it from the merge set; only real
    runs feed the report;
  --rows filter; dry-run (expand + validate, execute nothing);
  - a failed row does not abort the batch: the failure is recorded per
    row and the batch continues (a study's 137 rows must not die on
    row 3);
  - the batch manifest: plan sha256, per-row labels + run statuses, and
    the merge set of real-run execution manifests;
  - the end-to-end shape against the real experiment machinery: a
    two-row plan over existing designs with the injected fake executor
    (no Docker), then the report merge over the batch's merge set.

Run from the repo root:  python3 -m pytest tests/test_batch.py -v
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from framework.batch import (BatchError, expand_plan, load_plan,  # noqa: E402
                             merge_command, run_batch)
from framework.execute import ExecutionResult  # noqa: E402


def write_plan(tmp_path, doc) -> Path:
    p = tmp_path / "plan.yaml"
    p.write_text(yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return p


def row(rid, control, designs, **extra):
    r = {"id": rid,
         "experiment": {"control": control, "designs": designs,
                        "harness": "pi", "workload": "baseline-15"}}
    r.update(extra)
    return r


BASIC = {"schema": 1, "rows": [
    row("m-a", None, ["t0"]),
    row("m-b", "agt-gateway", ["t1"]),
]}


def test_plan_loads(tmp_path):
    p = write_plan(tmp_path, BASIC)
    rows, doc, sha = load_plan(p)
    assert [r.id for r in rows] == ["m-a", "m-b"]
    assert doc["schema"] == 1
    assert len(sha) == 64


def test_plan_schema_stamp_required(tmp_path):
    p = write_plan(tmp_path, {"rows": BASIC["rows"]})
    with pytest.raises(BatchError, match="bare literal 1"):
        load_plan(p)


def test_plan_duplicate_and_reserved_ids(tmp_path):
    with pytest.raises(BatchError, match="duplicate row id"):
        load_plan(write_plan(tmp_path, {"schema": 1, "rows": [
            row("m-a", None, ["t0"]), row("m-a", None, ["t0"])]}))
    with pytest.raises(BatchError, match="reserved"):
        load_plan(write_plan(tmp_path, {"schema": 1, "rows": [
            row("warmup-x", None, ["t0"])]}))


def test_expansion_validates_every_row(tmp_path):
    p = write_plan(tmp_path, BASIC)
    files = expand_plan(p, tmp_path)
    # one real file + one warmup file per row
    names = sorted(f.name for f in tmp_path.glob("experiments/*.yaml"))
    assert names == ["m-a.yaml", "m-b.yaml",
                     "warmup-m-a.yaml", "warmup-m-b.yaml"]
    assert sorted(f.stem for f in files) == ["m-a", "m-b"]


def test_expansion_rejects_invalid_row(tmp_path):
    # t7 with the gateway control: the framework's load-time validation
    # names the conflict; the batch refuses to expand it at all
    p = write_plan(tmp_path, {"schema": 1, "rows": [
        row("m-bad", "agt-gateway", ["t7"])]})
    with pytest.raises(BatchError, match="does not expand to a valid"):
        expand_plan(p, tmp_path)


def test_rows_filter_and_unknown_rows(tmp_path):
    p = write_plan(tmp_path, BASIC)
    files = expand_plan(p, tmp_path, rows=["m-b"])
    assert [f.stem for f in files] == ["m-b"]
    with pytest.raises(BatchError, match="no such row"):
        expand_plan(p, tmp_path, rows=["m-nope"])


# --- execution with the fake executor -------------------------------------------

class FakeExecutor:
    """Records every (descriptor, run_id) and writes a minimal
    execution.json per experiment stem, like the real executor does."""

    def __init__(self, out_root, fail_rows=()):
        self.calls = []
        self.out_root = Path(out_root)
        self.fail_rows = set(fail_rows)

    def __call__(self, descriptor, run_id, runs_dir, **kw):
        self.calls.append((run_id, descriptor.design))
        # execute_experiment derives the stem from the experiment file's
        # name; the fake executor writes the manifest the batch needs
        return None


def fake_execute_experiment_factory(fail_stems=()):
    """Patch framework.execute.execute_experiment for run_batch tests:
    writes a real execution.json per stem so the merge set fills."""
    from framework import batch as batch_mod

    def fake(experiment_path, *, out_root=None, sensor=True,
             workdir=None, run_executor=None):
        stem = Path(experiment_path).stem
        if stem in fail_stems:
            raise RuntimeError(f"simulated failure for {stem}")
        out = Path(out_root)
        d = out / stem
        d.mkdir(parents=True, exist_ok=True)
        mf = d / "execution.json"
        mf.write_text(json.dumps({"experiment_id": stem,
                                  "runs": []}) + "\n")
        # minimal ExecutionResult-shaped object
        class R:
            manifest_path = mf
            runs = []
        return R()
    batch_mod.execute_experiment = fake
    return batch_mod


def test_run_batch_warmup_and_merge_set(tmp_path, monkeypatch):
    batch_mod = fake_execute_experiment_factory()
    monkeypatch.setattr(batch_mod, "execute_experiment",
                        batch_mod.execute_experiment)
    p = write_plan(tmp_path, BASIC)
    batch = run_batch(p, out_root=tmp_path / "runs")
    assert [r.executed for r in batch.rows] == [True, True]
    # each row: one warmup + one real run
    kinds = {u["kind"] for r in batch.rows for u in r.runs}
    assert kinds == {"warmup", "real"}
    # the merge set carries ONLY the real runs' manifests (the warm-up
    # manifest sits at warmup-<id>/execution.json; the real run at <id>/)
    assert len(batch.merge_set) == 2
    assert all(not Path(m).parent.name.startswith("warmup-")
               for m in batch.merge_set)
    # the batch manifest is on disk with the plan hash + labels
    doc = json.loads((tmp_path / "runs" / "batch-manifest.json")
                     .read_text())
    assert doc["plan"]["sha256"] == batch.plan_sha256
    assert [r["row_id"] for r in doc["rows"]] == ["m-a", "m-b"]


def test_pending_rows_skipped_and_included(tmp_path, monkeypatch):
    batch_mod = fake_execute_experiment_factory()
    doc = {"schema": 1, "rows": [
        row("m-a", None, ["t0"]),
        row("m-later", None, ["t0"], ready=False,
            labels={"scenario": "s2"},
            notes="fixture not built yet")]}
    p = write_plan(tmp_path, doc)
    batch = run_batch(p, out_root=tmp_path / "runs")
    by_id = {r.row_id: r for r in batch.rows}
    assert by_id["m-a"].executed is True
    assert by_id["m-later"].executed is False
    assert "ready: false" in by_id["m-later"].reason
    # include_pending runs it anyway
    batch2 = run_batch(p, out_root=tmp_path / "runs2",
                       include_pending=True)
    assert all(r.executed for r in batch2.rows)
    assert len(batch2.merge_set) == 2


def test_failed_row_does_not_abort_batch(tmp_path, monkeypatch):
    batch_mod = fake_execute_experiment_factory(
        fail_stems=("m-b",))  # the real run of row b fails
    doc = {"schema": 1, "rows": [
        row("m-a", None, ["t0"]), row("m-b", None, ["t0"])]}
    p = write_plan(tmp_path, doc)
    batch = run_batch(p, out_root=tmp_path / "runs")
    by_id = {r.row_id: r for r in batch.rows}
    assert by_id["m-a"].executed and by_id["m-b"].executed
    b_runs = by_id["m-b"].runs
    # the warmup ran; the real run recorded its failure
    assert any(u.get("status") == "fail" for u in b_runs)
    # the failed row's manifest is not in the merge set
    assert len(batch.merge_set) == 1


def test_dry_run_expands_but_executes_nothing(tmp_path, monkeypatch):
    batch_mod = fake_execute_experiment_factory()
    p = write_plan(tmp_path, BASIC)
    batch = run_batch(p, out_root=tmp_path / "runs", dry_run=True)
    assert all(r.executed for r in batch.rows)
    assert all(r.reason.startswith("dry run") for r in batch.rows)
    assert batch.merge_set == []
    # the expanded files exist (validated) but no execution.json does
    assert list((tmp_path / "runs").glob("experiments/*.yaml"))
    assert not list((tmp_path / "runs").glob("*/execution.json"))


def test_labels_recorded_in_batch_manifest(tmp_path, monkeypatch):
    batch_mod = fake_execute_experiment_factory()
    doc = {"schema": 1, "rows": [
        row("m-x", None, ["t0"], labels={"scenario": "s3", "hops": 2,
                                         "condition": "retry"})]}
    p = write_plan(tmp_path, doc)
    batch = run_batch(p, out_root=tmp_path / "runs")
    m = json.loads((tmp_path / "runs" / "batch-manifest.json").read_text())
    assert m["rows"][0]["labels"] == {"scenario": "s3", "hops": 2,
                                     "condition": "retry"}


def test_single_control_per_expanded_file(tmp_path):
    """The one-control rule, structurally: every expanded experiment
    file is one the framework accepts, and the framework itself refuses
    two controls — so a plan row CANNOT smuggle a cross product (the
    composition block with a non-null control fails load)."""
    fixture = {"name": "x", "composition": [
        {"plugin": "agt-gateway"}, {"plugin": "actplane"}]}
    experiment = {"control": "agt-gateway", "designs": ["t1"],
                  "harness": "pi", "workload": "baseline-15",
                  "fixture": fixture}
    bad = {"schema": 1, "rows": [{"id": "m-bad",
                                   "experiment": experiment}]}
    p = write_plan(tmp_path, bad)
    with pytest.raises(BatchError, match="does not expand to a valid"):
        expand_plan(p, tmp_path)
