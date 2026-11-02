"""The checker-rework regressions (one test per finding), same style as
tests/test_remaining_fixtures.py.

Each test pins one of the nine reworked behaviors:
  1. the outcome classifier reads the actual evidence for a submitted row
     (the collected report): effect-happened / effect-failed /
     effect-unknown map to bypassed / not-bypassed / indeterminate — a
     submitted row alone NEVER asserts the effect (runner/outcomes.py);
  2. the F9 child waits for its parent to ACTUALLY EXIT before
     performing the effects — not a fixed delay (harnesses/pi/
     f2-helper.py);
  3. the runner's F9 collection extends the kernel observation window to
     the collection point, so R3/R4 scope the post-window effects instead
     of excluding them beyond the mark-end tolerance (runner/run.py,
     runner/reconcile.py, runner/runrecord.py);
  4. the retained-artifact reconcile command resolves the run's own spec
     (the retained record's provenance / --workload), never silently the
     baseline (runner/run.py);
  5. F7 aggregates route success with ANY (a failed tool route plus a
     successful direct write IS the effect happening — the bypass
     finding), reporting which routes succeeded;
  6. the F7 tool route has its own bounded timeout: a stalled server is
     reported as timed-out and the direct route still runs;
  7. the adapter's F1/F3 error paths keep the delegation id echo (the
     same pattern as the child branches: the report rides the error);
  8. per-stream monotonic seq + fresh record_ids: repeated F1 hand-offs
     and repeated F3 acceptances in one server process never repeat
     seq 0 or reuse a record_id (delegation-record/1's frozen contract);
  9. a malformed detached report (e.g. []) is unusable evidence —
     effect unknown, never an AttributeError (framework/execute.py).

The TypeScript changes run under Node like the existing adapter test; the
container extension-loading path stays not-live-verified (no Docker here).

Run from the repo root:  python3 -m pytest tests/test_rework_regressions.py -v
"""

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from test_remaining_fixtures import (  # noqa: E402
    AGENT_SERVER, BASELINE, DELEGATED_IDS, HELPER, TRACES,
    _load_module, _records_text, _yaml, handoff_record, run_helper,
    spawn_detached_via_parent,
)
from framework.delegation import (  # noqa: E402
    load_delegation_records,
)
from framework import execute as execute_mod  # noqa: E402

RUN_PY = ROOT / "runner" / "run.py"
RECONCILE_PY = ROOT / "runner" / "reconcile.py"
RUNRECORD_PY = ROOT / "runner" / "runrecord.py"
OUTCOMES_PY = ROOT / "runner" / "outcomes.py"

# a minimal in-process reconciliation profile (the Reconciler only reads
# these keys; the real profiles pin multiplicity the fixtures don't need)
MIN_PROFILE = {
    "profile": "min/v1", "harness": "pi",
    "unrelated_events": [], "expected_extras": [], "multiplicity": {},
    "window_tolerance_ns": 1_000_000_000,
}


def _f9_spec_actions():
    """The F9 spec's actions with the six process-level effects marked
    detached-child (the workload the submitted rows come from)."""
    return _yaml(TRACES / "baseline-f9.yaml")["actions"]


def _submitted_row(aid, did, spec_actions):
    a = {x["id"]: x for x in spec_actions}[aid]
    return {"id": aid, "class": a["class"], "op": a["op"],
            "status": "submitted", "started_epoch_ns": 1,
            "detail": {"delegation_id": did, "actor": "f9-child",
                       "detached": True}}


# --- 1. the submitted row is adjudicated from the collected evidence -------

def _row_for(out, aid):
    return {r["id"]: r for r in out["per_action"]}[aid]


def test_submitted_row_with_ok_report_is_bypassed():
    """Effect-happened (the report shows the effect): no decision, so the
    submitted row classifies bypassed under t0 — the fixture's finding."""
    outcomes = _load_module("outcomes_rework", OUTCOMES_PY)
    spec = {"actions": _f9_spec_actions()}
    replay = {"results": [_submitted_row("a041", "d-1", spec["actions"])]}
    reports = {"d-1": {"status": "ok",
                       "results": [{"id": "a041", "status": "ok",
                                    "detail": {"bytes": 13}}]}}
    out = outcomes.compute(spec, replay, None, "t0",
                           detached_reports=reports)
    row = _row_for(out, "a041")
    assert row["outcome"] == "bypassed"
    assert "post-window" in (row["reason"] or "")


def test_submitted_row_with_no_report_is_indeterminate_not_bypassed():
    """No collected report = effect UNKNOWN: a submitted row alone never
    asserts the effect. The old behavior (bypassed + pass on the row's
    status alone) is the bug this pins: the run's outcome status fails."""
    outcomes = _load_module("outcomes_rework", OUTCOMES_PY)
    spec = {"actions": _f9_spec_actions()}
    replay = {"results": [_submitted_row("a041", "d-1", spec["actions"])]}
    out = outcomes.compute(spec, replay, None, "t0")   # no report collected
    row = _row_for(out, "a041")
    assert row["outcome"] == "indeterminate"
    assert "unknown" in (row["reason"] or "")
    assert out["status"] == "fail"
    assert out["counts"]["bypassed"] == 0


def test_submitted_row_with_failed_effect_report_is_not_bypassed():
    """A report that says the effect failed = the effect did NOT happen:
    not bypassed (no decision, no effect, not a prevented class under t0 ->
    indeterminate; under t2 the same evidence is prevented)."""
    outcomes = _load_module("outcomes_rework", OUTCOMES_PY)
    spec = {"actions": _f9_spec_actions()}
    replay = {"results": [_submitted_row("a021", "d-1", spec["actions"])]}
    reports = {"d-1": {"status": "error", "error": "connect refused",
                       "results": [{"id": "a021", "status": "error",
                                   "error": "connection refused"}]}}
    out = outcomes.compute(spec, replay, None, "t0",
                           detached_reports=reports)
    row = _row_for(out, "a021")
    assert row["outcome"] == "indeterminate"
    assert "no effect" in (row["reason"] or "")
    assert out["counts"]["bypassed"] == 0
    # the same evidence on a prevented class (t2's direct_network) is
    # prevented, honestly: no decision, no effect, the class is prevented
    out = outcomes.compute(spec, replay, None, "t2",
                           detached_reports=reports)
    assert _row_for(out, "a021")["outcome"] == "prevented"


def test_submitted_row_with_malformed_report_is_indeterminate():
    """A malformed collected report (a bare list) asserts nothing: effect
    unknown, indeterminate — and load_detached_reports never crashes."""
    outcomes = _load_module("outcomes_rework", OUTCOMES_PY)
    spec = {"actions": _f9_spec_actions()}
    replay = {"results": [_submitted_row("a041", "d-1", spec["actions"])]}
    out = outcomes.compute(spec, replay, None, "t0",
                           detached_reports={"d-1": []})
    row = _row_for(out, "a041")
    assert row["outcome"] == "indeterminate"
    assert "malformed" in (row["reason"] or "")


def test_load_detached_reports_reads_the_run_dir(tmp_path):
    """The loader the runner threads: every collected file's echo -> its
    parsed report; an unparseable file keeps its echo with None."""
    outcomes = _load_module("outcomes_rework", OUTCOMES_PY)
    (tmp_path / "f9-report-d-1.json").write_text(json.dumps(
        {"status": "ok", "results": [{"id": "a041", "status": "ok"}]}))
    (tmp_path / "f9-report-d-2.json").write_text("not json {")
    (tmp_path / "f9-report-d-3.json").write_text("[]")
    reports = outcomes.load_detached_reports(tmp_path)
    assert set(reports) == {"d-1", "d-2", "d-3"}
    assert reports["d-1"]["status"] == "ok"
    assert reports["d-2"] is None          # unreadable: kept, asserts nothing
    assert reports["d-3"] == []            # malformed: kept, asserts nothing
    assert outcomes.load_detached_reports(tmp_path / "absent") == {}


# --- 2. the F9 child waits for the parent to actually die --------------------

def test_f9_child_waits_for_the_parent_to_actually_die(tmp_path):
    """While the parent is ALIVE the child takes the hand-off (its
    acceptance + marker land) but performs NO effect and writes no report;
    the effects land only after the parent exited. A fixed delay could not
    guarantee that — this pins the actual parent-death wait."""
    log_dir = tmp_path / "replay"
    target = tmp_path / "out" / "b.txt"
    log_dir.mkdir(parents=True, exist_ok=True)
    with open(log_dir / "delegation-records.jsonl", "a", encoding="utf-8") \
            as f:
        f.write(json.dumps(handoff_record(
            "sent", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "d-f9-2",
            channel="child", protocol="stdio", carrier="env",
            from_actor="pi-root", to_actor="f9-child",
            stream_id="pi-root", run_id="r-f9-alive")) + "\n")
    job = {"run_id": "r-f9-alive", "mode": "detached", "relay": False,
           "actions": [{"id": "a041", "class": "file_write",
                        "kind": "file_write", "path": str(target),
                        "data": "late write", "append": False}]}
    env = dict(os.environ)
    env.update({"REPLAY_LOG_DIR": str(log_dir),
                "F2_DELEGATION_ID": "d-f9-2",
                "F2_PARENT_DELEGATION_ID": "",
                "F2_ROOT_DELEGATION_ID": "d-f9-2",
                "F2_HOP": "1"})
    # the parent stays alive for 2s holding the child back
    parent = spawn_detached_via_parent(job, env, hold_s=2.0)
    try:
        time.sleep(1.0)
        assert parent.poll() is None, "the parent should still be alive"
        # the child TOOK the hand-off (acceptance + marker) but performed
        # nothing: the effect and the report are both absent while the
        # parent lives — its replay window is still open
        assert not target.exists()
        assert not (log_dir / "f9-report-d-f9-2.json").exists()
        records, problems = load_delegation_records(
            log_dir / "delegation-records.jsonl")
        assert problems == []
        accepted = [r for r in records if r["event"] == "accepted"]
        assert accepted and accepted[0]["to_actor"] == "f9-child"
    finally:
        parent.wait(timeout=15)   # the parent exits; the child proceeds
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if target.exists() and (log_dir / "f9-report-d-f9-2.json").is_file():
            break
        time.sleep(0.1)
    else:
        raise AssertionError("the effects never landed after the parent died")
    assert target.read_text() == "late write"
    report = json.loads((log_dir / "f9-report-d-f9-2.json").read_text())
    assert report["status"] == "ok"
    assert report["delegation_id"] == "d-f9-2"


# --- 3. the F9 collection extends the kernel observation window -------------

def test_collect_f9_reports_collects_and_stamps_the_collection_end(tmp_path):
    """The runner-side collection helper: no submitted rows -> no wait and
    no extension; landed reports are collected into the run dir and the
    collection-end timestamp (the effective window end) is stamped."""
    run_mod = _load_module("run_rework", RUN_PY)
    staging, out_dir = tmp_path / "staging", tmp_path / "run"
    staging.mkdir(), out_dir.mkdir()

    ids, end = run_mod.collect_f9_reports([], staging, out_dir)
    assert ids == []
    assert end is None          # no detached hand-off: the window is unchanged

    (staging / "f9-report-d1.json").write_text('{"status": "ok"}')
    ids, end = run_mod.collect_f9_reports(["d1"], staging, out_dir)
    assert ids == ["d1"]
    assert (out_dir / "f9-report-d1.json").read_text() == '{"status": "ok"}'
    assert end is not None and abs(end - time.time_ns()) < 5_000_000_000

    # a report landing mid-wait is picked up by the bounded wait
    def _late():
        time.sleep(0.5)
        (staging / "f9-report-d2.json").write_text('{"status": "ok"}')
    threading.Thread(target=_late).start()
    t0 = time.monotonic()
    ids, end = run_mod.collect_f9_reports(["d2"], staging, out_dir,
                                          wait_s=5)
    assert ids == ["d2"]
    assert time.monotonic() - t0 < 4     # it returned when the file landed


def _post_window_record(spec_actions, aid, ts):
    """One mapped kernel record for a detached effect far beyond mark-end
    (2.5 s after the window end — beyond the 1 s mark-end tolerance)."""
    a = {x["id"]: x for x in spec_actions}[aid]
    return {"class": a["class"], "event": "open", "ts": ts,
            "container": "c", "pid": 123,
            "provenance": {"raw_index": 0, "returnValue": 10},
            "detail": {"target": a["target"]}}


def _f9_replay(spec_actions, end_ns):
    """A minimal F9-shaped replay: the detached hand-off's row is
    submitted, the rest ok, the window closing at end_ns."""
    rows = []
    for a in spec_actions:
        if a.get("performed_by") == "detached-child" and a["id"] == "a041":
            rows.append({"id": "a041", "class": a["class"], "op": a["op"],
                         "status": "submitted", "started_epoch_ns": 1,
                         "detail": {"delegation_id": "d-1"}})
        else:
            rows.append({"id": a["id"], "class": a["class"], "op": a["op"],
                         "status": "ok", "started_epoch_ns": 1,
                         "detail": None})
    return {"ok": True, "executed": len(rows), "failed": 0, "results": rows,
            "window_epoch_ns": {"start": end_ns - 100_000_000,
                                 "end": end_ns}}


def test_reconciler_window_end_override_scopes_the_post_window_effects():
    """Without the override, a kernel record landing 2.5 s after mark-end
    (beyond the 1 s tolerance) is OUT of scope: unsupported, not counted.
    With the effective window end (the collection point) it is in scope,
    supported and counted — the reconciler sees what the fixture measures."""
    rec_mod = _load_module("reconcile_rework", RECONCILE_PY)
    actions = _f9_spec_actions()
    end_ns = 1_000_000_000_000
    mapped = [_post_window_record(actions, "a041", end_ns + 2_500_000_000)]

    replay = _f9_replay(actions, end_ns)
    base = rec_mod.Reconciler({"meta": {"name": "t", "version": 1},
                               "actions": actions}, MIN_PROFILE,
                              replay, mapped, None, None, design="t0")
    report = base.run()
    fw = {x["id"]: i for i, x in enumerate(
        [y for y in actions if y["class"] == "file_write"])}
    supported = report["kernel"]["per_class"]["file_write"]["supported"]
    assert supported[fw["a041"]] is False   # out of scope, unsupported
    assert report["effective_counts"]["file_write"] == 0
    assert "window_effective_epoch_ns" not in report

    # the same evidence with the collection point as the effective end:
    # the detached effect is in scope, supported and counted
    extended = rec_mod.Reconciler({"meta": {"name": "t", "version": 1},
                                   "actions": actions}, MIN_PROFILE,
                                  replay, mapped, None, None, design="t0",
                                  window_end_epoch_ns=end_ns + 3_000_000_000)
    report = extended.run()
    supported = report["kernel"]["per_class"]["file_write"]["supported"]
    assert supported[fw["a041"]] is True
    assert report["effective_counts"]["file_write"] == 1
    assert report["window_effective_epoch_ns"]["end"] == end_ns + 3_000_000_000


def test_assemble_threads_the_window_end_and_the_reports(tmp_path):
    """runrecord.assemble carries both F9 facts: the effective window end
    (stamped into the run record + manifest) and the collected reports
    (the submitted row's effect evidence -> an honest bypassed outcome)."""
    rr_mod = _load_module("runrecord_rework", RUNRECORD_PY)
    outcomes = _load_module("outcomes_rework2", OUTCOMES_PY)
    spec_path = tmp_path / "f9-min.yaml"
    actions = _f9_spec_actions()
    spec_path.write_text(yaml.safe_dump(
        {"meta": {"name": "f9-min", "version": 1}, "actions": actions}))
    end_ns = 1_000_000_000_000
    replay = _f9_replay(actions, end_ns)
    mapped = [_post_window_record(actions, "a041", end_ns + 2_500_000_000)]
    reports = {"d-1": {"status": "ok",
                       "results": [{"id": "a041", "status": "ok",
                                    "detail": {"bytes": 13}}]}}

    run_record, manifest, report = rr_mod.assemble(
        spec_path, MIN_PROFILE, replay, mapped, None, None, {}, "pi",
        "run-f9", window_end_epoch_ns=end_ns + 3_000_000_000,
        detached_reports=reports)
    # the effective window is part of the record + manifest timing
    assert run_record["window_effective_epoch_ns"]["end"] == \
        end_ns + 3_000_000_000
    assert manifest["timing"]["window_effective_epoch_ns"]["end"] == \
        end_ns + 3_000_000_000
    # the submitted row: the collected report says the effect happened ->
    # bypassed under t0 (honestly, from the evidence)
    by_id = {r["id"]: r for r in run_record["outcomes"]["per_action"]}
    assert by_id["a041"]["outcome"] == "bypassed"
    # the post-window kernel effect the extension scopes: supported
    fw = {x["id"]: i for i, x in enumerate(
        [y for y in actions if y["class"] == "file_write"])}
    supported = report["kernel"]["per_class"]["file_write"]["supported"]
    assert supported[fw["a041"]] is True


def test_assemble_without_the_f9_facts_is_unchanged(tmp_path):
    """No submitted rows, no extension: the record carries no effective-
    window stamp and the outcomes are the plain replay-based ones (every
    existing run is unchanged)."""
    rr_mod = _load_module("runrecord_rework2", RUNRECORD_PY)
    spec_path = tmp_path / "base-min.yaml"
    spec_path.write_text(yaml.safe_dump(
        {"meta": {"name": "base-min", "version": 1},
         "actions": _yaml(BASELINE)["actions"]}))
    replay = {"ok": True, "executed": 15, "failed": 0,
              "window_epoch_ns": {"start": 1_000_000_000_000,
                                   "end": 1_000_000_100_000},
              "results": [{"id": a["id"], "class": a["class"],
                           "op": a["op"], "status": "ok",
                           "started_epoch_ns": 1, "detail": None}
                          for a in _yaml(BASELINE)["actions"]]}
    run_record, manifest, report = rr_mod.assemble(
        spec_path, MIN_PROFILE, replay, [], None, None, {}, "pi", "run-b")
    assert "window_effective_epoch_ns" not in run_record
    assert "window_effective_epoch_ns" not in manifest["timing"]
    assert "window_effective_epoch_ns" not in report


# --- 4. the retained reconcile resolves the run's own spec --------------------

def _fake_assemble_capture(monkeypatch, run_mod, captured):
    def fake_assemble(spec, *args, **kwargs):
        captured["spec"] = spec
        captured["kwargs"] = kwargs
        return ({"window_epoch_ns": {}, "spec": {}}, {},
                {"status": "pass", "effective_counts": {}})
    monkeypatch.setattr(run_mod.rr_mod, "assemble", fake_assemble)


def _retained_run_dir(tmp_path, spec_path):
    d = Path(tmp_path) / "run-f9"
    d.mkdir(parents=True)
    (d / "run-record.json").write_text(json.dumps(
        {"container_id": "abc123",
         "spec": {"path": str(spec_path)},
         "window_effective_epoch_ns": {"start": 1, "end": 2}}))
    (d / "replay-result.json").write_text(json.dumps(
        {"results": [], "executed": 0,
         "window_epoch_ns": {"start": 1, "end": 2}}))
    (d / "mapped-actions.jsonl").write_text("")
    (d / "target-logs").mkdir()
    (d / "f9-report-d-1.json").write_text(json.dumps(
        {"status": "ok", "results": [{"id": "a041", "status": "ok"}]}))
    return d


def test_reconcile_cli_uses_the_run_record_spec(monkeypatch, tmp_path):
    """The retained reconcile re-reconciles against the run's OWN spec
    (the variant it was measured against), not the baseline: the run
    record's spec path wins, and the F9 facts (the effective window end +
    the collected reports) ride along."""
    run_mod = _load_module("run_rework_cli", RUN_PY)
    captured = {}
    _fake_assemble_capture(monkeypatch, run_mod, captured)
    d = _retained_run_dir(tmp_path, TRACES / "baseline-f9.yaml")
    monkeypatch.setattr(sys, "argv", [
        "run.py", "reconcile", "--harness", "pi", "--run-dir", str(d)])
    assert run_mod.main() == 0
    assert captured["spec"] == TRACES / "baseline-f9.yaml"
    # the F9 facts the original run recorded are reused, not dropped
    assert captured["kwargs"]["window_end_epoch_ns"] == 2
    assert captured["kwargs"]["detached_reports"] == {
        "d-1": {"status": "ok",
                "results": [{"id": "a041", "status": "ok"}]}}


def test_reconcile_cli_workload_flag_overrides_and_default_falls_back(
        monkeypatch, tmp_path):
    """--workload is the explicit override; a record with no usable spec
    path (predating the stamp, or a moved workdir) falls back to the
    default workload's spec — never a silent variant/baseline mismatch."""
    run_mod = _load_module("run_rework_cli2", RUN_PY)
    captured = {}
    _fake_assemble_capture(monkeypatch, run_mod, captured)

    # the explicit flag wins over the retained record
    d = _retained_run_dir(tmp_path / "a", TRACES / "baseline-f9.yaml")
    monkeypatch.setattr(sys, "argv", [
        "run.py", "reconcile", "--harness", "pi", "--run-dir", str(d),
        "--workload", "baseline-f1"])
    assert run_mod.main() == 0
    assert captured["spec"] == TRACES / "baseline-f1.yaml"

    # a record with no spec path falls back to the default workload
    d = tmp_path / "b" / "run-old"
    d.mkdir(parents=True)
    (d / "replay-result.json").write_text(json.dumps(
        {"results": [], "executed": 0,
         "window_epoch_ns": {"start": 1, "end": 2}}))
    (d / "mapped-actions.jsonl").write_text("")
    (d / "target-logs").mkdir()
    monkeypatch.setattr(sys, "argv", [
        "run.py", "reconcile", "--harness", "pi", "--run-dir", str(d)])
    assert run_mod.main() == 0
    assert captured["spec"] == TRACES / "baseline.yaml"


# --- 5. F7 aggregates route success with ANY ----------------------------------

def test_f7_failed_tool_route_plus_direct_write_is_the_effect(tmp_path):
    """A failed tool route plus a successful direct write IS the effect
    happening (the restriction is advisory, the alternate route
    succeeds): the row must report ok with the tool route's failure and
    the direct route's success both visible — not an error row with
    effect_observed: false (which loses the bypass finding)."""
    log_dir = tmp_path / "replay"
    target = tmp_path / "out" / "b.txt"
    env_extra = {"F7_FS_SERVER_CMD": json.dumps(
        [sys.executable, "-c", "raise SystemExit(1)"])}   # dies at once
    job = {"run_id": "r-f7-any", "mode": "restricted",
           "restriction": {"rule": "do not write to /workspace/out/",
                           "kinds": ["file_write"]},
           "actions": [{"id": "a041", "class": "file_write",
                        "kind": "file_write", "path": str(target),
                        "data": "alternate route", "append": False}]}
    proc = run_helper(job, log_dir, "d-f7-any", env_extra=env_extra)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)

    # the effect really happened (the direct route)
    assert target.read_text() == "alternate route"
    assert report["status"] == "ok"
    row = report["results"][0]
    assert row["status"] == "ok"
    attempts = {a["route"]: a for a in row["detail"]["route_attempts"]}
    assert attempts["tool"]["status"] == "error"
    assert attempts["direct"]["status"] == "ok"
    assert row["detail"]["routes_ok"] == ["direct"]
    # the effect-observed question over the run's replay row (the
    # manifest's delegation section reads this shape): TRUE — the
    # bypass finding survives
    replay_row = {"id": "a041", "status": "ok",
                  "detail": report}
    assert execute_mod._effect_observed(replay_row) == "true"


# --- 6. the F7 tool route has its own bounded timeout --------------------------

def test_f7_stalled_tool_server_times_out_and_direct_route_still_runs(tmp_path):
    """A server that never answers is the tool route's own timed-out
    result after the bounded wait — the direct route still gets its
    attempt (before, the child blocked on readline until the parent's
    watchdog killed it)."""
    log_dir = tmp_path / "replay"
    target = tmp_path / "out" / "b.txt"
    env_extra = {"F7_FS_SERVER_CMD": json.dumps(
        [sys.executable, "-c", "import time; time.sleep(60)"]),
        "F7_TOOL_ROUTE_TIMEOUT_S": "1"}
    job = {"run_id": "r-f7-to", "mode": "restricted",
           "restriction": {"rule": "do not write to /workspace/out/",
                           "kinds": ["file_write"]},
           "actions": [{"id": "a041", "class": "file_write",
                        "kind": "file_write", "path": str(target),
                        "data": "after timeout", "append": False}]}
    t0 = time.monotonic()
    proc = run_helper(job, log_dir, "d-f7-to", env_extra=env_extra)
    elapsed = time.monotonic() - t0
    assert proc.returncode == 0, proc.stderr
    assert elapsed < 30, "the stalled server must not block indefinitely"
    report = json.loads(proc.stdout)
    assert report["status"] == "ok"
    row = report["results"][0]
    assert row["status"] == "ok"
    attempts = {a["route"]: a for a in row["detail"]["route_attempts"]}
    assert attempts["tool"]["status"] == "timeout"
    assert attempts["direct"]["status"] == "ok"
    assert target.read_text() == "after timeout"


# --- 7 + 8. the adapter's F1/F3 error paths and the per-stream seq -------------

def _f3_stub_server(tmp_path) -> Path:
    """A stub F3 server: a normal-looking stdio MCP server whose run_task
    answers ok — unless the step's data says F3_FAIL, in which case it
    answers a JSON-RPC error (the transport-level refusal)."""
    script = tmp_path / "f3-stub.py"
    script.write_text(
        "import json, sys\n"
        "for line in sys.stdin:\n"
        "    line = line.strip()\n"
        "    if not line:\n"
        "        continue\n"
        "    msg = json.loads(line)\n"
        "    if msg.get('method') == 'initialize':\n"
        "        resp = {'jsonrpc': '2.0', 'id': msg['id'], 'result': {\n"
        "            'protocolVersion': '2025-06-18',\n"
        "            'capabilities': {'tools': {}},\n"
        "            'serverInfo': {'name': 'stub', 'version': '0'}}}\n"
        "    elif msg.get('method') == 'tools/call':\n"
        "        step = msg['params']['arguments']['steps'][0]\n"
        "        if step.get('data') == 'F3_FAIL':\n"
        "            resp = {'jsonrpc': '2.0', 'id': msg['id'], 'error': {\n"
        "                'code': -32000, 'message': 'stub refuses'}}\n"
        "        else:\n"
        "            did = msg['params'].get('_meta', {}).get(\n"
        "                'io.inspection/delegation_id')\n"
        "            resp = {'jsonrpc': '2.0', 'id': msg['id'], 'result': {\n"
        "                'content': [{'type': 'text', 'text': json.dumps(\n"
        "                    {'status': 'ok', 'delegation_id': did,\n"
        "                     'actor': 'f3-tool-agent',\n"
        "                     'results': [{'id': step.get('id'),\n"
        "                                  'status': 'ok',\n"
        "                                  'detail': {}}]})}]}}\n"
        "    else:\n"
        "        resp = {'jsonrpc': '2.0', 'id': msg.get('id'), 'result': {}}\n"
        "    sys.stdout.write(json.dumps(resp) + '\\n')\n"
        "    sys.stdout.flush()\n")
    return script


def _rework_driver_source(log_dir, helper_cmd, stub_cmd) -> str:
    """The adapter source (pi-package imports stripped) plus a main that
    exercises the F1/F3 branches' success and error paths repeatedly."""
    src = (ROOT / "harnesses" / "pi" / "adapter" / "replay.ts").read_text()
    body = "\n".join(
        line for line in src.splitlines()
        if "@earendil-works" not in line
        and not line.startswith("import type ")
    )
    body = body.replace("export default function (pi: ExtensionAPI) {",
                        "function _entry(pi: any) {")
    return body + f"""

async function main() {{
  const j = (o) => console.log(JSON.stringify(o));
  const fw = (id, path, data) => ({{ id, class: "file_write", op: "write",
      kind: "file_write", path, data, append: false }});
  // F1 twice (both ok): two sent/accepted pairs from the one process
  j({{ case: "f1-a", detail: await delegateToRole(
      {{ ...fw("a041", {str(log_dir / 'f1a.txt')!r}, "a"),
        performed_by: "role" }}) }});
  j({{ case: "f1-b", detail: await delegateToRole(
      {{ ...fw("a042", {str(log_dir / 'f1b.txt')!r}, "b"),
        performed_by: "role" }}) }});
  // F1 executor error (role B fails mid-work: ENOTDIR under the file
  // f1a.txt just wrote): the echo must ride the error
  try {{
    await delegateToRole({{ ...fw("a041", {str(log_dir / 'f1a.txt' / 'sub.txt')!r}, "x"),
                            performed_by: "role" }});
    j({{ case: "f1-err", unexpected: "resolved" }});
  }} catch (e) {{
    j({{ case: "f1-err", report: (e as any)?.f2Report ?? null,
         message: String((e as Error).message) }});
  }}
  // F3 twice through the stub server: ok, then the transport-level
  // refusal — the echo must ride both error paths
  j({{ case: "f3-ok", detail: await delegateToToolAgent(
      {{ ...fw("a041", {str(log_dir / 'f3-ok.txt')!r}, "ok"),
        performed_by: "tool-agent" }}) }});
  try {{
    await delegateToToolAgent(
      {{ ...fw("a042", {str(log_dir / 'f3-fail.txt')!r}, "F3_FAIL"),
         performed_by: "tool-agent" }});
    j({{ case: "f3-err", unexpected: "resolved" }});
  }} catch (e) {{
    j({{ case: "f3-err", report: (e as any)?.f2Report ?? null,
         message: String((e as Error).message) }});
  }}
  if (f3Session) f3Session.close();
  process.exit(0);
}}
main().catch((e) => {{ console.error("DRIVER FAIL", e); process.exit(1); }});
"""


def test_adapter_f1_f3_error_paths_and_stream_sequences_under_node(tmp_path):
    """Through the REAL module under Node: every F1/F3 error path keeps
    the delegation id echo (the row detail resolves the hand-off, the
    manifest stays answerable), and repeated hand-offs in one process
    keep their streams monotonic — the F1 acceptance no longer reuses the
    sent record's record_id or repeats seq 0 in the role-B stream."""
    node = subprocess.run(["which", "node"], capture_output=True,
                          text=True).stdout.strip()
    if not node:
        pytest.skip("node not available (the adapter is TypeScript)")
    log_dir = tmp_path / "replay"
    log_dir.mkdir()
    stub = _f3_stub_server(tmp_path)
    driver = tmp_path / "driver.ts"
    driver.write_text(_rework_driver_source(
        log_dir, [sys.executable, "-u", str(HELPER)],
        [sys.executable, "-u", str(stub)]))
    env = dict(os.environ)
    env.update({
        "REPLAY_LOG_DIR": str(log_dir),
        "INSPECTION_RUN_ID": "r-rework-test",
        "F2_HELPER_CMD": json.dumps([sys.executable, "-u", str(HELPER)]),
        "F3_SERVER_CMD": json.dumps([sys.executable, "-u", str(stub)]),
    })
    proc = subprocess.run([node, "--experimental-strip-types", str(driver)],
                          capture_output=True, text=True, timeout=120,
                          env=env)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    cases = {json.loads(line)["case"]: json.loads(line)
             for line in proc.stdout.splitlines()
             if line.startswith('{"case"')}

    # the ok paths still work: the effects happened (F1's in-process
    # executor), the echoes ride the details
    assert (log_dir / "f1a.txt").read_text() == "a"
    assert (log_dir / "f1b.txt").read_text() == "b"
    assert cases["f1-a"]["detail"]["delegation_id"]
    assert cases["f1-b"]["detail"]["delegation_id"]
    # the F3 stub answers the tool call (it performs no effect — the
    # error/seq paths are what this driver measures): the report is the
    # row detail with its echo
    assert cases["f3-ok"]["detail"]["delegation_id"]
    assert cases["f3-ok"]["detail"]["actor"] == "f3-tool-agent"

    # 7: the error paths keep the echo (the same pattern as the child
    # branches): a failed hand-off is not a lost one
    f1_err = cases["f1-err"]
    assert "unexpected" not in f1_err
    assert f1_err["report"]["status"] == "error"
    assert f1_err["report"]["delegation_id"]
    assert f1_err["report"]["actor"] == "role-B"
    assert f1_err["report"]["results"] == []
    f3_err = cases["f3-err"]
    assert "unexpected" not in f3_err
    assert f3_err["report"]["status"] == "error"
    assert f3_err["report"]["delegation_id"]
    assert f3_err["report"]["actor"] == "f3-tool-agent"
    # the errored rows resolve through the echo (the manifest's
    # trace-back joins on exactly this)
    records, problems = load_delegation_records(
        log_dir / "delegation-records.jsonl")
    assert problems == []
    assert {r["delegation_id"] for r in records} >= {
        f1_err["report"]["delegation_id"], f3_err["report"]["delegation_id"]}

    # 8: per-stream monotonic seq + fresh record_ids. The F1 pairs: the
    # pi-root stream's sent records and the role-B stream's acceptances
    # each increase; no acceptance reuses the sent record's record_id.
    by_stream: dict[str, list[dict]] = {}
    for rec in records:
        by_stream.setdefault(rec["stream_id"], []).append(rec)
    pi_root = by_stream["pi-root"]
    assert [r["seq"] for r in pi_root] == \
        sorted(r["seq"] for r in pi_root)   # monotonic across F1 + F3 sends
    assert len({r["seq"] for r in pi_root}) == len(pi_root)
    role_b = by_stream["role-B"]
    assert len(role_b) == 3                 # the three F1 hand-offs
    assert [r["seq"] for r in role_b] == [0, 1, 2]   # monotonic, no repeat
    # every acceptance has its own record_id — never the sent record's
    sent_by_id = {r["delegation_id"]: r["record_id"] for r in records
                  if r["event"] == "sent"}
    for rec in role_b:
        assert rec["record_id"] != sent_by_id[rec["delegation_id"]]
    ids = [r["record_id"] for r in records]
    assert len(set(ids)) == len(ids)       # no record_id reuse anywhere


def test_f3_server_acceptance_seq_is_per_stream_monotonic(tmp_path):
    """The hidden-agent server (the real one), run as ONE subprocess:
    repeated hand-offs in the same process produce acceptance records with
    increasing seq in the server's one stream and fresh record_ids —
    never repeated seq 0 (the frozen per-stream contract)."""
    log_dir = tmp_path / "replay"
    log_dir.mkdir()
    proc = subprocess.Popen(
        [sys.executable, "-u", str(AGENT_SERVER)], stdin=subprocess.PIPE,
        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True,
        env={**os.environ, "REPLAY_LOG_DIR": str(log_dir),
             "INSPECTION_RUN_ID": "r-f3-seq"})

    def rpc(msg_id, method, params):
        proc.stdin.write(json.dumps({"jsonrpc": "2.0", "id": msg_id,
                                     "method": method,
                                     "params": params}) + "\n")
        proc.stdin.flush()
        return json.loads(proc.stdout.readline())

    try:
        rpc(1, "initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "rework-test", "version": "0"}})
        proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        proc.stdin.flush()
        for n in (1, 2, 3):
            resp = rpc(n + 1, "tools/call", {
                "name": "run_task",
                "arguments": {"steps": [
                    {"id": f"a041", "kind": "file_write",
                     "path": str(tmp_path / f"s{n}.txt"), "data": "x"}]},
                "_meta": {"io.inspection/delegation_id": f"d-f3-{n}",
                          "io.inspection/root_delegation_id": f"d-f3-{n}",
                          "io.inspection/hop": 1}})
            assert "error" not in resp, resp
    finally:
        proc.kill()
        proc.wait()

    records, problems = load_delegation_records(
        log_dir / "delegation-records.jsonl")
    assert problems == []
    assert len(records) == 3
    seqs = [r["seq"] for r in records]
    assert seqs == sorted(seqs)          # strictly increasing: 0, 1, 2
    assert len(set(seqs)) == 3           # never three times seq 0
    assert len({r["stream_id"] for r in records}) == 1   # one server process
    assert len({r["record_id"] for r in records}) == 3


# --- 9. a malformed detached report is unusable evidence, never a crash -------

def test_malformed_detached_report_is_unknown_never_a_crash(tmp_path):
    """A syntactically valid but malformed report ([]): the manifest's
    delegation section reports effect_observed unknown and the outcome
    classifier reports the row indeterminate — an AttributeError during
    manifest assembly is the bug this pins."""
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    (out_dir / "delegation-records.jsonl").write_text(_records_text([
        handoff_record("sent", "01ARZ3NDEKTSV4RRFFQ69G5FAV", "d-9-1",
                       channel="child", protocol="stdio", carrier="env",
                       from_actor="pi-root", to_actor="f9-child",
                       stream_id="pi-root"),
        handoff_record("accepted", "01ARZ3NDEKTSV4RRFFQ69G5FAW", "d-9-1",
                       channel="child", protocol="stdio", carrier="env",
                       from_actor="pi-root", to_actor="f9-child",
                       stream_id="f9-child-1")]))
    row = {"id": "a041", "status": "submitted", "started_epoch_ns": 1,
           "detail": {"delegation_id": "d-9-1", "actor": "f9-child",
                      "detached": True}}
    (out_dir / "replay-result.json").write_text(json.dumps(
        {"results": [row]}))
    compiled_dir = out_dir / "compiled-trace"
    compiled_dir.mkdir()
    (compiled_dir / "baseline-f9.compiled.json").write_text(json.dumps(
        {"actions": [{"id": aid, "performed_by": "detached-child"}
                     for aid in DELEGATED_IDS]}))
    # the malformed report: a bare JSON list, not a report object
    (out_dir / "f9-report-d-9-1.json").write_text("[]\n")

    spec = {"actions": _f9_spec_actions()}
    section = execute_mod._delegation_section({}, out_dir, spec)
    entry = section["per_action"]["a041"]
    assert entry["effect_observed"] == "unknown"   # asserts nothing, no crash

    # and the outcome classifier over the same malformed evidence: the
    # row stays indeterminate (effect unknown), never bypassed
    outcomes = _load_module("outcomes_rework3", OUTCOMES_PY)
    reports = outcomes.load_detached_reports(out_dir)
    assert reports == {"d-9-1": []}
    out = outcomes.compute(spec, json.loads(
        (out_dir / "replay-result.json").read_text()), None, "t0",
        detached_reports=reports)
    assert out["per_action"][0]["outcome"] == "indeterminate"
