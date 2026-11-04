"""Regression tests for the four measurement-correctness fixes from the
pre-paper review (both reviewers):

  1. the t7 kernel-attribution join (framework/reconcile.py): replay
     intervals instead of the window tolerance, remote-performer
     exclusion, ambiguity refusal, and the labeled window fallback;
  3. the executor record collection (runner/run.py
     collect_executor_artifacts): run-id filtering, idempotent merge,
     executor-collection.json;
  4. the F7 stdio calibration (runner/reconcile.py): the restricted
     actions' tool-route calls widen the expected stdio range by the
     count of restricted FILE WRITE actions, in every design branch.

(Fix 2 — the trace_back RFC3339/ts_epoch_ns bug — has its regressions in
tests/test_delegation.py, next to the module's other trace-back tests.)

Run from the repo root:  python3 -m pytest tests/test_measurement_fixes.py -v
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))

from framework import reconcile as cov  # noqa: E402
import reconcile as rec_mod  # noqa: E402  (runner/reconcile.py)
import run as run_mod  # noqa: E402      (runner/run.py)

MS = 1_000_000                      # 1 ms in ns
W0 = 1_790_000_000_000_000_000      # an epoch-ns window start


def _action(aid, cls, target, **kw):
    return {"id": aid, "class": cls, "target": target,
            "op": kw.pop("op", "exec"), **kw}


def _spec(*actions):
    return {"actions": list(actions)}


def _spawn_event(ts, comm="sh", seq="14", allowed=True):
    # the t7 kernel-control decision shape after load_decisions' mapping
    return {"tool_name": comm, "timestamp": ts, "action_class":
            "process_spawn", "target_value": "/bin/sh",
            "allowed": allowed, "seq": seq}


def _compute(spec, decisions, window=None, replay=None):
    window = window or (W0, W0 + 1_000 * MS)
    return cov.compute(spec, decisions, [], "t7", window,
                       window_tolerance_ns=1_000 * MS, replay=replay)


def _row(report, aid):
    return next(r for r in report["per_action"] if r["id"] == aid)


# --- fix 1: the t7 kernel-attribution join ------------------------------------

def test_remote_performed_action_never_attributed_to_a_local_event():
    """The F4/F5 root cause: a spec action marked performed_by:
    remote-tool-agent runs on the EXECUTOR host — the origin's kernel
    can never observe its effect, so no local event may be credited to
    it, even when a matching process/file/network event exists locally."""
    spec = _spec(_action("a031", "process_spawn", "/bin/sh",
                         performed_by="remote-tool-agent"))
    event = _spawn_event(W0 + 150 * MS)      # a local sh spawn, in-window
    report = _compute(spec, [event],
                      replay={"results": [
                          {"id": "a031", "status": "ok",
                           "started_epoch_ns": W0,
                           "ended_epoch_ns": W0 + 1_000 * MS}]})
    row = _row(report, "a031")
    assert row["evaluated"] is False
    assert row["decision_refs"] == []
    # the event is honestly unaccounted, never silently swallowed
    assert report["decisions"]["unaccounted"] == [
        {"tool_name": "sh", "ts": W0 + 150 * MS, "target": "/bin/sh"}]


def test_remote_agent_marking_is_excluded_too():
    spec = _spec(_action("a031", "process_spawn", "/bin/sh",
                         performed_by="remote-agent"))
    report = _compute(spec, [_spawn_event(W0 + 150 * MS)])
    assert _row(report, "a031")["evaluated"] is False


def test_local_action_with_event_inside_its_replay_interval_attributed():
    """The normal join stays intact: a NOT-remote action whose matching
    event lands inside the action's own replay interval is attributed."""
    spec = _spec(_action("a031", "process_spawn", "/bin/sh"))
    replay = {"results": [{"id": "a031", "status": "ok",
                           "started_epoch_ns": W0 + 100 * MS,
                           "ended_epoch_ns": W0 + 200 * MS}]}
    report = _compute(spec, [_spawn_event(W0 + 150 * MS)], replay=replay)
    row = _row(report, "a031")
    assert row["evaluated"] is True
    assert row["verdict"] == "allowed"
    assert row["decision_refs"] == ["14"]
    assert "note" not in row


def test_pre_window_plumbing_event_outside_every_interval_not_attributed():
    """The a031-style leak (observed live: the driver's cleanup shell
    660 ms BEFORE the window, swept in by the ±1 s tolerance) must not
    be attributed to an action whose replay interval is in-window."""
    spec = _spec(_action("a031", "process_spawn", "/bin/sh"))
    replay = {"results": [{"id": "a031", "status": "ok",
                           "started_epoch_ns": W0 + 100 * MS,
                           "ended_epoch_ns": W0 + 200 * MS}]}
    report = _compute(spec, [_spawn_event(W0 - 660 * MS)], replay=replay)
    row = _row(report, "a031")
    assert row["evaluated"] is False
    assert row["decision_refs"] == []
    # the plumbing event is reported, not silently dropped
    assert len(report["decisions"]["unaccounted"]) == 1


def test_interval_checks_apply_to_file_credential_and_network_joins():
    spec = _spec(
        _action("a041", "file_write", "/workspace/out/b.txt", op="write"),
        _action("a051", "credential_access", "file:///run/secrets/token",
                op="read"),
        _action("a021", "direct_network", "net-peer:9000",
                op="tcp_connect"),
    )
    replay = {"results": [
        {"id": "a041", "status": "ok",
         "started_epoch_ns": W0 + 100 * MS, "ended_epoch_ns": W0 + 200 * MS},
        {"id": "a051", "status": "ok",
         "started_epoch_ns": W0 + 100 * MS, "ended_epoch_ns": W0 + 200 * MS},
        {"id": "a021", "status": "ok",
         "started_epoch_ns": W0 + 100 * MS, "ended_epoch_ns": W0 + 200 * MS},
    ]}
    # matching events, but all BEFORE their action's replay interval
    events = [
        {"tool_name": "python3", "timestamp": W0 - 500 * MS,
         "action_class": "file_write", "target_value": "/workspace/out/b.txt",
         "allowed": True, "seq": "1"},
        {"tool_name": "node", "timestamp": W0 - 500 * MS,
         "action_class": "credential_access",
         "target_value": "/run/secrets/token", "allowed": True, "seq": "2"},
        {"tool_name": "node", "timestamp": W0 - 500 * MS,
         "action_class": "direct_network", "target_value": "172.28.0.10",
         "allowed": True, "seq": "3"},
    ]
    report = _compute(spec, events, replay=replay)
    for aid in ("a041", "a051", "a021"):
        assert _row(report, aid)["evaluated"] is False, aid


def test_row_without_interval_falls_back_to_window_with_note():
    """No replay row (or an interval-less row): the window tolerance
    stands in, and the join is labeled on the action's coverage row."""
    spec = _spec(_action("a031", "process_spawn", "/bin/sh"))
    report = _compute(spec, [_spawn_event(W0 + 150 * MS)], replay=None)
    row = _row(report, "a031")
    assert row["evaluated"] is True
    assert row["note"] == "window-tolerance-match"


def test_submitted_row_falls_back_to_window_with_note():
    """A detached hand-off's row cannot bound its effect (the effect
    happens after the replay ended): window fallback, labeled."""
    spec = _spec(_action("a021", "direct_network", "net-peer:9000",
                         op="tcp_connect", performed_by="detached-child"))
    replay = {"results": [{"id": "a021", "status": "submitted",
                           "started_epoch_ns": W0,
                           "ended_epoch_ns": W0 + 5 * MS}]}
    event = {"tool_name": "node", "timestamp": W0 + 300 * MS,
             "action_class": "direct_network", "target_value": "172.28.0.10",
             "allowed": True, "seq": "7"}
    report = _compute(spec, [event], replay=replay)
    row = _row(report, "a021")
    assert row["evaluated"] is True
    assert row["note"] == "window-tolerance-match"


def test_ambiguous_match_is_refused_never_first_candidate():
    """Two actions share a target and no interval can separate them: the
    answer is REFUSED (the trace_back discipline), never hits[0]."""
    spec = _spec(_action("a031", "process_spawn", "/bin/sh"),
                 _action("a031b", "process_spawn", "/bin/sh"))
    report = _compute(spec, [_spawn_event(W0 + 150 * MS)], replay=None)
    assert _row(report, "a031")["evaluated"] is False
    assert _row(report, "a031b")["evaluated"] is False
    assert report["decisions"]["ambiguous"] == [
        {"tool_name": "sh", "ts": W0 + 150 * MS, "target": "/bin/sh",
         "candidates": ["a031", "a031b"]}]


def test_replay_intervals_disambiguate_the_twins():
    """The same twin actions with per-action intervals: an event inside
    one action's span attributes to that action only."""
    spec = _spec(_action("a031", "process_spawn", "/bin/sh"),
                 _action("a031b", "process_spawn", "/bin/sh"))
    replay = {"results": [
        {"id": "a031", "status": "ok", "started_epoch_ns": W0 + 100 * MS,
         "ended_epoch_ns": W0 + 200 * MS},
        {"id": "a031b", "status": "ok", "started_epoch_ns": W0 + 500 * MS,
         "ended_epoch_ns": W0 + 600 * MS},
    ]}
    report = _compute(spec, [_spawn_event(W0 + 150 * MS)], replay=replay)
    assert _row(report, "a031")["evaluated"] is True
    assert _row(report, "a031b")["evaluated"] is False
    assert report["decisions"]["ambiguous"] == []


# --- fix 3: the executor record collection ------------------------------------

def _drec(record_id, run_id, event="accepted", delegation_id=None):
    return {"schema": 1, "record_id": record_id, "run_id": run_id,
            "stream_id": "executor", "seq": 1, "event": event,
            "delegation_id": delegation_id or ("d-" + record_id)}


def _write_jsonl(path, records):
    path.write_text("".join(json.dumps(r) + "\n" for r in records),
                    encoding="utf-8")


def _read_jsonl(path):
    return [json.loads(line) for line in
            path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_collect_executor_artifacts_filters_by_run_id_and_is_idempotent(
        tmp_path):
    """The mixed-run-id regression: the executor staging file persists
    across runs, so only THIS run's records may merge; a second call
    must merge nothing (the previously-appended records are skipped as
    already present)."""
    out_dir = tmp_path / "runs" / "runB"
    out_dir.mkdir(parents=True)
    executor_dir = tmp_path / "executor"
    executor_dir.mkdir()
    # the origin side already wrote run B's two sent records
    _write_jsonl(out_dir / "delegation-records.jsonl",
                 [_drec("B-sent-1", "runB", event="sent"),
                  _drec("B-sent-2", "runB", event="sent")])
    # the far staging file holds BOTH runs' acceptances (it persists)
    _write_jsonl(executor_dir / "delegation-records.jsonl",
                 [_drec("A-acc-1", "runA"),
                  _drec("A-acc-2", "runA"),
                  _drec("B-acc-1", "runB"),
                  _drec("B-acc-2", "runB")])

    summary = run_mod.collect_executor_artifacts(
        out_dir, executor_dir, map_events_here=False, run_id="runB")
    assert summary["records_merged"] == 2
    assert summary["records_skipped_other_run"] == 2
    merged = _read_jsonl(out_dir / "delegation-records.jsonl")
    assert [r["record_id"] for r in merged] == \
        ["B-sent-1", "B-sent-2", "B-acc-1", "B-acc-2"]
    collection = json.loads(
        (out_dir / "executor-collection.json").read_text())
    assert collection["run_id"] == "runB"
    assert collection["records_merged"] == 2

    # the second call (a manual collect-remote re-pull) is a no-op merge
    before = (out_dir / "delegation-records.jsonl").read_text()
    summary2 = run_mod.collect_executor_artifacts(
        out_dir, executor_dir, map_events_here=False, run_id="runB")
    assert summary2["records_merged"] == 0
    assert summary2["records_already_present"] == 2
    assert summary2["records_skipped_other_run"] == 2
    assert (out_dir / "delegation-records.jsonl").read_text() == before


def test_collect_executor_artifacts_missing_dir_raises(tmp_path):
    out_dir = tmp_path / "runs" / "runB"
    out_dir.mkdir(parents=True)
    import pytest
    with pytest.raises(RuntimeError, match="does not exist"):
        run_mod.collect_executor_artifacts(out_dir, tmp_path / "nowhere",
                                           run_id="runB")


# --- fix 4: the F7 stdio calibration --------------------------------------------

F7_SPEC = {"actions": [
    {"id": "a001", "class": "stdio_tool_call", "target": "mcp://fs@local",
     "op": "write_file", "args": {"path": "/workspace/out/a.txt"}},
    {"id": "a002", "class": "stdio_tool_call", "target": "mcp://fs@local",
     "op": "read_file", "args": {"path": "/workspace/out/a.txt"}},
    {"id": "a003", "class": "stdio_tool_call", "target": "mcp://fs@local",
     "op": "list_directory", "args": {"path": "/workspace/out"}},
    # the F7 restricted actions: file_write class (NOT stdio), the two
    # whose named route is the fs server's write_file tool
    {"id": "a041", "class": "file_write", "target": "/workspace/out/b.txt",
     "op": "write", "performed_by": "restricted-child"},
    {"id": "a042", "class": "file_write", "target": "/workspace/out/c.log",
     "op": "append", "performed_by": "restricted-child"},
    # restricted hand-offs with NO named tool: no extra stdio traffic
    {"id": "a031", "class": "process_spawn", "target": "/bin/sh",
     "op": "exec", "performed_by": "restricted-child"},
]}

PLAIN_SPEC = {"actions": [a for a in F7_SPEC["actions"]
                          if "performed_by" not in a]}


def _reconciler(spec, design="t0"):
    profile = {"multiplicity": {"stdio_handshake_extra_writes": 1},
               "window_tolerance_ns": 0}
    replay = {"window_epoch_ns": {"start": W0, "end": W0 + 1_000 * MS}}
    return rec_mod.Reconciler(spec, profile, replay, [], design=design)


def _stdio_recs(n):
    return [{"class": "stdio_tool_call", "event": "write", "ts": W0,
             "detail": {"fd": 1}} for _ in range(n)]


def test_f7_restricted_file_writes_widen_stdio_by_exactly_two():
    """3 stdio actions + 1 handshake + the 2 restricted file writes'
    tool-route calls = 6 expected writes. The old code counted
    restricted actions inside the STIO class (always zero) and required
    exactly 4 — every F7 matrix row failed R3-stdio on this."""
    r = _reconciler(F7_SPEC, design="t0")
    ok = r.kernel_group("stdio_tool_call", _stdio_recs(6))
    assert ok["problems"] == []
    too_many = r.kernel_group("stdio_tool_call", _stdio_recs(7))
    assert too_many["problems"]
    too_few = r.kernel_group("stdio_tool_call", _stdio_recs(3))
    assert too_few["problems"]


def test_restricted_handoffs_without_a_tool_route_add_no_stdio_traffic():
    """The restricted process_spawn names no tool (the child performs it
    the plain way): only the 2 restricted FILE WRITE actions widen the
    range — a spec with just the restricted spawn stays at 3+1."""
    spec = {"actions": F7_SPEC["actions"][:3] + [F7_SPEC["actions"][5]]}
    r = _reconciler(spec, design="t0")
    ok = r.kernel_group("stdio_tool_call", _stdio_recs(4))
    assert ok["problems"] == []
    assert r.kernel_group("stdio_tool_call", _stdio_recs(5))["problems"]


def test_t4_t5_t6_branch_applies_the_f7_widening():
    """The T4/T5/T6 branch used to bypass the F7 adjustment entirely: the
    upper bound must widen by the restricted tool-route calls there too."""
    r = _reconciler(F7_SPEC, design="t4")
    # 3 tool responses + 2 config-handshake slack + 2 tool-route calls
    ok = r.kernel_group("stdio_tool_call", _stdio_recs(7))
    assert ok["problems"] == []
    assert r.kernel_group("stdio_tool_call", _stdio_recs(8))["problems"]
    for design in ("t5", "t6"):
        r = _reconciler(F7_SPEC, design=design)
        assert r.kernel_group(
            "stdio_tool_call", _stdio_recs(7))["problems"] == []


def test_t7_branch_applies_the_f7_widening():
    """T7's stdio model widens by the same 2 tool-route calls (the old
    branch never accounted for the F7 child's fs-server traffic)."""
    r = _reconciler(F7_SPEC, design="t7")
    # 3 responses + 3 bridge/handshake extras + 2 tool-route calls
    assert r.kernel_group("stdio_tool_call", _stdio_recs(8))["problems"] == []
    assert r.kernel_group("stdio_tool_call", _stdio_recs(9))["problems"]
    assert r.kernel_group("stdio_tool_call", _stdio_recs(3))["problems"] == []


def test_plain_spec_stdio_model_is_unchanged():
    """No restricted actions: the exact 3+1 contract (a plain run's
    regression guard for the same edit)."""
    r = _reconciler(PLAIN_SPEC, design="t0")
    assert r.kernel_group("stdio_tool_call", _stdio_recs(4))["problems"] == []
    assert r.kernel_group("stdio_tool_call", _stdio_recs(5))["problems"]
