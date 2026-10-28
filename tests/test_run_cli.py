"""M7 runner-CLI unit tests (docker-free): rerun reproducibility verdict,
run-record collection, artifact-retention check, and the T0 report/table.

Live orchestration (run/rerun/reconcile against Docker) is validated on the
server; these tests cover the pure logic in runner/run.py.
"""

import json
import sys
from pathlib import Path

import pytest

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / "runner"))

import run as run_mod  # noqa: E402

COUNTS = {"stdio_tool_call": 3, "http_tool_call": 3, "direct_network": 2,
          "process_spawn": 2, "file_write": 2, "credential_access": 2}


def _write_run(runs_dir: Path, run_id: str, harness: str, counts: dict,
               status: str = "pass", artifacts: dict | None = None,
               design: str | None = None, coverage: str | None = None,
               outcomes: dict | None = None) -> Path:
    d = runs_dir / run_id
    d.mkdir(parents=True)
    manifest = {"run_id": run_id, "harness": harness,
                "artifacts": artifacts if artifacts is not None else {
                    name: {"sha256": "a" * 64, "bytes": 10}
                    for name in ("tracee-events", "mapped-actions",
                                 "replay-result", "replay-log")}}
    if design is not None:
        manifest["design"] = design
        for name in ("gateway-decisions", "gateway-policy"):
            manifest["artifacts"][name] = {"sha256": "b" * 64, "bytes": 10}
    (d / "manifest.json").write_text(json.dumps(manifest))
    rec = {
        "run_id": run_id, "harness": harness,
        "reconciliation": {"status": status},
        "effective_counts": counts,
        "ground_truth_counts": COUNTS,
        "spec": {"canonical_sha256": "7ef73010" * 8},
        "mapping": {"version": 5},
    }
    if outcomes is not None:
        rec["outcomes"] = outcomes
    if design is not None:
        rec["design"] = design
        if coverage:
            per = {c: {"coverage": 1.0 if c == "http_tool_call" else 0.0}
                   for c in COUNTS}
            rec["coverage"] = {"status": coverage, "coverage": per}
        else:
            rec["coverage"] = None
    (d / "run-record.json").write_text(json.dumps(rec))
    return d


def _write_repro(tmp_path: Path, label: str, harness: str, run_ids: list[str],
                 status: str = "pass", design: str | None = None) -> None:
    d = tmp_path / f"{harness}-{label}"
    d.mkdir(parents=True, exist_ok=True)
    verdict = {
        "schema": "inspection-reproducibility/1", "harness": harness,
        "runs": run_ids, "status": status,
        "identical_counts": status == "pass", "all_reconciled": status == "pass"}
    if design is not None:
        verdict["design"] = design
        verdict["coverage"] = {r: "pass" for r in run_ids}
        verdict["all_covered"] = status == "pass"
    (d / "reproducibility.json").write_text(json.dumps(verdict))


# --- reproducibility verdict -------------------------------------------------------


def test_verdict_pass_identical_counts():
    summaries = [{"run_id": "r1", "harness": "pi", "status": "pass",
                  "effective_counts": dict(COUNTS)},
                 {"run_id": "r2", "harness": "pi", "status": "pass",
                  "effective_counts": dict(COUNTS)}]
    v = run_mod.reproducibility_verdict(summaries)
    assert v["status"] == "pass"
    assert v["identical_counts"] and v["all_reconciled"]


def test_verdict_fails_on_differing_counts():
    diff = dict(COUNTS)
    diff["file_write"] = 1
    summaries = [{"run_id": "r1", "harness": "pi", "status": "pass",
                  "effective_counts": dict(COUNTS)},
                 {"run_id": "r2", "harness": "pi", "status": "pass",
                  "effective_counts": diff}]
    v = run_mod.reproducibility_verdict(summaries)
    assert v["status"] == "fail"
    assert v["identical_counts"] is False


def test_verdict_fails_when_a_run_fails_reconciliation():
    summaries = [{"run_id": "r1", "harness": "pi", "status": "pass",
                  "effective_counts": dict(COUNTS)},
                 {"run_id": "r2", "harness": "pi", "status": "fail",
                  "effective_counts": dict(COUNTS)}]
    v = run_mod.reproducibility_verdict(summaries)
    assert v["status"] == "fail"
    assert v["all_reconciled"] is False


def test_verdict_needs_two_runs():
    v = run_mod.reproducibility_verdict(
        [{"run_id": "r1", "harness": "pi", "status": "pass",
          "effective_counts": dict(COUNTS)}])
    assert v["status"] == "fail"


def test_rerun_requires_at_least_two_runs():
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        try:
            run_mod.run_rerun("pi", "x", 1, Path(tmp))
        except ValueError as exc:
            assert ">= 2" in str(exc)
        else:
            raise AssertionError("expected ValueError for --runs 1")


# --- run-record collection + report ------------------------------------------------


def test_collect_run_records(tmp_path):
    _write_run(tmp_path, "pi-r1", "pi", COUNTS)
    _write_run(tmp_path, "openclaw-r1", "openclaw", COUNTS)
    (tmp_path / "not-a-run").mkdir()          # no run-record.json -> ignored
    records = run_mod.collect_run_records(tmp_path)
    assert [r["run_id"] for r in records] == ["openclaw-r1", "pi-r1"]  # sorted


def test_build_report_counts_and_acceptance(tmp_path):
    _write_run(tmp_path, "pi-r1", "pi", COUNTS)
    _write_run(tmp_path, "pi-r2", "pi", COUNTS)
    _write_run(tmp_path, "openclaw-r1", "openclaw", COUNTS)
    _write_repro(tmp_path, "m7", "pi", ["pi-r1", "pi-r2"])
    report = run_mod.build_report(tmp_path)
    assert len(report["runs"]) == 3  # 2 pi + 1 openclaw
    assert report["spec_ground_truth_counts"] == COUNTS
    acc = report["acceptance"]
    assert acc["pi"]["t0_criteria_met"] is True
    # openclaw has a single run and no rerun-mode verdict: reproducibility
    # cannot be demonstrated
    assert acc["openclaw"]["t0_criteria_met"] is False
    assert acc["openclaw"]["rerun_verdicts"] == []


def test_build_report_excludes_warmup_runs(tmp_path):
    # warmup dirs fail reconciliation by construction (R4 leftovers; the
    # window is not clean), so they must not enter the acceptance gate:
    # all_reconciled_pass stays true over the measured runs only
    _write_run(tmp_path, "pi-r1", "pi", COUNTS,
               outcomes={"status": "pass", "counts": {"bypassed": sum(COUNTS.values())}})
    _write_run(tmp_path, "pi-r2", "pi", COUNTS,
               outcomes={"status": "pass", "counts": {"bypassed": sum(COUNTS.values())}})
    _write_run(tmp_path, "warmup-t0-pi", "pi", COUNTS, status="fail")
    _write_repro(tmp_path, "m7", "pi", ["pi-r1", "pi-r2"])
    report = run_mod.build_report(tmp_path)
    acc = report["acceptance"]["pi"]
    assert acc["runs_recorded"] == 2
    assert acc["all_reconciled_pass"] is True
    assert acc["identical_counts"] is True
    assert acc["outcome_counts"]["bypassed"] == 2 * sum(COUNTS.values())
    assert all(v["status"] == "pass" for v in acc["rerun_verdicts"])
    # and a warmup-only design contributes nothing
    empty = run_mod.build_report(tmp_path, design="t3")
    assert empty["acceptance"]["pi"]["runs_recorded"] == 0


def test_build_report_flags_missing_artifacts(tmp_path):
    _write_run(tmp_path, "pi-r1", "pi", COUNTS, artifacts={
        "tracee-events": {"sha256": "a" * 64, "bytes": 10},
        "mapped-actions": {"sha256": "a" * 64, "bytes": 10},
        "replay-result": {"sha256": None, "bytes": None},   # not retained
        "replay-log": {"sha256": "a" * 64, "bytes": 10},
    })
    _write_run(tmp_path, "pi-r2", "pi", COUNTS)
    _write_repro(tmp_path, "m7", "pi", ["pi-r1", "pi-r2"])
    report = run_mod.build_report(tmp_path)
    assert report["acceptance"]["pi"]["artifacts_complete"] is False
    assert report["acceptance"]["pi"]["t0_criteria_met"] is False


def test_build_report_flags_failed_reconciliation_without_verdict(tmp_path):
    # one pass + one failed run, and NO passing rerun-mode verdict: the
    # reproducibility criterion is not demonstrated
    _write_run(tmp_path, "pi-r1", "pi", COUNTS)
    _write_run(tmp_path, "pi-r2", "pi", COUNTS, status="fail")
    report = run_mod.build_report(tmp_path)
    assert report["acceptance"]["pi"]["all_reconciled_pass"] is False
    assert report["acceptance"]["pi"]["t0_criteria_met"] is False


def test_build_report_failed_run_does_not_undo_a_passing_verdict(tmp_path):
    # the live m7 incident: one capture-race failure outside the rerun pair;
    # the rerun-mode verdict (m7b) still demonstrates the criterion
    _write_run(tmp_path, "openclaw-m7-r1", "openclaw", COUNTS, status="fail")
    _write_run(tmp_path, "openclaw-m7b-r1", "openclaw", COUNTS)
    _write_run(tmp_path, "openclaw-m7b-r2", "openclaw", COUNTS)
    _write_repro(tmp_path, "m7b", "openclaw",
                 ["openclaw-m7b-r1", "openclaw-m7b-r2"])
    report = run_mod.build_report(tmp_path)
    acc = report["acceptance"]["openclaw"]
    assert acc["all_reconciled_pass"] is False   # visible, auditable
    assert acc["t0_criteria_met"] is True        # via the m7b verdict


def test_render_markdown_table(tmp_path):
    _write_run(tmp_path, "pi-r1", "pi", COUNTS)
    _write_run(tmp_path, "pi-r2", "pi", COUNTS)
    _write_run(tmp_path, "oc-r1", "openclaw", COUNTS)
    _write_repro(tmp_path, "m7", "pi", ["pi-r1", "pi-r2"])
    md = run_mod.render_markdown(run_mod.build_report(tmp_path))
    assert "| pi | pi-r1 | pass |" in md.replace("  ", " ") or "pi-r1" in md
    for cls in run_mod.SIX_CLASSES:
        assert cls in md
    assert "OpenCode was" in md  # deviation note (M5)


def test_counts_identical_edge():
    assert run_mod.counts_identical({}) is False
    assert run_mod.counts_identical({"a": dict(COUNTS)}) is True


# --- T1 design plumbing (T1-5) ---------------------------------------------------


def test_harness_cfg_prefixes_per_design():
    assert run_mod.harness_cfg("pi", "t0")["container"] == "t0-pi"
    assert run_mod.harness_cfg("pi", "t1")["container"] == "t1-pi"
    assert run_mod.harness_cfg("openclaw", "t1")["container"] == "t1-openclaw"
    assert run_mod.DESIGNS["t1"]["gateway"] is True
    assert run_mod.DESIGNS["t0"]["gateway"] is False
    try:
        run_mod.harness_cfg("pi", "t9")
    except ValueError as exc:
        assert "t9" in str(exc)
    else:
        raise AssertionError("expected ValueError for unknown design")


def test_verdict_requires_coverage_pass_for_t1():
    base = {"harness": "pi", "design": "t1", "effective_counts": dict(COUNTS),
            "status": "pass"}
    ok = run_mod.reproducibility_verdict(
        [{**base, "run_id": "r1", "coverage": "pass"},
         {**base, "run_id": "r2", "coverage": "pass"}])
    assert ok["status"] == "pass" and ok["all_covered"] is True
    bad = run_mod.reproducibility_verdict(
        [{**base, "run_id": "r1", "coverage": "pass"},
         {**base, "run_id": "r2", "coverage": "fail"}])
    assert bad["status"] == "fail" and bad["all_covered"] is False
    # t0 summaries without a coverage key are unaffected
    t0 = run_mod.reproducibility_verdict(
        [{"run_id": "r1", "harness": "pi", "status": "pass",
          "effective_counts": dict(COUNTS)},
         {"run_id": "r2", "harness": "pi", "status": "pass",
          "effective_counts": dict(COUNTS)}])
    assert t0["status"] == "pass"


def test_check_artifacts_t1_requires_gateway_record():
    base = {name: {"sha256": "a" * 64, "bytes": 10}
            for name in ("tracee-events", "mapped-actions",
                         "replay-result", "replay-log")}
    assert run_mod.check_artifacts({"artifacts": base}) == []
    # t1 manifest without the enforcement-point record: incomplete
    assert run_mod.check_artifacts({"design": "t1", "artifacts": base}) == \
        ["gateway-decisions", "gateway-policy"]
    full = dict(base, **{n: {"sha256": "b" * 64, "bytes": 10}
                         for n in ("gateway-decisions", "gateway-policy")})
    assert run_mod.check_artifacts({"design": "t1", "artifacts": full}) == []


def test_coverage_matches_design():
    match = run_mod._coverage_matches_design
    t1_full = {"coverage": {c: {"coverage": 1.0 if c == "http_tool_call" else 0.0}
                            for c in run_mod.SIX_CLASSES}}
    assert match(t1_full, ["http_tool_call"]) is True
    # a non-inspected class partially covered -> design assumption broken
    broken = {"coverage": dict(t1_full["coverage"],
                               **{"stdio_tool_call": {"coverage": 0.5}})}
    assert match(broken, ["http_tool_call"]) is False
    assert match({}, ["http_tool_call"]) is False


def test_build_report_t1(tmp_path):
    for i in (1, 2):
        _write_run(tmp_path, f"pi-t1-r{i}", "pi", COUNTS, design="t1",
                   coverage="pass")
    _write_run(tmp_path, "pi-m7-r1", "pi", COUNTS)  # t0 record, excluded
    _write_repro(tmp_path, "t1", "pi", ["pi-t1-r1", "pi-t1-r2"], design="t1")
    _write_repro(tmp_path, "m7", "pi", ["pi-m7-r1"])  # t0 verdict, excluded
    report = run_mod.build_report(tmp_path, design="t1")
    assert [r["run_id"] for r in report["runs"]] == ["pi-t1-r1", "pi-t1-r2"]
    assert report["inspected_classes"] == ["http_tool_call"]
    acc = report["acceptance"]["pi"]
    assert acc["all_covered_pass"] is True
    assert acc["coverage_matches_design"] is True
    assert [v["dir"] for v in acc["rerun_verdicts"]] == ["pi-t1"]
    # t0 report over the same runs dir: only the t0 record
    t0 = run_mod.build_report(tmp_path, design="t0")
    assert [r["run_id"] for r in t0["runs"]] == ["pi-m7-r1"]


def test_render_markdown_t1(tmp_path):
    _write_run(tmp_path, "pi-t1-r1", "pi", COUNTS, design="t1", coverage="pass")
    md = run_mod.render_markdown(run_mod.build_report(tmp_path, design="t1"))
    assert "T1 report" in md
    assert "http_tool_call" in md


def test_pull_gateway_log_copies_record_and_policy(tmp_path, monkeypatch):
    import subprocess

    def fake_exec(container, cmd, check=True):
        class P:
            returncode = 0
            stdout = ('{"timestamp": 1.0, "tool_name": "post_hook"}\n'
                      if "decisions" in cmd else
                      "apiVersion: governance.toolkit/v1\nname: t1-allow-all\n")
        return P()

    monkeypatch.setattr(run_mod, "docker_exec", fake_exec)
    d = run_mod.pull_gateway_log(tmp_path, "t1")
    assert (d / "decisions.jsonl").read_text().startswith('{"timestamp"')
    assert (d / "policy.yaml").read_text().startswith("apiVersion")


# --- Tracee flush-lag guard ---------------------------------------------------------


def test_in_window_mapped_counts_and_filters(tmp_path):
    base = 1_789_030_000_000_000_000
    window = {"start": base, "end": base + 1_000}
    mapped = tmp_path / "m.jsonl"
    recs = [
        {"ts": base + 100, "container": "c1", "class": "process_spawn"},   # in
        {"ts": base + 900, "container": "c1", "class": "file_write"},     # in
        {"ts": base + 5_000_000_000, "container": "c1", "class": "file_write"},  # outside
        {"ts": base + 200, "container": "other", "class": "file_write"},  # other container
        "not json",
    ]
    mapped.write_text("\n".join(
        json.dumps(r) if isinstance(r, dict) else r for r in recs) + "\n")
    assert run_mod.in_window_mapped(mapped, window, "c1") == 2
    assert run_mod.in_window_mapped(mapped, window, "other") == 1
    assert run_mod.in_window_mapped(mapped, window, None) == 3


def test_in_window_mapped_missing_file(tmp_path):
    assert run_mod.in_window_mapped(tmp_path / "nope.jsonl",
                                    {"start": 0, "end": 1}, "c") == 0
