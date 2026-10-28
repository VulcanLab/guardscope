"""Instance-level outcome classifier tests (runner/outcomes.py).

The RQ1 artifact: every canonical action instance classified as
checked-allowed / checked-denied / bypassed / prevented / indeterminate from
the retained per-run evidence (replay statuses + the enforcement-point
coverage rows), per the paper's §5 definitions.

Run from experiments/mediation/:  python3 -m pytest tests/test_outcomes.py -v
"""

import importlib.util
import sys
from pathlib import Path

INSPECTION_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(INSPECTION_ROOT / "runner"))

import reconcile as rec_mod  # noqa: E402

OUTCOMES_PATH = INSPECTION_ROOT / "runner" / "outcomes.py"
SPEC_PATH = INSPECTION_ROOT / "trace" / "traces" / "baseline.yaml"

SPEC = rec_mod.load_spec(SPEC_PATH)
BY_ID = {a["id"]: a for a in SPEC["actions"]}


def _load_module():
    spec = importlib.util.spec_from_file_location("outcomes", OUTCOMES_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


oc = _load_module()


def replay_result(status_by_id: dict[str, str] | None = None):
    results = []
    for a in SPEC["actions"]:
        status = (status_by_id or {}).get(a["id"], "ok")
        results.append({"id": a["id"], "class": a["class"], "op": a["op"],
                        "status": status, "detail": None,
                        "error": "connect ECONNREFUSED" if status == "error" else None})
    return {"ok": all(r["status"] == "ok" for r in results),
            "executed": len(results),
            "failed": sum(1 for r in results if r["status"] == "error"),
            "results": results}


def cov_row(aid: str, evaluated: bool, verdict: str | None = None,
            decisions: int = 1) -> dict:
    return {"id": aid, "class": BY_ID[aid]["class"], "evaluated": evaluated,
            "verdict": verdict, "decisions": decisions if evaluated else 0,
            "decision_refs": ["d1"] if evaluated else []}


def coverage(rows_by_id: dict[str, dict], design: str = "t1") -> dict:
    return {"design": design, "per_action": list(rows_by_id.values()),
            "status": "pass"}


def by_outcome(report):
    return {r["id"]: r["outcome"] for r in report["per_action"]}


# --- T1: gateway inspects http only ------------------------------------------


def test_t1_outcomes():
    rows = {aid: cov_row(aid, aid in ("a011", "a012", "a013", "a014"),
                         "allowed") for aid in BY_ID}
    report = oc.compute(SPEC, replay_result(), coverage(rows), "t1")
    got = by_outcome(report)
    # inspected + allowed + effect -> checked-allowed
    for aid in ("a011", "a012", "a013", "a014"):
        assert got[aid] == "checked-allowed", aid
    # escapes that took effect -> bypassed
    for aid in ("a001", "a002", "a003", "a021", "a022", "a031", "a032",
                "a041", "a042", "a051", "a052"):
        assert got[aid] == "bypassed", aid
    assert report["counts"] == {"checked-allowed": 4, "checked-denied": 0,
                                "bypassed": 11, "prevented": 0,
                                "indeterminate": 0}
    assert report["status"] == "pass" and report["checked_total"] == 4


def test_t2_prevented_network():
    rows = {aid: cov_row(aid, aid in ("a011", "a012", "a013", "a014"),
                         "allowed") for aid in BY_ID}
    replay = replay_result({"a021": "error", "a022": "ok"})  # a022 sends ok locally
    report = oc.compute(SPEC, replay, coverage(rows), "t2")
    got = by_outcome(report)
    assert got["a021"] == "prevented"
    assert got["a022"] == "bypassed"   # sent 'ok', unconnected dgram: no icmp surface
    assert got["a011"] == "checked-allowed"
    assert report["counts"]["prevented"] == 1
    assert report["status"] == "pass"


def test_t6_checked_deny():
    tool_ids = {a["id"] for a in SPEC["actions"]
                if a["class"] in ("stdio_tool_call", "http_tool_call")}
    rows = {aid: cov_row(aid, aid in tool_ids, "allowed") for aid in BY_ID}
    rows["a014"] = cov_row("a014", True, "denied")
    replay = replay_result({"a014": "denied"})
    report = oc.compute(SPEC, replay, coverage(rows), "t6")
    got = by_outcome(report)
    assert got["a014"] == "checked-denied"
    assert got["a011"] == "checked-allowed"
    assert got["a041"] == "bypassed"
    assert report["counts"] == {"checked-allowed": 6, "checked-denied": 1,
                                "bypassed": 8, "prevented": 0,
                                "indeterminate": 0}
    assert report["status"] == "pass" and report["checked_total"] == 7


# --- failure paths -------------------------------------------------------------


def test_denied_but_took_effect_is_indeterminate():
    rows = {aid: cov_row(aid, True, "denied") for aid in BY_ID}
    replay = replay_result({aid: "denied" for aid in BY_ID})
    replay["results"][list(BY_ID).index("a011")]["status"] = "ok"  # effect!
    report = oc.compute(SPEC, replay, coverage(rows), "t6")
    got = by_outcome(report)
    assert got["a011"] == "indeterminate"
    assert report["status"] == "fail"
    reason = next(r["reason"] for r in report["per_action"] if r["id"] == "a011")
    assert "did not hold" in reason


def test_denied_without_decision_backing_is_indeterminate():
    """The replay reports a denial but the enforcement record has no decision
    for the instance — a spurious denial, not a checked-deny."""
    rows = {aid: cov_row(aid, aid != "a014",
                         "allowed") for aid in BY_ID}
    replay = replay_result({"a014": "denied"})
    report = oc.compute(SPEC, replay, coverage(rows), "t6")
    got = by_outcome(report)
    assert got["a014"] == "indeterminate"
    assert report["status"] == "fail"


def test_allowed_but_no_effect_is_indeterminate():
    rows = {aid: cov_row(aid, True, "allowed") for aid in BY_ID}
    replay = replay_result({"a011": "error"})
    report = oc.compute(SPEC, replay, coverage(rows), "t1")
    got = by_outcome(report)
    assert got["a011"] == "indeterminate"
    assert report["status"] == "fail"


def test_no_decision_and_no_effect_outside_prevented_class_fails():
    rows = {aid: cov_row(aid, False) for aid in BY_ID}
    replay = replay_result({"a011": "error"})
    report = oc.compute(SPEC, replay, coverage(rows), "t1")
    got = by_outcome(report)
    assert got["a011"] == "indeterminate"
    assert report["status"] == "fail"


def test_t0_all_bypassed():
    report = oc.compute(SPEC, replay_result(), None, "t0")
    got = by_outcome(report)
    assert all(v == "bypassed" for v in got.values())
    assert report["counts"]["bypassed"] == 15
    assert report["status"] == "pass"
