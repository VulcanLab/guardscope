"""T1-4 acceptance: enforcement-point sensor + coverage computation
(runner/coverage.py) — docker-free unit tests over synthetic AuditEntry
streams shaped like the gateway's decisions.jsonl (spec §12 fields +
parameters; the timestamp shape pinned in tests/test_gateway.py).

Covers: 1:1 tool->action attribution, per-class inspection coverage (T1:
http_tool_call 3/3 = 1.0, all escapes 0.0), window scoping against the
persistent gateway-logs volume, and the C1-C4 failure paths.

Run from experiments/mediation/:  python3 -m pytest tests/test_coverage.py -v
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

INSPECTION_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(INSPECTION_ROOT / "runner"))

import reconcile as rec_mod  # noqa: E402

COVERAGE_PATH = INSPECTION_ROOT / "runner" / "coverage.py"
RUNRECORD_PATH = INSPECTION_ROOT / "runner" / "runrecord.py"
SPEC_PATH = INSPECTION_ROOT / "trace" / "traces" / "baseline.yaml"

SPEC = rec_mod.load_spec(SPEC_PATH)

WIN_START = 1_789_030_000_000_000_000  # epoch ns; decisions use epoch seconds
WIN_END = WIN_START + 5_000_000_000

# runrecord tests' fixture stream (correct-run) for the t1 integration test
sys.path.insert(0, str(INSPECTION_ROOT / "tests"))
from test_runrecord import VERSIONS_ENV, write_artifacts  # noqa: E402


def _load_module():
    spec = importlib.util.spec_from_file_location("coverage", COVERAGE_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


cov = _load_module()

GATEWAY_VERSIONS_ENV = VERSIONS_ENV + """\
GATEWAY_PACKAGE=agent-os-kernel
GATEWAY_PACKAGE_VERSION=3.7.0
GATEWAY_POLICY_VERSION=1
"""


def entry(ts_s: float, tool: str = "post_hook", allowed: bool = True,
          params: dict | None = None) -> dict:
    return {"timestamp": ts_s, "agent_id": "t1-replay", "tool_name": tool,
            "allowed": allowed, "reason": "in allowed_tools",
            "approval_status": None, "parameters": params or {}}


def t1_decisions() -> list[dict]:
    """The 4 in-window decisions a T1 replay of baseline.yaml v2 produces
    (a011-a014; a014 shares the post_hook route, distinguished by body),
    epoch-second timestamps inside the replay window."""
    base = WIN_START / 1e9
    return [
        entry(base + 0.5, "post_hook", params={"body": "tool-call payload"}),
        entry(base + 1.5, "get_health"),
        entry(base + 2.5, "put_state", params={"body": "k=v"}),
        entry(base + 3.5, "post_hook", params={"body": "policy-deny probe"}),
    ]


def compute(decisions, problems=None, design="t1", window=(WIN_START, WIN_END)):
    return cov.compute(SPEC, decisions, problems or [], design, window)


# --- the T1 coverage matrix ---------------------------------------------------

def test_t1_full_coverage_pass():
    report = compute(t1_decisions())
    assert report["status"] == "pass"
    assert [c["id"] for c in report["checks"] if c["status"] == "fail"] == []
    # http_tool_call fully evaluated at the enforcement point ...
    http = report["coverage"]["http_tool_call"]
    assert http == {"ground_truth": 4, "covered": 4, "coverage": 1.0,
                    "inspected": True}
    # ... and none of the escape classes cross it (the T1 escapes)
    gt_all = {"stdio_tool_call": 3, "direct_network": 2, "process_spawn": 2,
              "file_write": 2, "credential_access": 2}
    for cls, gt in gt_all.items():
        assert report["coverage"][cls] == {"ground_truth": gt, "covered": 0,
                                           "coverage": 0.0, "inspected": False}


def test_per_action_rows_match_canonical_actions():
    report = compute(t1_decisions())
    by_id = {r["id"]: r for r in report["per_action"]}
    assert by_id["a011"]["tool"] == "post_hook"
    assert by_id["a011"]["crosses_enforcement_point"] is True
    assert by_id["a011"]["evaluated"] is True
    assert by_id["a011"]["decisions"] == 1
    assert by_id["a011"]["allowed"] is True
    assert by_id["a011"]["verdict"] == "allowed"
    assert by_id["a011"]["params_match"] is True
    # a014 shares the post_hook route; argument-level attribution separates it
    assert by_id["a014"]["evaluated"] is True
    assert by_id["a014"]["decision_refs"] != by_id["a011"]["decision_refs"]
    assert by_id["a001"]["crosses_enforcement_point"] is False
    assert by_id["a001"]["evaluated"] is False
    assert len(report["per_action"]) == 15


def test_denied_decision_still_covers():
    """Coverage counts CROSSING: an evaluated-and-denied action is covered
    (a denial is policy content, recorded per action, not a coverage loss).
    The denial is attributed by argument values: the decision carrying the
    a014 body denies a014, not a011."""
    decisions = [entry(WIN_START / 1e9 + 0.5, "post_hook",
                       params={"body": "tool-call payload"}),
                 entry(WIN_START / 1e9 + 1.5, "get_health"),
                 entry(WIN_START / 1e9 + 2.5, "put_state"),
                 entry(WIN_START / 1e9 + 3.5, "post_hook", allowed=False,
                       params={"body": "policy-deny probe"})]
    report = compute(decisions)
    assert report["status"] == "pass"
    assert report["coverage"]["http_tool_call"]["coverage"] == 1.0
    by_id = {r["id"]: r for r in report["per_action"]}
    assert by_id["a011"]["verdict"] == "allowed"
    assert by_id["a014"]["verdict"] == "denied"
    assert by_id["a014"]["allowed"] is False


# --- failure paths ------------------------------------------------------------

def test_missing_decision_fails_c3():
    decisions = [d for d in t1_decisions()
                 if d["tool_name"] != "get_health"]  # a012 not evaluated
    report = compute(decisions)
    assert report["status"] == "fail"
    c3 = next(c for c in report["checks"] if c["id"] == "C3-evaluated")
    assert c3["status"] == "fail" and "a012" in c3["detail"]
    assert report["coverage"]["http_tool_call"]["coverage"] == 3 / 4


def test_unknown_tool_fails_c2():
    report = compute(t1_decisions() + [entry(WIN_START / 1e9 + 3.5, "nope")])
    assert report["status"] == "fail"
    c2 = next(c for c in report["checks"] if c["id"] == "C2-accounted")
    assert c2["status"] == "fail"
    assert report["decisions"]["unaccounted"][0]["tool_name"] == "nope"


def test_decision_on_non_inspected_action_fails_c4():
    """A decision that maps onto a NON-inspected class breaks the topology
    assumption: design t0 inspects nothing, so any decision is a crossing
    outside the inspected set."""
    report = compute(t1_decisions(), design="t0")
    assert report["status"] == "fail"
    c4 = next(c for c in report["checks"] if c["id"] == "C4-inspected-only")
    assert c4["status"] == "fail"
    assert report["decisions"]["unaccounted"][0]["action"] == "a011"


def test_http_action_in_new_inspected_set_without_decision_fails_c3():
    """A spec action reclassified into the inspected set (here: a001 moved
    onto the http route set) must be evaluated too, else C3 fires."""
    spec = json.loads(json.dumps(rec_mod.load_spec(SPEC_PATH)))
    spec["actions"][0]["class"] = "http_tool_call"  # a001 stdio -> http
    report = cov.compute(spec, t1_decisions(), [], "t1", (WIN_START, WIN_END))
    assert report["status"] == "fail"
    c3 = next(c for c in report["checks"] if c["id"] == "C3-evaluated")
    assert c3["status"] == "fail" and "a001" in c3["detail"]


def test_parse_problems_fail_c1(tmp_path):
    p = tmp_path / "decisions.jsonl"
    p.write_text('{"timestamp": 1.0}\nnot json\n')
    decisions, problems = cov.load_decisions(p)
    report = compute(decisions, problems)
    assert report["status"] == "fail"
    c1 = next(c for c in report["checks"] if c["id"] == "C1-parse")
    assert c1["status"] == "fail" and len(report["decisions"]["parse_problems"]) == 2


def test_load_decisions_counts_lines(tmp_path):
    p = tmp_path / "decisions.jsonl"
    p.write_text("\n".join(json.dumps(e) for e in t1_decisions()) + "\n")
    decisions, problems = cov.load_decisions(p)
    assert problems == [] and len(decisions) == 4


# --- window scoping (persistent gateway-logs volume) ---------------------------

def test_out_of_window_decisions_excluded():
    """The gateway-logs volume persists across runs; decisions from an
    earlier run are outside this run's window and must not count."""
    stale = entry(WIN_START / 1e9 - 3600)  # an hour before the window
    report = compute(t1_decisions() + [stale, stale])
    assert report["status"] == "pass"
    assert report["decisions"] == {"total": 6, "in_window": 4,
                                   "out_of_window": 2, "unaccounted": [],
                                   "parse_problems": []}
    # duplicates inside the window are reported per action, still covered once
    report = compute(t1_decisions() + [t1_decisions()[0]])
    assert report["status"] == "pass"
    assert next(r for r in report["per_action"]
                if r["id"] == "a011")["decisions"] == 2


def test_no_window_counts_everything():
    report = compute(t1_decisions(), window=None)
    assert report["status"] == "pass"
    assert report["decisions"]["in_window"] == 4
    assert report["window_epoch_ns"] is None


def test_iso_and_ns_timestamps_accepted():
    from datetime import datetime, timezone
    iso = datetime.fromtimestamp(WIN_START / 1e9, tz=timezone.utc)\
        .isoformat()
    decisions = [entry(WIN_START / 1e9 + 0.5, "post_hook"),
                 {**entry(0), "timestamp": WIN_START + 1_500_000_000,
                  "tool_name": "get_health"},
                 {**entry(0), "timestamp": WIN_START + 2_500_000_000,
                  "tool_name": "put_state"},
                 {**entry(0), "timestamp": iso, "tool_name": "post_hook",
                  "parameters": {"body": "policy-deny probe"}}]
    report = compute(decisions)
    assert report["status"] == "pass"


# --- CLI -----------------------------------------------------------------------

def test_cli_end_to_end(tmp_path):
    dec = tmp_path / "decisions.jsonl"
    dec.write_text("\n".join(json.dumps(e) for e in t1_decisions()) + "\n")
    out = tmp_path / "coverage.json"
    proc = subprocess.run(
        [sys.executable, str(COVERAGE_PATH), "--spec", str(SPEC_PATH),
         "--design", "t1", "--decisions", str(dec),
         "--replay", str(_replay_fixture(tmp_path)), "--out", str(out)],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    report = json.loads(out.read_text())
    assert report["schema"] == cov.SCHEMA
    assert report["status"] == "pass"
    assert report["coverage"]["http_tool_call"]["coverage"] == 1.0


def _replay_fixture(tmp_path: Path) -> Path:
    p = tmp_path / "replay-result.json"
    p.write_text(json.dumps({"window_epoch_ns": {"start": WIN_START,
                                                 "end": WIN_END}}))
    return p


# --- runrecord integration (t1 record carries the coverage section) ------------

def _runrecord_cmd(tmp_path, runs, raw, logs, versions_env, decisions, policy):
    out_dir = tmp_path / "out-t1"
    return subprocess.run(
        [sys.executable, str(RUNRECORD_PATH), "--harness", "pi",
         "--run-id", "pi-t1-test", "--spec", str(SPEC_PATH),
         "--mapped", str(runs / "mapped-actions.jsonl"),
         "--replay", str(runs / "replay-result.json"),
         "--tracee-raw", str(raw), "--target-logs", str(logs),
         "--versions", str(versions_env),
         "--design", "t1", "--gateway-log", str(decisions),
         "--gateway-policy", str(policy),
         "--out-dir", str(out_dir)], capture_output=True, text=True), out_dir


def test_runrecord_t1_embeds_coverage_and_hashes(tmp_path):
    import hashlib
    runs, mapped, replay, raw, logs, versions = write_artifacts(tmp_path)
    versions.write_text(GATEWAY_VERSIONS_ENV)
    gw = tmp_path / "gateway"
    gw.mkdir()
    dec = gw / "decisions.jsonl"
    # decisions inside the CORRECT-RUN fixture's window (do not clobber the
    # replay window the reconciliation fixture stream is built against)
    fixture_window = json.loads(replay.read_text())["window_epoch_ns"]
    base = fixture_window["start"] / 1e9
    in_window = [
        entry(base + 0.5, "post_hook", params={"body": "tool-call payload"}),
        entry(base + 1.5, "get_health"),
        entry(base + 2.5, "put_state", params={"body": "k=v"}),
        entry(base + 3.5, "post_hook", params={"body": "policy-deny probe"}),
    ]
    dec.write_text("\n".join(json.dumps(e) for e in in_window) + "\n")
    policy = gw / "policy.yaml"
    policy.write_text("apiVersion: governance.toolkit/v1\nname: t1-allow-all\n")

    proc, out_dir = _runrecord_cmd(tmp_path, runs, raw, logs, versions,
                                   dec, policy)
    assert proc.returncode == 0, proc.stderr
    record = json.loads((out_dir / "run-record.json").read_text())
    manifest = json.loads((out_dir / "manifest.json").read_text())

    assert record["design"] == "t1"
    assert record["coverage"]["status"] == "pass"
    assert record["coverage"]["coverage"]["http_tool_call"]["coverage"] == 1.0
    assert record["pinned"]["gateway_package_version"] == "3.7.0"
    assert record["pinned"]["gateway_policy_version"] == "1"
    assert manifest["design"] == "t1" and manifest["coverage"] == "pass"

    # the enforcement-point artifacts are hashed into the manifest
    arts = manifest["artifacts"]
    h = hashlib.sha256(dec.read_bytes()).hexdigest()
    assert arts["gateway-decisions"]["sha256"] == h
    assert arts["gateway-policy"]["sha256"] == hashlib.sha256(
        policy.read_bytes()).hexdigest()


def test_runrecord_t1_requires_gateway_log(tmp_path):
    runs, mapped, replay, raw, logs, versions = write_artifacts(tmp_path)
    proc = subprocess.run(
        [sys.executable, str(RUNRECORD_PATH), "--harness", "pi",
         "--run-id", "x", "--spec", str(SPEC_PATH),
         "--mapped", str(runs / "mapped-actions.jsonl"),
         "--replay", str(runs / "replay-result.json"),
         "--versions", str(versions), "--design", "t1",
         "--out-dir", str(tmp_path / "out-x")],
        capture_output=True, text=True)
    assert proc.returncode != 0


def test_runrecord_t0_has_no_coverage_section(tmp_path):
    runs, mapped, replay, raw, logs, versions = write_artifacts(tmp_path)
    out_dir = tmp_path / "out-t0"
    proc = subprocess.run(
        [sys.executable, str(RUNRECORD_PATH), "--harness", "pi",
         "--run-id", "pi-t0-test", "--spec", str(SPEC_PATH),
         "--mapped", str(runs / "mapped-actions.jsonl"),
         "--replay", str(runs / "replay-result.json"),
         "--tracee-raw", str(raw), "--target-logs", str(logs),
         "--versions", str(versions), "--out-dir", str(out_dir)],
        capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    record = json.loads((out_dir / "run-record.json").read_text())
    assert record["design"] == "t0" and record["coverage"] is None


# --- T3: all tools behind the gateway ------------------------------------------


def t3_decisions() -> list[dict]:
    """The 7 in-window decisions a T3 replay produces: the fs tools proxied
    through the gateway (a001-a003) plus the http tools (a011-a014). Params
    mirror the canonical spec args."""
    base = WIN_START / 1e9
    return [
        entry(base + 0.5, "write_file",
              params={"path": "/workspace/out/a.txt", "data": "hello from mcp fs"}),
        entry(base + 1.0, "read_file", params={"path": "/workspace/out/a.txt"}),
        entry(base + 1.5, "list_directory", params={"path": "/workspace/out"}),
        entry(base + 2.5, "post_hook", params={"body": "tool-call payload"}),
        entry(base + 3.0, "get_health"),
        entry(base + 3.5, "put_state", params={"body": "k=v"}),
        entry(base + 4.0, "post_hook", params={"body": "policy-deny probe"}),
    ]


def test_t3_full_coverage_pass():
    report = compute(t3_decisions(), design="t3")
    assert report["status"] == "pass", report["checks"]
    # BOTH tool classes are inspected in T3 ...
    assert report["inspected_classes"] == ["http_tool_call", "stdio_tool_call"]
    assert report["coverage"]["http_tool_call"] == {"ground_truth": 4, "covered": 4,
                                                    "coverage": 1.0, "inspected": True}
    assert report["coverage"]["stdio_tool_call"] == {"ground_truth": 3, "covered": 3,
                                                     "coverage": 1.0, "inspected": True}
    # ... and the remaining classes are escapes/prevented
    for cls, gt in {"direct_network": 2, "process_spawn": 2, "file_write": 2,
                    "credential_access": 2}.items():
        assert report["coverage"][cls]["covered"] == 0
        assert report["coverage"][cls]["inspected"] is False


def test_t3_fs_tool_maps_to_stdio_action():
    report = compute(t3_decisions(), design="t3")
    by_id = {r["id"]: r for r in report["per_action"]}
    assert by_id["a001"]["tool"] == "write_file"
    assert by_id["a001"]["evaluated"] is True
    assert by_id["a001"]["crosses_enforcement_point"] is True
    assert by_id["a001"]["params_match"] is True
    assert by_id["a003"]["tool"] == "list_directory"


def test_t3_missing_fs_decision_fails_c3():
    """C3 must cover the proxied fs tools too: a missing write_file decision
    on a001 fails the run."""
    report = compute([d for d in t3_decisions() if d["tool_name"] != "write_file"],
                     design="t3")
    assert report["status"] == "fail"
    assert any(c["id"] == "C3-evaluated" and c["status"] == "fail"
               for c in report["checks"])


# --- T4: harness-native enforcement (namespaced MCP tool names) ------------------


def t4_decisions() -> list[dict]:
    """The 7 in-window decisions pi's tool_call permission hook records in
    T4: namespaced MCP tool names (mcp__<server>__<tool>), AuditEntry-shaped."""
    base = WIN_START / 1e9
    def ns_entry(ts_s, tool, params):
        return {"timestamp": ts_s, "agent_id": "t4-harness", "tool_name": tool,
                "tool_call_id": "a", "allowed": True,
                "reason": "harness permission mode (allow-all)",
                "parameters": params}
    return [
        ns_entry(base + 0.5, "mcp__toy-mcp-fs__write_file",
                 {"path": "/workspace/out/a.txt", "data": "hello from mcp fs"}),
        ns_entry(base + 1.0, "mcp__toy-mcp-fs__read_file",
                 {"path": "/workspace/out/a.txt"}),
        ns_entry(base + 1.5, "mcp__toy-mcp-fs__list_directory",
                 {"path": "/workspace/out"}),
        ns_entry(base + 2.5, "mcp__toy-mcp-http__post_hook",
                 {"body": "tool-call payload"}),
        ns_entry(base + 3.0, "mcp__toy-mcp-http__get_health", {}),
        ns_entry(base + 3.5, "mcp__toy-mcp-http__put_state", {"body": "k=v"}),
        ns_entry(base + 4.0, "mcp__toy-mcp-http__post_hook",
                 {"body": "policy-deny probe"}),
    ]


def test_t4_full_coverage_pass():
    report = compute(t4_decisions(), design="t4")
    assert report["status"] == "pass", report["checks"]
    assert report["inspected_classes"] == ["http_tool_call", "stdio_tool_call"]
    assert report["coverage"]["stdio_tool_call"]["coverage"] == 1.0
    assert report["coverage"]["http_tool_call"]["coverage"] == 1.0
    for cls in ("direct_network", "process_spawn", "file_write", "credential_access"):
        assert report["coverage"][cls]["coverage"] == 0.0


def test_t4_namespaced_tool_resolves():
    report = compute(t4_decisions(), design="t4")
    by_id = {r["id"]: r for r in report["per_action"]}
    assert by_id["a001"]["tool"] == "write_file"
    assert by_id["a001"]["evaluated"] is True
    assert by_id["a011"]["tool"] == "post_hook"
    assert by_id["a011"]["evaluated"] is True


def test_t4_unknown_namespaced_tool_fails_c2():
    bad = t4_decisions() + [dict(t4_decisions()[0], tool_name="mcp__other__nope")]
    report = compute(bad, design="t4")
    assert report["status"] == "fail"
    assert any(c["id"] == "C2-accounted" and c["status"] == "fail"
               for c in report["checks"])


def test_t5_full_coverage_pass():
    """T5 coverage input = the harness record (the union): both tool classes
    fully evaluated; the gateway's second evaluation lives in the seam record."""
    report = compute(t4_decisions(), design="t5")
    assert report["status"] == "pass", report["checks"]
    assert report["inspected_classes"] == ["http_tool_call", "stdio_tool_call"]
    assert report["coverage"]["stdio_tool_call"]["coverage"] == 1.0
    assert report["coverage"]["http_tool_call"]["coverage"] == 1.0


def test_t6_full_coverage_pass():
    """T6: same placement as T4 — the in-process policy engine inspects both
    tool classes (the decisions carry argument-level rule matches)."""
    report = compute(t4_decisions(), design="t6")
    assert report["status"] == "pass", report["checks"]
    assert report["inspected_classes"] == ["http_tool_call", "stdio_tool_call"]
    assert report["coverage"]["stdio_tool_call"]["coverage"] == 1.0
    assert report["coverage"]["http_tool_call"]["coverage"] == 1.0
