"""F2 fixture tests: the child-process delegation fixture (DESIGN.md 7
delegation fixtures, scenario class S2 — a child process on the same
machine).

Covers, offline only (no Docker, no network):
  - the two trace variants validate against the trace schema (the additive
    optional performed_by field) and keep the canonical action surface
    1:1 (same ids/classes/targets/ops as baseline.yaml; only the six
    process-level effect actions are marked child-/grandchild-performed);
  - the compiler passes performed_by through to the compiled plan and the
    C2 diff catches a corrupted marking;
  - the child program (harnesses/pi/f2-helper.py), RUN AS A REAL LOCAL
    SUBPROCESS, performs a real file write, writes its acceptance record
    and marker, and its records load clean through
    framework.delegation.load_delegation_records; the two-hop variant
    spawns the grandchild (one more hand-off in the chain) and the chain
    builds ([child, grandchild]) with the trace-back attributing through
    it;
  - the execution manifest's delegation section over a synthetic run
    (attributed via the exact id echo; ERROR rows still trace back through
    their echo; exactly the three contract statuses plus the separate
    effect_observed field reporting what the evidence shows), and its
    ABSENCE for a run with no delegation records — zero behavior change
    for every existing single-agent fixture;
  - the rework's regression cases: a timeout kills the whole child tree
    (the actual delegateToChild block, extracted and run under Node); a
    cyclic chain reports unresolved entries, never a crash; a one-sided
    performed_by marking is a diff finding, never a KeyError.

The TypeScript adapter branch (harnesses/pi/adapter/replay.ts) needs the
harness container and is not live-tested here (the compiled-plan shape it
consumes is: these tests pin it from the compiler side).

Run from the repo root:  python3 -m pytest tests/test_f2.py -v
"""

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from framework.delegation import (  # noqa: E402
    ATTRIBUTED, build_chains, load_delegation_records, trace_back,
)
from framework import execute as execute_mod  # noqa: E402
from framework.execute import execute_experiment  # noqa: E402

BASELINE = ROOT / "trace" / "traces" / "baseline.yaml"
F2_SPEC = ROOT / "trace" / "traces" / "baseline-f2.yaml"
F2H2_SPEC = ROOT / "trace" / "traces" / "baseline-f2h2.yaml"
TRACE_SCHEMA = ROOT / "trace" / "schema" / "trace.schema.json"
COMPILE_PY = ROOT / "trace" / "compile" / "pi" / "compile.py"
HELPER = ROOT / "harnesses" / "pi" / "f2-helper.py"

# the six process-level effect actions the F2 variants mark child-performed
DELEGATED_IDS = {"a021", "a022", "a031", "a032", "a041", "a042"}

# well-formed ULIDs for the synthetic records (delegation-record/1 record_id)
RID1 = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
RID2 = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
RID3 = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"


def _load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _yaml(path):
    return yaml.safe_load(path.read_text())


# --- the trace variants --------------------------------------------------------

def test_f2_specs_validate_against_the_trace_schema():
    schema = json.loads(TRACE_SCHEMA.read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    validator = cls(schema)
    validator.validate(_yaml(F2_SPEC))
    validator.validate(_yaml(F2H2_SPEC))


def test_f2_specs_keep_the_canonical_action_surface():
    baseline = {a["id"]: a for a in _yaml(BASELINE)["actions"]}
    for path, mark in ((F2_SPEC, "child"), (F2H2_SPEC, "grandchild")):
        spec = _yaml(path)
        assert {a["id"] for a in spec["actions"]} == set(baseline)
        for a in spec["actions"]:
            sa = baseline[a["id"]]
            for field in ("class", "target", "op"):
                assert a[field] == sa[field], f"{a['id']}: {field} moved"
            assert a.get("args") == sa.get("args")
            if a["id"] in DELEGATED_IDS:
                assert a["performed_by"] == mark
            else:
                assert "performed_by" not in a
        assert spec["meta"]["window"] == _yaml(BASELINE)["meta"]["window"]


def test_f2_sidecars_match_the_canonical_hash():
    hash_mod = _load_module("hash_spec", ROOT / "trace" / "hash_spec.py")
    for path in (F2_SPEC, F2H2_SPEC):
        sidecar = Path(str(path) + ".sha256")
        assert sidecar.is_file(), f"{sidecar.name} missing"
        assert sidecar.read_text().split()[0] == hash_mod.canonical_hash(path)


# --- the compile path ------------------------------------------------------------

def _compile(path):
    return _load_module("compile_pi_f2", COMPILE_PY).compile_spec(path)


def test_f2_compiles_and_passes_performed_by_through():
    co = _load_module("compile_pi_f2", COMPILE_PY)
    compiled = co.compile_spec(F2_SPEC)
    by_id = {a["id"]: a for a in compiled["actions"]}
    assert len(compiled["actions"]) == 15
    for aid in DELEGATED_IDS:
        assert by_id[aid]["performed_by"] == "child"
        assert by_id[aid]["kind"] in ("tcp_connect", "udp_send", "spawn",
                                      "file_write")
    for aid in set(by_id) - DELEGATED_IDS:
        assert "performed_by" not in by_id[aid]
    assert co.diff_compiled(F2_SPEC, compiled) == []


def test_f2h2_compiles_with_grandchild_marks():
    co = _load_module("compile_pi_f2", COMPILE_PY)
    compiled = co.compile_spec(F2H2_SPEC)
    by_id = {a["id"]: a for a in compiled["actions"]}
    assert all(by_id[aid]["performed_by"] == "grandchild"
               for aid in DELEGATED_IDS)
    assert co.diff_compiled(F2H2_SPEC, compiled) == []


def test_compile_diff_catches_a_corrupted_performed_by():
    co = _load_module("compile_pi_f2", COMPILE_PY)
    bad = co.compile_spec(F2_SPEC)
    for a in bad["actions"]:
        if a["id"] == "a021":
            a["performed_by"] = "grandchild"      # the spec says "child"
    problems = co.diff_compiled(F2_SPEC, bad)
    assert problems and "a021" in problems[0]


def test_compile_diff_reports_a_one_sided_performed_by_marking():
    """Regression (the rework's MEDIUM finding): performed_by is OPTIONAL —
    a marking present on one side only is a corruption FINDING, never a
    KeyError. Both directions: spec marked / compiled unmarked, and the
    reverse."""
    co = _load_module("compile_pi_f2", COMPILE_PY)
    # spec marked, compiled unmarked (the compiled plan dropped the field)
    unmarked = co.compile_spec(F2_SPEC)
    for a in unmarked["actions"]:
        a.pop("performed_by", None)
    problems = co.diff_compiled(F2_SPEC, unmarked)
    assert any("a021" in p and "performed_by" in p for p in problems), \
        problems
    # the reverse: spec unmarked, compiled marked
    marked_up = co.compile_spec(BASELINE)
    for a in marked_up["actions"]:
        if a["id"] == "a021":
            a["performed_by"] = "child"     # the spec has no such marking
    problems = co.diff_compiled(BASELINE, marked_up)
    assert any("a021" in p and "performed_by" in p for p in problems), \
        problems


def test_f2_compile_is_deterministic():
    one = _compile(F2_SPEC)
    two = _compile(F2_SPEC)
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)


# --- the child program, run as a real local subprocess ---------------------------

def run_helper(job: dict, log_dir: Path, delegation_id: str, *,
               parent: str = "", root: str | None = None, hop: int = 1,
               with_chain: bool = True):
    """Spawn harnesses/pi/f2-helper.py exactly the way the adapter does:
    the job on stdin, the chain ids in the environment (the env carrier)."""
    env = dict(os.environ)
    env["REPLAY_LOG_DIR"] = str(log_dir)
    if with_chain:
        env["F2_DELEGATION_ID"] = delegation_id
        env["F2_PARENT_DELEGATION_ID"] = parent
        env["F2_ROOT_DELEGATION_ID"] = root or delegation_id
        env["F2_HOP"] = str(hop)
    else:
        for key in ("F2_DELEGATION_ID", "F2_PARENT_DELEGATION_ID",
                    "F2_ROOT_DELEGATION_ID", "F2_HOP"):
            env.pop(key, None)
    return subprocess.run([sys.executable, str(HELPER)],
                          input=json.dumps(job), capture_output=True,
                          text=True, env=env, timeout=60)


def file_write_job(target: Path, action_id: str = "a041",
                   relay: bool = False) -> dict:
    return {"run_id": "r-f2-test", "relay": relay,
            "actions": [{"id": action_id, "class": "file_write",
                         "kind": "file_write", "path": str(target),
                         "data": "direct write", "append": False}]}


def adapter_sent_record(log_dir: Path, delegation_id: str, rid: str) -> None:
    """Pre-write the adapter's side of the hand-off — the exact line
    harnesses/pi/adapter/replay.ts writes before spawning the helper — so
    the helper-alone test sees the record stream a real run produces
    (sent by the parent, accepted by the child)."""
    log_dir.mkdir(parents=True, exist_ok=True)
    with open(log_dir / "delegation-records.jsonl", "a", encoding="utf-8") \
            as f:
        f.write(json.dumps({
            "schema": 1, "record_id": rid, "run_id": "r-f2-test",
            "stream_id": "pi-root", "seq": 0,
            "ts": "2026-11-02T10:00:00.000Z", "event": "sent",
            "channel": "child", "delegation_id": delegation_id,
            "parent_delegation_id": None,
            "root_delegation_id": delegation_id, "hop": 1,
            "from_actor": "pi-root", "to_actor": "f2-child",
            "task_digest": "0123456789abcdef", "protocol": "stdio",
            "machine": "origin", "carrier": "env"}) + "\n")


def test_helper_performs_a_real_file_write_and_emits_clean_records(tmp_path):
    log_dir = tmp_path / "replay"
    target = tmp_path / "out" / "b.txt"
    adapter_sent_record(log_dir, "d-test-1", RID1)   # the parent's side first
    proc = run_helper(file_write_job(target), log_dir, "d-test-1")
    assert proc.returncode == 0, proc.stderr

    # the effect really happened, from the child process
    assert target.read_text() == "direct write"
    # the marker file proves the child ran and carries the chain ids
    marker = json.loads((log_dir / "f2-marker-d-test-1.json").read_text())
    assert marker["delegation_id"] == "d-test-1"
    assert marker["hop"] == 1 and marker["actor"] == "f2-child"

    # the sent + acceptance records load clean and chain (the loader
    # validates against the frozen delegation-record/1 schema)
    records, problems = load_delegation_records(
        log_dir / "delegation-records.jsonl")
    assert problems == []
    assert len(records) == 2
    rec = [r for r in records if r["event"] == "accepted"][0]
    assert rec["event"] == "accepted"
    assert rec["delegation_id"] == "d-test-1"
    assert rec["hop"] == 1 and rec["to_actor"] == "f2-child"
    assert rec["carrier"] == "env" and rec["channel"] == "child"
    table = build_chains(records)
    assert table.problems == []
    assert table.accepted["d-test-1"] == "f2-child"

    # the report echoes the hand-off id: the exact-echo trace-back
    report = json.loads(proc.stdout)
    assert report["status"] == "ok"
    assert report["delegation_id"] == "d-test-1"
    res = trace_back([{"ts_epoch_ns": 1, "delegation_id": "d-test-1"}],
                     table)
    assert res[0]["status"] == ATTRIBUTED
    assert res[0]["method"] == "id-echo"
    assert res[0]["chain"] == ["d-test-1"]


def test_helper_hop2_spawns_the_grandchild_and_the_chain_builds(tmp_path):
    """The two-hop variant: the child does NOT perform the effect — it
    hands one level further down. The chain the trace-back walks is
    [child hand-off, grandchild hand-off]; the grandchild performs the
    effect and its echo attributes through the whole chain."""
    log_dir = tmp_path / "replay"
    target = tmp_path / "out" / "c.log"
    adapter_sent_record(log_dir, "d-hop-1", RID1)   # the parent's side first
    job = file_write_job(target, action_id="a042", relay=True)
    proc = run_helper(job, log_dir, "d-hop-1")
    assert proc.returncode == 0, proc.stderr
    report = json.loads(proc.stdout)

    # the effect really happened — written by the GRANDCHILD process
    assert target.read_text() == "direct write"

    # four records: the parent's hand-off record + the child's acceptance,
    # the child's hand-off record for the grandchild (hop 2), the
    # grandchild's acceptance
    records, problems = load_delegation_records(
        log_dir / "delegation-records.jsonl")
    assert problems == []
    assert len(records) == 4
    table = build_chains(records)
    assert table.problems == []
    sent2 = [r for r in records if r["event"] == "sent"
             and r["hop"] == 2][0]
    assert sent2["parent_delegation_id"] == "d-hop-1"
    assert sent2["root_delegation_id"] == "d-hop-1"
    assert sent2["from_actor"] == "f2-child"
    assert sent2["to_actor"] == "f2-grandchild"
    assert table.ancestry(sent2["delegation_id"]) == \
        ["d-hop-1", sent2["delegation_id"]]
    assert table.accepted[sent2["delegation_id"]] == "f2-grandchild"

    # the relayed report echoes the GRANDCHILD's hand-off id (the deepest
    # hop), so the traced chain is the full two-hand-off chain
    assert report["delegation_id"] == sent2["delegation_id"]
    res = trace_back([{"ts_epoch_ns": 1,
                       "delegation_id": sent2["delegation_id"]}], table)
    assert res[0]["status"] == ATTRIBUTED
    assert res[0]["chain"] == ["d-hop-1", sent2["delegation_id"]]

    # both children left their liveness markers
    for did in ("d-hop-1", sent2["delegation_id"]):
        marker = json.loads((log_dir / f"f2-marker-{did}.json").read_text())
        assert marker["run_id"] == "r-f2-test"


def test_helper_without_chain_ids_refuses_and_performs_nothing(tmp_path):
    """No hand-off ids in the environment means no hand-off happened: the
    child must refuse (never invent an id), and nothing is performed."""
    log_dir = tmp_path / "replay"
    target = tmp_path / "out" / "b.txt"
    proc = run_helper(file_write_job(target), log_dir, "d-never",
                      with_chain=False)
    assert proc.returncode == 2
    assert "F2_DELEGATION_ID" in proc.stderr
    assert not target.exists()
    assert not (log_dir / "delegation-records.jsonl").exists()


# --- the adapter's timeout must kill the whole child tree ---------------------------

def test_adapter_timeout_kills_the_whole_child_tree(tmp_path):
    """Regression (the rework's HIGH finding): a timeout must never leave
    the child running — an abandoned helper keeps performing effects and
    writing records after the action finished. This extracts the ACTUAL
    F2 delegation block from replay.ts and runs it under Node (node 24
    strips the erasable type annotations natively), pointed at a
    hanging helper that spawns a grandchild which would write a file
    AFTER the timeout. The whole tree must die; the late file must never
    land. The live container path (jiti extension loading) stays
    not-live-verified, as before."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node not available (the adapter is TypeScript)")
    src = (ROOT / "harnesses" / "pi" / "adapter" / "replay.ts").read_text()
    start = src.index("let f2Seq = 0;")
    end = src.index("// T3 (compose/t3.yaml")
    block = src[start:end]     # exactly the F2 block, nothing else
    assert "delegateToChild" in block and "killTree" in block

    log_dir = tmp_path / "replay"
    log_dir.mkdir(parents=True)   # the real adapter mkdirs it before spawning
    late = tmp_path / "late-effect.txt"
    pids_file = tmp_path / "pids"
    helper = tmp_path / "hang-helper.py"
    helper.write_text(
        "import os, subprocess, time\n"
        f"late = {str(late)!r}\n"
        f"pids_file = {str(pids_file)!r}\n"
        # the grandchild would perform its effect 7s in — past the ~5s
        # timeout — proving a survivor writes after the action ended
        f"cmd = 'sleep 7; echo late > ' + {str(late)!r}\n"
        'gc = subprocess.Popen(["sh", "-c", cmd])\n'
        'with open(pids_file, "w") as f:\n'
        '    f.write(f"{os.getpid()} {gc.pid}\\n")\n'
        "time.sleep(60)\n")
    driver = tmp_path / "driver.ts"
    driver.write_text(
        # stubs for the module-level names the extracted block reads
        'const { spawn } = require("node:child_process");\n'
        'const { appendFileSync } = require("node:fs");\n'
        'const crypto = require("node:crypto");\n'
        f'const REPLAY_LOG_DIR = {json.dumps(str(log_dir))};\n'
        'const INSPECTION_RUN_ID = "r-f2-test";\n'
        'const ACTION_TIMEOUT_MS = 1;\n'
        'const F2_HELPER_CMD = JSON.parse(process.env.F2_HELPER_CMD);\n'
        + block
        + '\ndelegateToChild({ id: "a041", class: "file_write", op: "write",\n'
        '                 performed_by: "child" }).then(\n'
        '  (r) => { console.log("RESOLVED " + JSON.stringify(r)); },\n'
        '  (e) => { console.log("REJECTED " + e.message); });\n')
    proc = subprocess.run(
        [node, str(driver)], capture_output=True, text=True, timeout=60,
        env={**os.environ,
             "F2_HELPER_CMD": json.dumps([sys.executable, "-u", str(helper)])})

    # the action rejected on the timeout (never resolved), and the sent
    # record was still written before the spawn
    assert "REJECTED f2-helper timeout" in proc.stdout, \
        proc.stdout + proc.stderr
    assert (log_dir / "delegation-records.jsonl").is_file()

    # the child AND its grandchild are dead: the tree was killed, not
    # just the direct child
    child_pid, grandchild_pid = map(int, pids_file.read_text().split())
    for pid in (child_pid, grandchild_pid):
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                break
            time.sleep(0.1)
        else:
            pytest.fail(f"pid {pid} survived the timeout kill")

    # the grandchild's late effect (7s after spawn, well past the ~5s
    # timeout) never landed
    time.sleep(3)
    assert not late.exists()


# --- the execution manifest's delegation section ---------------------------------

def synthetic_handoff_records() -> list[dict]:
    """One hand-off the way the fixture writes it: the adapter's sent
    line (the giver's side) + the child's accepted line."""
    def rec(event, rid, ts, to_actor):
        return {"schema": 1, "record_id": rid, "run_id": "r-f2-test",
                "stream_id": "pi-root" if event == "sent" else "f2-child-1",
                "seq": 0, "ts": ts, "event": event, "channel": "child",
                "delegation_id": "d-run-1", "parent_delegation_id": None,
                "root_delegation_id": "d-run-1", "hop": 1,
                "from_actor": "pi-root", "to_actor": to_actor,
                "task_digest": "0123456789abcdef", "protocol": "stdio",
                "machine": "origin", "carrier": "env"}
    return [rec("sent", RID1, "2026-11-02T10:00:00.000Z", "f2-child"),
            rec("accepted", RID2, "2026-11-02T10:00:00.100Z", "f2-child")]


def test_delegation_section_over_a_synthetic_run(tmp_path):
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    (out_dir / "delegation-records.jsonl").write_text(
        "".join(json.dumps(r) + "\n"
                for r in synthetic_handoff_records()))
    # the run's effect evidence: a021's replay row carries the child's
    # delegation_id echo (the exact-echo attribution); a011 happened with
    # no echo (a parent-performed tool call, nothing to trace back to)
    (out_dir / "replay-result.json").write_text(json.dumps({
        "results": [
            {"id": "a021", "status": "ok", "started_epoch_ns": 123,
             "detail": {"delegation_id": "d-run-1", "status": "ok"}},
            {"id": "a011", "status": "ok", "started_epoch_ns": 456,
             "detail": {"status": 200}},
        ]}))
    # the run's compiled trace marks a021 child-performed
    compiled_dir = out_dir / "compiled-trace"
    compiled_dir.mkdir()
    (compiled_dir / "baseline-f2.compiled.json").write_text(json.dumps(
        {"actions": [{"id": "a021", "performed_by": "child"}]}))

    spec = _yaml(BASELINE)
    outcome = {"out_dir": str(out_dir)}
    section = execute_mod._delegation_section(outcome, out_dir, spec)
    assert section is not None
    assert section["records"] == 2
    assert section["record_problems"] == []
    assert section["chain_problems"] == []
    a021 = section["per_action"]["a021"]
    assert a021["delegated"] is True
    assert a021["status"] == ATTRIBUTED
    assert a021["method"] == "id-echo"
    assert a021["chain"] == ["d-run-1"]
    assert a021["effect_observed"] == "true"
    # a011's effect happened but no hand-off explains it (it was not
    # delegated): zero candidates -> unresolved, and the delegated flag
    # says so without hiding the trace-back's honest answer
    a011 = section["per_action"]["a011"]
    assert a011["delegated"] is False
    assert a011["status"] == "unresolved"
    assert a011["effect_observed"] == "true"
    # every spec action gets an entry. An action with no effect evidence
    # at all stays inside the three-status contract: unresolved (never a
    # fourth label) with effect_observed unknown — missing evidence never
    # asserts the effect did not happen
    assert set(section["per_action"]) == {a["id"] for a in spec["actions"]}
    a014 = section["per_action"]["a014"]
    assert a014["status"] == "unresolved"
    assert a014["effect_observed"] == "unknown"
    assert a014["method"] is None


def test_error_rows_still_trace_back_through_their_echo(tmp_path):
    """Regression (the rework's HIGH finding): a child that performed a
    real effect and then failed is not silence. Its row carries the
    helper's report — the delegation_id echo rides detail regardless of
    the row's status — so the action traces back through its chain, and
    the effect-observed question reports what the evidence shows,
    separately from the trace-back status."""
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    (out_dir / "delegation-records.jsonl").write_text(
        "".join(json.dumps(r) + "\n"
                for r in synthetic_handoff_records()))
    (out_dir / "replay-result.json").write_text(json.dumps({
        "results": [
            # a041: the child performed the effect, the report still says
            # error (the report's overall status is not the effect's status)
            {"id": "a041", "status": "error", "started_epoch_ns": 1,
             "detail": {"status": "error", "delegation_id": "d-run-1",
                        "results": [{"id": "a041", "status": "ok",
                                     "detail": {"bytes": 12}}]}},
            # a042: the child's effect itself failed
            {"id": "a042", "status": "error", "started_epoch_ns": 2,
             "detail": {"status": "error", "delegation_id": "d-run-1",
                        "results": [{"id": "a042", "status": "error",
                                     "error": "connection refused"}]}},
            # a021: the child was killed on a timeout — the echo is kept,
            # no per-effect result survived
            {"id": "a021", "status": "error", "started_epoch_ns": 3,
             "detail": {"status": "error", "delegation_id": "d-run-1",
                        "results": []}},
        ]}))
    compiled_dir = out_dir / "compiled-trace"
    compiled_dir.mkdir()
    (compiled_dir / "baseline-f2.compiled.json").write_text(json.dumps(
        {"actions": [{"id": aid, "performed_by": "child"}
                     for aid in ("a021", "a041", "a042")]}))

    section = execute_mod._delegation_section({"out_dir": str(out_dir)},
                                              out_dir, _yaml(BASELINE))
    assert section is not None
    # the hand-off was accepted and the echo exists: all three trace
    # back through the chain even though every row is an error
    for aid in ("a041", "a042", "a021"):
        entry = section["per_action"][aid]
        assert entry["status"] == ATTRIBUTED, (aid, entry)
        assert entry["method"] == "id-echo"
        assert entry["chain"] == ["d-run-1"]
        assert entry["delegated"] is True
    # the effect-observed question stays separate and reports what the
    # evidence shows, per action (never more than it shows)
    assert section["per_action"]["a041"]["effect_observed"] == "true"
    assert section["per_action"]["a042"]["effect_observed"] == "false"
    assert section["per_action"]["a021"]["effect_observed"] == "unknown"


def cyclic_handoff_records() -> list[dict]:
    """Two hand-offs whose came-from pointers form a cycle (d-a came from
    d-b, d-b came from d-a) — schema-valid lines, an unbuildable chain."""
    def rec(event, rid, did, parent, ts, to_actor):
        return {"schema": 1, "record_id": rid, "run_id": "r-f2-test",
                "stream_id": "pi-root" if event == "sent" else "f2-child-1",
                "seq": 0, "ts": ts, "event": event, "channel": "child",
                "delegation_id": did, "parent_delegation_id": parent,
                "root_delegation_id": "d-a", "hop": 2,
                "from_actor": "pi-root" if event == "sent" else "f2-child",
                "to_actor": to_actor,
                "task_digest": "0123456789abcdef", "protocol": "stdio",
                "machine": "origin", "carrier": "env"}
    return [
        rec("sent", RID1, "d-a", "d-b", "2026-11-02T10:00:00.000Z",
            "f2-child"),
        rec("accepted", RID2, "d-a", "d-b",
            "2026-11-02T10:00:00.100Z", "f2-child"),
        rec("sent", RID3, "d-b", "d-a", "2026-11-02T10:00:01.000Z",
            "f2-child-2"),
        rec("accepted", RID1, "d-b", "d-a",
            "2026-11-02T10:00:01.100Z", "f2-child-2"),
    ]


def test_cyclic_records_report_unresolved_never_a_crash(tmp_path):
    """Regression (the rework's MEDIUM finding): a schema-valid cyclic
    chain must not abort the manifest. Chain problems are data in the
    section; the per-action trace-back for an action whose chain walks
    the cycle reports unresolved with the cycle noted in its entry."""
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    (out_dir / "delegation-records.jsonl").write_text(
        "".join(json.dumps(r) + "\n"
                for r in cyclic_handoff_records()))
    (out_dir / "replay-result.json").write_text(json.dumps({
        "results": [
            {"id": "a021", "status": "ok", "started_epoch_ns": 1,
             "detail": {"delegation_id": "d-a", "status": "ok"}},
        ]}))
    compiled_dir = out_dir / "compiled-trace"
    compiled_dir.mkdir()
    (compiled_dir / "baseline-f2.compiled.json").write_text(json.dumps(
        {"actions": [{"id": "a021", "performed_by": "child"}]}))

    spec = _yaml(BASELINE)
    section = execute_mod._delegation_section({"out_dir": str(out_dir)},
                                              out_dir, spec)
    # no exception escaped: the section exists, every action has an entry
    assert section is not None
    assert set(section["per_action"]) == {a["id"] for a in spec["actions"]}
    assert any("cycle" in p for p in section["chain_problems"])
    a021 = section["per_action"]["a021"]
    assert a021["status"] == "unresolved"
    assert "cycle" in a021["note"]
    # actions with no effect evidence are unaffected by the cycle
    a011 = section["per_action"]["a011"]
    assert a011["status"] == "unresolved"
    assert a011["effect_observed"] == "unknown"


def test_delegation_section_is_absent_without_delegation_records(tmp_path):
    """Zero behavior change for every existing single-agent fixture: no
    hand-off records -> no section."""
    out_dir = tmp_path / "run"
    out_dir.mkdir()
    (out_dir / "replay-result.json").write_text(json.dumps({"results": []}))
    assert execute_mod._delegation_section({}, out_dir, _yaml(BASELINE)) is \
        None


def _no_delegation_executor(descriptor, run_id, out_root):
    """A minimal fake run_executor (the test_framework_execute convention:
    no Docker; a t0 run with no decision log and no delegation records)."""
    out_dir = Path(out_root) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "run-record.json").write_text(json.dumps({"run_id": run_id}))
    return {"run_id": run_id, "harness": descriptor.harness,
            "design": descriptor.design, "out_dir": str(out_dir),
            "run_record": str(out_dir / "run-record.json"), "status": "pass",
            "coverage": None, "window_epoch_ns": None, "decision_log": None,
            "sensor_present": True, "effective_counts": {},
            "spec_sha256": "f" * 64}


def test_manifest_omits_the_delegation_key_for_single_agent_runs(tmp_path):
    """The manifest byte-shape is unchanged for existing fixtures: the
    delegation key appears only when the run wrote hand-off records."""
    experiment = tmp_path / "e.yaml"
    experiment.write_text(yaml.safe_dump(
        {"schema": 1, "control": None, "designs": ["t0"]},
        sort_keys=False))
    result = execute_experiment(experiment, run_executor=_no_delegation_executor,
                                out_root=tmp_path / "runs")
    entry = result.manifest["runs"][0]
    assert "delegation" not in entry
    assert json.loads(json.dumps(entry)) == entry   # plain JSON, no hidden keys
