"""Per-control enforcement-point collection tests (phase 2a): the ingested
binding recipe (plugins/agentgateway/collect.yaml) through the runner
(runner/run.py pull_ingested_log / gateway_readiness_probe) and the
framework's per-control fixture fingerprint (framework/execute.py
_enforcement_config_file).

Docker-free: docker_exec/sh are monkeypatched; the plugin shim itself runs
for real over synthetic vendor rows (the same dtrace-event grammar the shim
tests pin), so the collection path is exercised end to end except the
container I/O.

Run from the repo root:  python3 -m pytest tests/test_agentgateway_runner.py -v
"""

import base64
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))

import run as run_mod  # noqa: E402
from framework import execute as execute_mod  # noqa: E402
from framework.contracts import (  # noqa: E402
    READINESS_TOOL, ContractError, load_collect_recipe,
)


# --- fixtures: synthetic vendor rows in the collector's JSONL grammar -------

def _b64(payload) -> str:
    return base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode()).decode()


def _tools_call_row(ns, rid, tool, args, result, extra_meta=None):
    body = {"jsonrpc": "2.0", "id": f"rpc-{rid}", "method": "tools/call",
            "params": {"name": tool, "arguments": args,
                       **({"_meta": extra_meta} if extra_meta else {})}}
    raw = {"requestId": rid, "eventStart": None, "eventEnd": 200,
           "severity": "info",
           "message": {"type": "cel", "expr": "true",
                       "requestState": {"request": {"body": _b64(body)}},
                       "result": True}}
    return json.dumps({"received_epoch_ns": ns, "raw": raw})


def _auth_row(ns, rid, result):
    raw = {"requestId": rid, "eventStart": None, "eventEnd": 220,
           "severity": "success" if result == "allow" else "error",
           "message": {"type": "authorizationResult",
                       "rules": [{"name": "true", "matched": True,
                                  "mode": "require"}],
                       "result": result}}
    return json.dumps({"received_epoch_ns": ns, "raw": raw})


PROBE_NS = 1_000_000_000_000   # the readiness probe's pre-window rows
RUN_NS = 2_000_000_000_000     # this run's replay-window rows
EARLIER_NS = 500_000_000_000   # an EARLIER run's rows on the same volume

VENDOR_ROWS = [
    # an earlier run's rows (accumulated volume; outside this run's scope)
    _tools_call_row(EARLIER_NS, 1, "post_hook", {"body": "stale"}, "allow"),
    _auth_row(EARLIER_NS + 1, 1, "allow"),
    # this run's readiness probe: the reserved tool, denied by its rule
    _tools_call_row(PROBE_NS, 2, READINESS_TOOL, {}, "deny"),
    _auth_row(PROBE_NS + 1, 2, "deny"),
    # this run's workload decisions
    _tools_call_row(RUN_NS, 3, "post_hook",
                    {"body": "tool-call payload"}, "allow"),
    _auth_row(RUN_NS + 1, 3, "allow"),
    _tools_call_row(RUN_NS + 2, 4, "get_health", {}, "allow"),
    _auth_row(RUN_NS + 3, 4, "allow"),
]


def _recipe():
    return load_collect_recipe("agentgateway", "t1")


# --- the recipe loader ------------------------------------------------------

def test_the_binding_recipe_loads_and_covers_t1():
    recipe = _recipe()
    assert recipe["vendor_log"] == "agentgateway-trace.jsonl"
    assert recipe["collect_container"] == "agentgateway-trace"
    assert recipe["shim"] == "shim/translate.py"
    assert recipe["policy"] == "config/t1-allow-all.json"
    assert recipe["readiness"] is True


def test_recipe_design_coverage_is_enforced():
    with pytest.raises(ContractError, match="does not cover design"):
        load_collect_recipe("agentgateway", "t3")


def test_a_control_without_a_recipe_stays_on_the_default_path():
    # the v0 AGT binding (direct shape: one stateless POST per tool call)
    # ships no recipe, so it never declares a session shape and its runs
    # keep the plain pooled-connect range
    assert load_collect_recipe("agt-gateway", "t1") is None
    assert load_collect_recipe("no-such-control", "t1") is None


def test_the_agentgateway_examples_select_the_calibrated_path():
    """The re-scoped calibration still fires for the agentgateway examples
    (the checker's requirement 2): each example resolves to the
    agentgateway control, whose recipe declares the streamable session
    shape, and that declared value — the same fact the runner threads into
    the reconciler — is what the harness profiles' http_startup_calibration
    pins gate on (design matching alone is not the scope; the v0 binding's
    t1 runs never activate the pin because no recipe declares the shape)."""
    import yaml
    from framework.experiment import load_experiment, resolve
    for example, harness in (("t1-pi-agentgateway.yaml", "pi"),
                             ("t1-mock-agentgateway.yaml", "mock-harness")):
        plan = resolve(load_experiment(ROOT / "examples" / example))
        assert len(plan.runs) == 1
        run = plan.runs[0]
        assert run.control == "agentgateway"
        recipe = load_collect_recipe(run.control, run.design)
        shape = recipe["session_shape"]
        profile = yaml.safe_load(
            (ROOT / "runner" / "profiles" / f"{harness}.yaml")
            .read_text(encoding="utf-8"))
        pin = profile["multiplicity"]["http_startup_calibration"]
        # the declared shape + the run's design are BOTH within the pin's
        # scope: the pin fires for these runs and only for them
        assert shape in pin["session_shapes"], (example, pin)
        assert run.design in pin["designs"], (example, pin)


# --- pull_ingested_log (the per-control collection) --------------------------

def test_pull_ingested_log_scopes_gates_and_translates(tmp_path, monkeypatch):
    """The ingested collection path: the vendor rows are scoped to THIS run
    (an accumulated volume's earlier rows are excluded, counted), the shim
    translates the scoped rows (real shim, real deployed config), the
    readiness deny record gates the run and stays out of the coverage
    input, and the deployed config becomes the run's policy artifact."""

    class P:
        returncode = 0

        def __init__(self, stdout):
            self.stdout = stdout

    def fake_exec(container, cmd, check=True):
        assert container == "t1-mock-agentgateway-trace", container
        assert cmd.startswith("cat /var/log/gateway/agentgateway-trace.jsonl")
        return P("\n".join(VENDOR_ROWS) + "\n")

    monkeypatch.setattr(run_mod, "docker_exec", fake_exec)
    monkeypatch.setattr(run_mod.time, "sleep", lambda s: None)

    probe_ns = PROBE_NS - run_mod.RUN_SCOPE_MARGIN_NS // 2
    d = run_mod.pull_ingested_log(
        tmp_path, "agentgateway", "t1-mock", "agw-run-1", _recipe(),
        probe_started_ns=probe_ns,
        probe_report={"tool": READINESS_TOOL, "denied": True,
                      "status": 403})

    # the scoped vendor artifact: the earlier run's rows excluded, retained
    # on the slot volume (never silently dropped — the count is printed)
    scoped = (d / "agentgateway-trace.jsonl").read_text().splitlines()
    assert len(scoped) == 6          # the 2 earlier-run rows excluded

    # the translated native stream: readiness deny + the workload records
    native = [json.loads(l)
              for l in (d / "decision-records.jsonl").read_text().splitlines()]
    assert [r["tool"] for r in native] == \
        [READINESS_TOOL, "post_hook", "get_health"]
    assert native[0]["decision"] == "deny"
    # the shim stamps the deployed config's sha256 as policy_hash
    policy = (d / "policy.json").read_bytes()
    import hashlib
    assert native[0]["policy"]["policy_hash"] == \
        hashlib.sha256(policy).hexdigest()
    assert (d / "readiness-probe.json").is_file()

    # the coverage input: the workload records only (the pre-window
    # readiness record is runner plumbing; retained above, excluded here)
    coverage = [json.loads(l)
                for l in (d / "decisions.jsonl").read_text().splitlines()]
    assert [r["tool"] for r in coverage] == ["post_hook", "get_health"]
    assert all(r["decision"] == "allow" for r in coverage)
    # the shim's stderr (the skip-count summary) is retained, never dropped
    assert "translate:" in (d / "shim-problems.txt").read_text()


def test_pull_ingested_log_fails_loudly_without_the_readiness_deny(
        tmp_path, monkeypatch):
    """The readiness gate's record half: a collected stream without the
    reserved tool's deny record fails the run — a started container is not
    a ready one (DESIGN.md 3)."""

    class P:
        returncode = 0

        def __init__(self, stdout):
            self.stdout = stdout

    rows = [
        _tools_call_row(RUN_NS, 3, "post_hook", {"body": "x"}, "allow"),
        _auth_row(RUN_NS + 1, 3, "allow"),
    ]

    def fake_exec(container, cmd, check=True):
        return P("\n".join(rows) + "\n")

    monkeypatch.setattr(run_mod, "docker_exec", fake_exec)
    monkeypatch.setattr(run_mod.time, "sleep", lambda s: None)
    with pytest.raises(RuntimeError, match="readiness"):
        run_mod.pull_ingested_log(
            tmp_path, "agentgateway", "t1-mock", "agw-run-2", _recipe(),
            probe_started_ns=RUN_NS, probe_report={"denied": True})


# --- gateway_readiness_probe (the pre-window request half) -------------------

def test_readiness_probe_passes_only_on_a_refusal(monkeypatch):
    denied = {"tool": READINESS_TOOL, "denied": True, "status": 403,
              "detail": "denied by policy"}

    class P:
        returncode = 0

        def __init__(self, stdout):
            self.stdout = stdout

    monkeypatch.setattr(run_mod, "sh",
                        lambda cmd, **kw: P(json.dumps(denied)))
    cfg = {"container": "t1-mock"}
    assert run_mod.gateway_readiness_probe("mock-harness", cfg) == denied

    allowed = dict(denied, denied=False, status=200, detail="ok")
    monkeypatch.setattr(run_mod, "sh",
                        lambda cmd, **kw: P(json.dumps(allowed)))
    with pytest.raises(RuntimeError, match="NOT proven"):
        run_mod.gateway_readiness_probe("mock-harness", cfg)


def test_readiness_probe_command_shapes(monkeypatch):
    """The probe is issued through the topology: docker-exec into the mock
    fixture container (cwd /repo, no bytecode writes on the read-only
    mount) or the pi container's node probe script; an unwired harness is
    an error, never a silent skip."""
    seen = []

    class P:
        returncode = 0
        stdout = json.dumps({"denied": True, "status": 403})

    def fake_sh(cmd, **kw):
        seen.append(list(cmd))
        return P()

    monkeypatch.setattr(run_mod, "sh", fake_sh)
    run_mod.gateway_readiness_probe("mock-harness", {"container": "t1-mock"})
    assert "-w" in seen[-1] and "/repo" in seen[-1]
    assert seen[-1][-1] == "mock_harness.gateway_probe"   # -m module

    run_mod.gateway_readiness_probe("pi", {"container": "t1-pi"})
    assert "node" in seen[-1]
    assert seen[-1][-1].endswith("readiness-probe.mjs")

    with pytest.raises(RuntimeError, match="no readiness probe"):
        run_mod.gateway_readiness_probe("openclaw", {"container": "t1-x"})


# --- the per-control fixture fingerprint (framework/execute.py) --------------

def test_enforcement_config_resolves_per_control():
    """The fingerprint's enforcement_config component hashes the config the
    binding ACTUALLY deploys (the recipe's policy file), not the design's
    default gateway/policy.yaml; controls without a recipe keep the
    default (the v0 AGT path unchanged)."""
    rel = execute_mod._enforcement_config_file("t1", "pi", "agentgateway")
    assert rel == "plugins/agentgateway/config/t1-allow-all.json"
    assert (ROOT / rel).is_file()
    assert execute_mod._enforcement_config_file("t1", "pi", "agt-gateway") \
        == "gateway/policy.yaml"
    assert execute_mod._enforcement_config_file("t1", "pi", None) \
        == "gateway/policy.yaml"


def test_fixture_fingerprint_carries_the_binding_config():
    import yaml
    from framework.experiment import load_experiment, resolve
    plan = resolve(load_experiment(
        ROOT / "examples" / "t1-mock-agentgateway.yaml"))
    fp = execute_mod.fixture_fingerprint(plan.runs[0])
    assert fp["enforcement_config"]["path"] == \
        "plugins/agentgateway/config/t1-allow-all.json"
    assert fp["enforcement_config"]["sha256"] == \
        execute_mod.sha256_file(
            ROOT / "plugins/agentgateway/config/t1-allow-all.json")
    # the same experiment under the v0 binding pins the default policy
    plan = resolve(load_experiment(ROOT / "examples" / "t1-mock.yaml"))
    fp = execute_mod.fixture_fingerprint(plan.runs[0])
    assert fp["enforcement_config"]["path"] == "gateway/policy.yaml"


# --- run_design threads the control through to run_one ------------------------

def test_run_design_accepts_and_validates_the_control():
    # the signature carries the control (the experiment layer passes it);
    # an unknown design still fails validation before anything runs
    import inspect
    assert "control" in inspect.signature(run_mod.run_design).parameters
    with pytest.raises(ValueError, match="unknown design"):
        run_mod.run_design("pi", "t9", "x", control="agentgateway")


def test_native_decision_records_are_kept_verbatim_by_the_mapping(tmp_path):
    """framework/execute.py _map_decision_records: a decision-record/1 log
    (the ingested binding's and the t7 kernel control's shape) passes
    through VERBATIM — the binding's own producer identity, action_id and
    policy stay on the record instead of being relabeled through the v0
    reader-side mapping (shape-driven, never plugin-identity-driven)."""
    shim_rows = [_tools_call_row(RUN_NS, 3, "post_hook",
                                 {"body": "tool-call payload"}, "allow"),
                 _auth_row(RUN_NS + 1, 3, "allow")]
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "agentgateway_shim",
        ROOT / "plugins" / "agentgateway" / "shim" / "translate.py")
    shim = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shim)
    records, problems = shim.translate(
        shim_rows, run_id="r1", stream_id="r1:gateway",
        policy={"policy_id": "t1-allow-all", "policy_version": "1",
                "policy_hash": "a" * 64})
    assert problems == [] and len(records) == 1
    outcome = {"decision_log": str(_write_log(tmp_path, records))}
    mapped, map_problems = execute_mod._map_decision_records(
        outcome, "r1", tmp_path)
    assert map_problems == []
    assert mapped == records    # verbatim: the same dicts, identity intact
    assert mapped[0]["producer"]["plugin"] == "agentgateway"
    assert mapped[0]["enforcement_point"]["product"] == "agentgateway"


def _write_log(dir_path: Path, records) -> Path:
    dir_path = dir_path / "agw-native-decisions"
    dir_path.mkdir(parents=True, exist_ok=True)
    path = dir_path / "decisions.jsonl"
    path.write_text("".join(json.dumps(r, sort_keys=True) + "\n"
                            for r in records), encoding="utf-8")
    return path
