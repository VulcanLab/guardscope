"""T1-2 acceptance: gateway service (gateway/server.py) — docker-free unit
tests for the importable pure parts (policy loading, audit writer, tool-action
mapping). The full intercept path (agent_os only available in the container)
is exercised live in T1-5; the policy-to-GovernancePolicy contract is pinned
here against the shape observed in the agent-os-kernel 3.7.0 investigation.

Run from experiments/mediation/:  python3 -m pytest tests/test_gateway.py -v
"""

import importlib.util
import json
import sys
from pathlib import Path

import yaml

INSPECTION_ROOT = Path(__file__).resolve().parent.parent


def _load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


# gateway/server.py keeps agent_os imports lazy inside build_gateway(), so it
# imports docker-free; explicit module name avoids the "server.py" collision
# with targets/*/server.py.
gateway_server = _load_module("t1_gateway", INSPECTION_ROOT / "gateway" / "server.py")

POLICY_PATH = INSPECTION_ROOT / "gateway" / "policy.yaml"


def read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


# --- policy artifact ---------------------------------------------------------

def test_policy_is_allow_all_for_trace_tools():
    """T1 policy: allow-list covers exactly the three trace tools, no deny
    rules, budget far above the trace size (14 actions)."""
    raw = yaml.safe_load(POLICY_PATH.read_text())
    assert raw["name"] == "t1-allow-all"
    assert set(raw["allowed_tools"]) == {"post_hook", "get_health", "put_state"}
    assert raw["denied_tools"] == []
    assert raw["sensitive_tools"] == []
    assert raw["blocked_patterns"] == []
    assert raw["max_tool_calls"] >= 14


def test_load_policy_yaml_matches_governancepolicy_shape():
    """The loader output has every field build_gateway() passes to
    GovernancePolicy (signature verified during the agent-os-kernel 3.7.0 investigation)."""
    kwargs = gateway_server.load_policy_yaml(POLICY_PATH)
    assert set(kwargs) == {"name", "allowed_tools", "denied_tools",
                           "sensitive_tools", "max_tool_calls", "blocked_patterns"}
    assert kwargs["max_tool_calls"] >= 14


# --- audit writer ------------------------------------------------------------

def test_audit_writer_writes_jsonl(tmp_path, capsys):
    writer = gateway_server.JsonlAuditWriter(tmp_path)
    entry = {"timestamp": 1.0, "agent_id": "t1-replay", "tool_name": "post_hook",
             "allowed": True, "reason": "in allowed_tools", "approval_status": None}
    writer.record(entry)
    writer.record({**entry, "tool_name": "nope", "allowed": False,
                 "reason": "tool 'nope' is not in the allowed list"})
    out = read_jsonl(tmp_path / "decisions.jsonl")
    assert out == [entry, {**entry, "tool_name": "nope", "allowed": False,
                           "reason": "tool 'nope' is not in the allowed list"}]
    # stdout mirror for docker-logs capture
    assert len(capsys.readouterr().out.strip().splitlines()) == 2


def test_audit_writer_missing_dir_is_silent(tmp_path):
    """Logging must never break enforcement (same rule as targets/common.py):
    a missing log dir drops the file write but keeps stdout emission."""
    writer = gateway_server.JsonlAuditWriter(tmp_path / "does-not-exist")
    writer.record({"tool_name": "post_hook", "allowed": True})  # no raise
    assert not writer.path.exists()


# --- forwarded-method contract ----------------------------------------------

def test_forwarded_method_set():
    """tools/call is intercepted, everything else is proxied; unknown methods
    are rejected without upstream contact."""
    assert gateway_server.FORWARDED == {"initialize", "notifications/initialized",
                                        "ping", "tools/list"}
    assert "tools/call" not in gateway_server.FORWARDED
