"""Schema tests for the canonical trace spec (C1 acceptance).

Run from experiments/mediation/:  python3 -m pytest tests/test_schema.py -v
"""

import json
import subprocess
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml

INSPECTION_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = INSPECTION_ROOT / "trace" / "schema" / "trace.schema.json"
BASELINE_PATH = INSPECTION_ROOT / "trace" / "traces" / "baseline.yaml"
HASH_TOOL = INSPECTION_ROOT / "trace" / "hash_spec.py"

SIX_CLASSES = {
    "stdio_tool_call",
    "http_tool_call",
    "direct_network",
    "process_spawn",
    "file_write",
    "credential_access",
}


@pytest.fixture(scope="module")
def schema():
    return json.loads(SCHEMA_PATH.read_text())


@pytest.fixture(scope="module")
def baseline():
    return yaml.safe_load(BASELINE_PATH.read_text())


@pytest.fixture(scope="module")
def validator(schema):
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


def test_schema_is_valid_draft2020(schema):
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"
    jsonschema.Draft202012Validator.check_schema(schema)


def test_baseline_validates(validator, baseline):
    validator.validate(baseline)


def test_every_action_class_represented(baseline):
    present = {a["class"] for a in baseline["actions"]}
    assert present == SIX_CLASSES


def test_action_ids_unique(baseline):
    ids = [a["id"] for a in baseline["actions"]]
    assert len(ids) == len(set(ids))


def test_multiple_instances_per_class(baseline):
    counts = {}
    for a in baseline["actions"]:
        counts[a["class"]] = counts.get(a["class"], 0) + 1
    assert all(c >= 2 for c in counts.values()), counts


def test_window_marks_defined(baseline):
    w = baseline["meta"]["window"]
    assert w["start"] and w["end"] and w["start"] != w["end"]


# --- class-conditional schema constraints -----------------------------------


def _action(cls, **overrides):
    base = {
        "id": "a999",
        "class": cls,
        "target": {
            "stdio_tool_call": "mcp://fs@local",
            "http_tool_call": "http://http-endpoint:8080",
            "direct_network": "net-peer:9000",
            "process_spawn": "/bin/sh",
            "file_write": "/workspace/out/x.txt",
            "credential_access": "file:///run/secrets/token",
        }[cls],
        "op": {
            "stdio_tool_call": "write_file",
            "http_tool_call": "POST",
            "direct_network": "tcp_connect",
            "process_spawn": "exec",
            "file_write": "write",
            "credential_access": "read",
        }[cls],
        "args": {},
    }
    base.update(overrides)
    return base


@pytest.mark.parametrize(
    "bad",
    [
        _action("http_tool_call", target="ftp://http-endpoint:8080"),  # wrong scheme
        _action("http_tool_call", op="BREW"),  # not an HTTP method
        _action("direct_network", target="net-peer"),  # missing port
        _action("direct_network", op="icmp_ping"),  # unsupported op
        _action("process_spawn", target="sh"),  # relative path
        _action("process_spawn", op="fork"),  # unsupported op
        _action("file_write", target="workspace/out/x.txt"),  # relative path
        _action("file_write", op="delete"),  # unsupported op
        _action("credential_access", target="env://SECRET"),  # not kernel-observable in v1
        _action("credential_access", op="write"),  # secrets are read-only here
        _action("stdio_tool_call", target="fs@local"),  # not an mcp:// URI
        {"id": "a999", "class": "brain_wave", "target": "x", "op": "y"},  # unknown class
        {"id": "a999", "class": "file_write", "target": "/x"},  # missing op
        {"id": "a999", "class": "file_write", "op": "write"},  # missing target
        {"class": "file_write", "target": "/x", "op": "write"},  # missing id
    ],
)
def test_schema_rejects_invalid_actions(validator, bad):
    with pytest.raises(jsonschema.ValidationError):
        validator.validate({"meta": {"name": "t", "version": 1,
                                     "window": {"start": "s", "end": "e"}},
                            "actions": [bad]})


# --- hash tooling ------------------------------------------------------------


def _run_hash_tool(*cli_args):
    return subprocess.run(
        [sys.executable, str(HASH_TOOL), *cli_args],
        capture_output=True, text=True, check=True,
    )


def test_hash_stable_across_cosmetic_edits(tmp_path):
    """Reordering keys / changing comments / requoting must not change the hash."""
    original = BASELINE_PATH.read_text()
    perturbed = (
        "# a brand new comment\n"
        + original.replace("name: baseline-t0", "description: x\n  name: baseline-t0")
    )
    perturbed_path = tmp_path / "baseline.yaml"
    perturbed_path.write_text(perturbed)
    assert _run_hash_tool(str(perturbed_path)).stdout.strip() == \
        _run_hash_tool(str(BASELINE_PATH)).stdout.strip()


def test_hash_changes_on_semantic_edit(tmp_path):
    data = yaml.safe_load(BASELINE_PATH.read_text())
    data["actions"][0]["args"]["data"] = "tampered"
    tampered_path = tmp_path / "baseline.yaml"
    tampered_path.write_text(yaml.safe_dump(data, sort_keys=True))
    assert _run_hash_tool(str(tampered_path)).stdout.strip() != \
        _run_hash_tool(str(BASELINE_PATH)).stdout.strip()


def test_hash_check_mode():
    h = _run_hash_tool(str(BASELINE_PATH)).stdout.strip()
    proc = _run_hash_tool("--check", h, str(BASELINE_PATH))
    assert proc.returncode == 0
    with pytest.raises(subprocess.CalledProcessError):
        subprocess.run([sys.executable, str(HASH_TOOL), "--check",
                        "0" * 64, str(BASELINE_PATH)],
                       capture_output=True, text=True, check=True)


def test_hash_sidecar_roundtrip(tmp_path):
    spec_copy = tmp_path / "baseline.yaml"
    spec_copy.write_text(BASELINE_PATH.read_text())
    _run_hash_tool("--write-sidecar", str(spec_copy))
    sidecar = tmp_path / "baseline.yaml.sha256"
    assert sidecar.is_file()
    proc = _run_hash_tool("--check", str(sidecar), str(spec_copy))
    assert proc.returncode == 0
