"""OpenClaw compiler tests (C2, M4 acceptance).

The compiled trace must diff clean against the canonical spec (id/class/
target/op 1:1), be deterministic, and carry a valid spec hash.

Run from experiments/mediation/:  python3 -m pytest tests/test_compile.py -v
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

INSPECTION_ROOT = Path(__file__).resolve().parent.parent
COMPILE_PY = INSPECTION_ROOT / "trace" / "compile" / "openclaw" / "compile.py"
BASELINE = INSPECTION_ROOT / "trace" / "traces" / "baseline.yaml"


def _load_module():
    spec = importlib.util.spec_from_file_location("compile_openclaw", COMPILE_PY)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture(scope="module")
def co():
    return _load_module()


@pytest.fixture(scope="module")
def compiled(co):
    return co.compile_spec(BASELINE)


def test_all_actions_compiled(compiled):
    assert len(compiled["actions"]) == 15
    assert {a["id"] for a in compiled["actions"]} == {f"a{i:03d}" for i in
                                                      [1, 2, 3, 11, 12, 13, 14, 21, 22, 31, 32, 41, 42, 51, 52]}


def test_spec_hash_embedded(compiled):
    import hashlib
    assert compiled["meta"]["spec_sha256"] == hashlib.sha256(BASELINE.read_bytes()).hexdigest()


def test_stdio_actions_plan(compiled):
    by_id = {a["id"]: a for a in compiled["actions"]}
    assert by_id["a001"]["kind"] == "mcp"
    assert by_id["a001"]["tool"] == "write_file"
    assert by_id["a001"]["server"] == "fs"
    assert by_id["a001"]["arguments"]["path"] == "/workspace/out/a.txt"
    assert by_id["a002"]["tool"] == "read_file"
    assert by_id["a003"]["tool"] == "list_directory"


def test_http_actions_plan(compiled):
    by_id = {a["id"]: a for a in compiled["actions"]}
    assert by_id["a011"]["kind"] == "http"
    assert by_id["a011"]["method"] == "POST"
    assert by_id["a011"]["url"] == "http://http-endpoint:8080/hook"
    assert by_id["a011"]["body"] == "tool-call payload"
    assert by_id["a012"]["method"] == "GET"
    assert by_id["a013"]["method"] == "PUT"


def test_network_actions_plan(compiled):
    by_id = {a["id"]: a for a in compiled["actions"]}
    assert by_id["a021"]["kind"] == "tcp_connect"
    assert by_id["a021"]["host"] == "net-peer" and by_id["a021"]["port"] == 9000
    assert by_id["a022"]["kind"] == "udp_send" and by_id["a022"]["port"] == 9001


def test_spawn_actions_plan(compiled):
    by_id = {a["id"]: a for a in compiled["actions"]}
    assert by_id["a031"]["cmd"] == ["/bin/sh", "-c", "echo hi"]
    assert by_id["a032"]["cmd"] == ["/bin/echo", "spawned", "directly"]


def test_fs_and_credential_plans(compiled):
    by_id = {a["id"]: a for a in compiled["actions"]}
    assert by_id["a041"]["kind"] == "file_write" and by_id["a041"]["append"] is False
    assert by_id["a042"]["append"] is True
    assert by_id["a051"]["kind"] == "credential_read"
    assert by_id["a051"]["path"] == "/run/secrets/token"
    assert by_id["a052"]["path"] == "/run/secrets/db_password"


def test_diff_clean(compiled, co):
    assert co.diff_compiled(BASELINE, compiled) == []


def test_diff_detects_corruption(co, compiled):
    bad = json.loads(json.dumps(compiled))
    bad["actions"][0]["class"] = "http_tool_call"  # corrupt a001
    problems = co.diff_compiled(BASELINE, bad)
    assert problems and "a001" in problems[0]


def test_determinism(co):
    one = co.compile_spec(BASELINE)
    two = co.compile_spec(BASELINE)
    assert json.dumps(one, sort_keys=True) == json.dumps(two, sort_keys=True)


def test_cli_out_and_check(tmp_path, co):
    out = Path("/tmp") / "m4-test-compile.json"
    subprocess.run([sys.executable, str(COMPILE_PY), str(BASELINE), "--out", str(out)],
                   check=True, capture_output=True)
    on_disk = json.loads(out.read_text())
    assert co.diff_compiled(BASELINE, on_disk) == []
    # --check mode: exit 0 when clean
    subprocess.run([sys.executable, str(COMPILE_PY), str(BASELINE), "--check"],
                   check=True, capture_output=True)
    # a drifted compiled trace (dropped action) fails the diff
    drifted = dict(on_disk)
    drifted["actions"] = drifted["actions"][:-1]
    out.write_text(json.dumps(drifted))
    problems = co.diff_compiled(BASELINE, json.loads(out.read_text()))
    assert problems