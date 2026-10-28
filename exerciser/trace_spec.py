"""Trace-spec loading, verification, and compiled-plan derivation (v1).

Read-only reuse of the canonical trace tooling (the exerciser must not
re-encode the action list in a parallel file):

  - trace/schema/trace.schema.json validates the spec
  - trace/hash_spec.py provides the canonical/raw SHA-256 (sidecar pin)
  - trace/compile/pi/compile.py derives the per-action execution plan, so
    the exerciser's argv/url/path shapes are byte-identical to the harness
    replay's compiled plan for the same spec

Nothing here writes to trace/ and nothing here imports the inspection layer
(gateway/) or the mapper (sensor/mapping/).
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import jsonschema
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
TRACE_SCHEMA_PATH = REPO_ROOT / "trace" / "schema" / "trace.schema.json"
PI_COMPILE_PATH = REPO_ROOT / "trace" / "compile" / "pi" / "compile.py"
DEFAULT_TRACE = REPO_ROOT / "trace" / "traces" / "baseline.yaml"

_hash_spec = None  # lazy import of trace/hash_spec.py


def _load_hash_spec():
    """Import trace/hash_spec.py (sidecar-canonical SHA-256 tooling)."""
    global _hash_spec
    if _hash_spec is None:
        sys.path.insert(0, str(REPO_ROOT / "trace"))
        try:
            import hash_spec  # noqa: E402
        finally:
            sys.path.pop(0)
        _hash_spec = hash_spec
    return _hash_spec


def load_spec(path: Path) -> dict:
    """Parse + schema-validate a canonical trace spec (read-only reuse)."""
    spec = yaml.safe_load(Path(path).read_text())
    schema = json.loads(TRACE_SCHEMA_PATH.read_text())
    jsonschema.validate(spec, schema)
    return spec


def canonical_sha256(path: Path) -> str:
    return _load_hash_spec().canonical_hash(Path(path))


def raw_sha256(path: Path) -> str:
    return _load_hash_spec().raw_hash(Path(path))


def verify_sidecar(path: Path) -> bool | None:
    """Verify the spec against its .sha256 sidecar when one exists.

    Returns True/False when a sidecar is present, None when there is none
    to check (a caller-supplied spec without a pin is permitted; the run
    manifest records which case held).
    """
    sidecar = Path(path).with_suffix(Path(path).suffix + ".sha256")
    if not sidecar.is_file():
        return None
    expected = sidecar.read_text().split()[0]
    return canonical_sha256(path) == expected


def load_pi_compile():
    """Import trace/compile/pi/compile.py under a private module name."""
    spec = importlib.util.spec_from_file_location("inspection_exerciser_pi_compile", PI_COMPILE_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def compile_action(action: dict) -> dict:
    """Canonical action -> the harness replay's execution plan for it.

    Same compiler the pi replay adapter consumes: the exerciser's spawn
    argv, http url/method/body, network host/port/payload, file path/data,
    and credential path are byte-identical to the harness replay's.
    """
    return load_pi_compile().compile_action(action)
