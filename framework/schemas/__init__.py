"""JSON Schema files for the user-facing schema set (DESIGN.md §4).

The `$id` host `guardscope.dev` is a placeholder: the real host and the
distribution form are an open question in DESIGN.md and must be fixed
before the first public release. The type + version identity of every
record lives only in the `$id` here and in the run manifest; data files
carry a bare `schema: 1` stamp.
"""

import json
from pathlib import Path

SCHEMA_DIR = Path(__file__).resolve().parent

# file name -> schema type, both used when composing $id-qualified references
SCHEMA_TYPES = {
    "decision-record": "decision-record",
    "dispatch-record": "dispatch-record",
    # the delegation study's record layer (0.3.0): one record per agent
    # hand-off / acceptance, from the harness/fixture side
    "delegation-record": "delegation-record",
    "experiment": "experiment",
    "capabilities-manifest": "capabilities-manifest",
    "registry-verdict": "registry-verdict",
    "registry-facts": "registry-facts",
}
SCHEMA_VERSION = 1


def schema_path(name: str) -> Path:
    """Path of <name>/1.schema.json under this directory."""
    if name not in SCHEMA_TYPES:
        raise KeyError(f"unknown schema {name!r} (known: {sorted(SCHEMA_TYPES)})")
    return SCHEMA_DIR / name / "1.schema.json"


def load_schema(name: str) -> dict:
    """Load and return the parsed schema document for `name`."""
    return json.loads(schema_path(name).read_text(encoding="utf-8"))
