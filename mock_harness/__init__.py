"""Path-originator mock harness (v1): a policy-blind instrument that
deterministically performs the canonical 15-action surface directly at the
OS level, from inside the harness trust domain.

NOT a harness, NOT an agent: it has no enforcement, no permission checks,
and no classification logic. It exists to exercise the action paths that
bypass every sub-kernel enforcement design (direct-origin operations,
unwatched channels, daemon submissions, outliving processes, dispatch-free
output consumption) and to serve as the deterministic action source for T7
observation runs. Classification happens only in the existing reconcile step
against Tracee.

Layout:
  manifest.yaml (+ .sha256)  the pinned path manifest (first artifact)
  manifest.schema.json        JSON Schema for the path manifest
  plan-schema.json            JSON Schema for run plans
  record.schema.json          JSON Schema for action records + run manifests
  syscalls.py                 the thin syscall layer (all OS effects)
  originators.py              one deterministic originator per canonical action
  trace_spec.py               trace-spec loading/verification/plan compile (read-only reuse)
  driver.py                   CLI: reads the trace, runs the originators, writes the logs
"""

MOCK_HARNESS_VERSION = "mock-harness@1"
PATH_MANIFEST_SCHEMA = "mock-harness-path-manifest/1"
ACTION_RECORD_SCHEMA = "mock-harness-action-record/1"
RUN_MANIFEST_SCHEMA = "mock-harness-run-manifest/1"
PLAN_SCHEMA = "mock-harness-plan/1"

# The five escape-path categories the instrument exercises (manifest.yaml
# `escape_paths` is the authoritative declaration; this is the code-side list
# the driver uses for the `--mode escape` preset semantics documentation).
ESCAPE_CLASSES = frozenset(
    {"direct_network", "process_spawn", "file_write", "credential_access"})
TWIN_CLASSES = frozenset({"stdio_tool_call", "http_tool_call"})
