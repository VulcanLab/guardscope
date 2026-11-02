"""The framework's own version (single source of truth).

Every place that needs to stamp the framework's version imports it from
here; no other module may carry a duplicated literal. pyproject.toml reads
the version dynamically from this module (`dynamic = ["version"]`), so the
installed distribution and the code always agree.

What lives here and what does NOT:
  __version__    the package version ("0.1.0"), PEP 440.
  FRAMEWORK_LINE the framework line of the registry verdict key
                 (DESIGN.md 11): the release line a conformance verdict was
                 recorded under. It is the "<major>.<minor>" of the package
                 version (additive changes only bump the line with a minor
                 release; anything that expires verdicts also changes
                 SUITE_VERSION in conformance.py).

Not this module's business (their own lines, deliberately not unified
here): the control contract version (contracts.py, part of every verdict
key and record $id), the conformance kit/suite versions (conformance.py,
registry keys), and plugin versions (each plugin's manifest.json, registry
keys), which change on their own schedules.
"""

# 0.2.0: the T7 kernel slot materialized (DESIGN.md 7; the kernel
# facts pinned by the 2026-10-31 probe). Additive for existing
# designs: a control-bound t7 run composes compose/t7.yaml with a
# kernel control binding; control:null t7 keeps the observation-row
# semantics unchanged. Schema notes: capabilities-manifest/1 gains
# the kernel slot kind + the kernel_interference declaration;
# decision-record/1 gains protocol "none" (kernel-position records).
# 0.3.0: the delegation record layer (delegation-record/1 +
# framework/delegation.py): hand-off records with came-from chains,
# acceptance events, the which-machine label, and the trace-back rules
# (exact echo first; actor-window fallback with exactly one live
# candidate; ambiguity REFUSED, never nearest-timestamp). Additive: no
# existing schema or outcome changed; the single-agent designs never
# emit these records.
__version__ = "0.3.0"
FRAMEWORK_LINE = "0.3"
