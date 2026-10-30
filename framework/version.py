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

__version__ = "0.1.0"
FRAMEWORK_LINE = "0.1"
