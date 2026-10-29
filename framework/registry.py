"""The registry (DESIGN.md 11 "Registry & governance", the full spec).

DESIGN.md 11's three strict layers put the registry in the middle: verdicts
keyed by (plugin version, contract version, framework line, suite version,
golden-fixture hash); per-product capability facts with provenance and
expiry; two tiers, one format.

Data layout (one JSON file per plugin per tier):

  registry/curated/<plugin_id>.json   framework-CI re-verified verdicts;
                                      main-grid eligible (DESIGN.md 11)
  registry/open/<plugin_id>.json      self-attested, labeled, appendix-only
  registry/facts/<plugin_id>.json     selection-rule facts with provenance
                                      and expiry (separate from verdicts)

Every verdict entry records its full key (the `as_of` field: what the
verdict was verified against). A verdict is valid ONLY for the exact key it
was recorded under (DESIGN.md 11): is_verdict_current() reports staleness
for any key-component change (a plugin version bump, a contract version
bump, a framework line bump, a suite version bump, a golden-fixture hash
change). Staleness downgrades the display (as-of), never hides the verdict.

eligible_for_main_grid() applies the tier rule (DESIGN.md 11): curated tier
+ current verdict only; open-tier or stale verdicts are not eligible but are
returned labeled.

Honesty rule honored here: no framework CI exists yet, so this registry
records only OPEN-tier self-attested verdicts (the seed files say so in
their notes/limitations fields). No curated file may be recorded until
framework-CI re-verification exists.
"""

import json
from pathlib import Path

import jsonschema

from framework.schemas import load_schema

REPO_ROOT = Path(__file__).resolve().parent.parent
REGISTRY_DIR = REPO_ROOT / "registry"

TIERS = ("curated", "open")

# The verdict key, all of it (DESIGN.md 11): a verdict is valid only for the
# exact key it was recorded under.
VERDICT_KEY = ("plugin_id", "plugin_version", "contract_version",
               "framework_line", "suite_version", "golden_fixture_hash")

_VERDICT_VALIDATOR = jsonschema.Draft202012Validator(
    load_schema("registry-verdict"))
_FACT_VALIDATOR = jsonschema.Draft202012Validator(
    load_schema("registry-facts"))


class RegistryError(ValueError):
    """A registry file is missing, unreadable, or schema-invalid."""


# --- loading -----------------------------------------------------------------------


def _load_and_validate(path: Path, validator, what: str) -> dict:
    if not path.is_file():
        raise RegistryError(f"no {what} at {path}")
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RegistryError(f"{path}: not valid JSON ({exc})") from exc
    error = jsonschema.exceptions.best_match(validator.iter_errors(doc))
    if error is not None:
        raise RegistryError(f"{path}: schema violation: {error.message}")
    return doc


def _tier_docs(tier: str, registry_root: Path) -> dict[str, dict]:
    if tier not in TIERS:
        raise RegistryError(f"unknown tier {tier!r} (known: {list(TIERS)})")
    root = registry_root / tier
    if not root.is_dir():
        return {}
    docs = {}
    for path in sorted(root.glob("*.json")):
        doc = _load_and_validate(path, _VERDICT_VALIDATOR,
                                 f"{tier} verdict file")
        docs[doc["plugin"]] = doc
    return docs


def load_verdict_docs(*, registry_root=None) -> dict[str, dict]:
    """All verdict files: {tier: {plugin_id: doc}} (schema-validated)."""
    root = Path(registry_root) if registry_root is not None else REGISTRY_DIR
    return {tier: _tier_docs(tier, root) for tier in TIERS}


def load_fact_docs(*, registry_root=None) -> dict[str, dict]:
    """All fact files: {plugin_id: doc} (schema-validated; DESIGN.md 11:
    facts are separate from verdicts)."""
    root = Path(registry_root) if registry_root is not None else REGISTRY_DIR
    facts_dir = root / "facts"
    if not facts_dir.is_dir():
        return {}
    docs = {}
    for path in sorted(facts_dir.glob("*.json")):
        doc = _load_and_validate(path, _FACT_VALIDATOR, "fact file")
        docs[doc["plugin"]] = doc
    return docs


# --- currency (DESIGN.md 11: verdicts expire when any key component changes) -------


def current_keys(plugin_id: str, *, plugin_version: str | None = None,
                 golden_fixture_hash: str | None = None) -> dict:
    """The current verdict key for a plugin, computed from the repo's state:
    the plugin's manifest version (the registered current version), the
    control-contract line and framework line this framework implements, and
    the conformance suite's current golden-fixture hash. Any component that
    changes makes recorded verdicts stale (DESIGN.md 11)."""
    from framework.contracts import CONTROL_CONTRACT_VERSION
    from framework.conformance import (
        FRAMEWORK_LINE, SUITE_VERSION, suite_golden_fixture_hash,
    )
    if plugin_version is None:
        manifest_path = REPO_ROOT / "plugins" / plugin_id / "manifest.json"
        plugin_version = (json.loads(manifest_path.read_text(
            encoding="utf-8"))["version"] if manifest_path.is_file()
            else "unknown")
    return {
        "plugin_id": plugin_id,
        "plugin_version": plugin_version,
        "contract_version": CONTROL_CONTRACT_VERSION,
        "framework_line": FRAMEWORK_LINE,
        "suite_version": SUITE_VERSION,
        "golden_fixture_hash": (golden_fixture_hash
                                if golden_fixture_hash is not None
                                else suite_golden_fixture_hash()),
    }


def is_verdict_current(verdict: dict, *, current_keys: dict) -> tuple[bool, list]:
    """(current, reasons) for one verdict against the current keys
    (DESIGN.md 11: any key-component change makes the verdict stale).

    A component missing from current_keys cannot be verified, so it counts
    as stale (conservative: never claim currency a check did not establish).
    The verdict itself is returned by the callers with its as_of display,
    never hidden.
    """
    reasons = []
    for component in VERDICT_KEY:
        recorded = verdict.get(component)
        current = current_keys.get(component)
        if current is None:
            reasons.append(f"{component}: current key unknown "
                           f"(cannot verify currency)")
        elif recorded is None:
            reasons.append(f"{component}: the verdict does not record this "
                           f"key component")
        elif recorded != current:
            reasons.append(f"{component}: verdict {recorded!r} != current "
                           f"{current!r}")
    return (not reasons, reasons)


def _entry_as_of(verdict: dict) -> dict:
    """The as_of display field: what the verdict was verified against (the
    exact key it was recorded under, DESIGN.md 11)."""
    return {component: verdict.get(component) for component in VERDICT_KEY}


# --- main-grid eligibility (DESIGN.md 11: curated + current only) -------------------


def eligible_for_main_grid(plugin_id: str, version: str | None = None, *,
                           registry_root=None, keys: dict | None = None) -> dict:
    """Main-grid eligibility for one plugin version (DESIGN.md 11): curated
    tier + current verdict only. Open-tier or stale verdicts are not
    eligible but are returned labeled (staleness downgrades display, never
    hides); a plugin with no verdict is labeled as such."""
    docs = load_verdict_docs(
        registry_root=registry_root if registry_root is not None
        else REGISTRY_DIR)
    keys = keys if keys is not None else current_keys(
        plugin_id, plugin_version=version)
    result = {
        "plugin": plugin_id,
        "version": version,
        "eligible": False,
        "tier": None,
        "current": None,
        "stale_reasons": [],
        "label": "no verdict recorded for this plugin/version",
        "as_of": None,
        "verdicts": [],
    }
    for tier in TIERS:
        for entry in (docs[tier].get(plugin_id) or {}).get("entries") or []:
            verdict = entry.get("verdict") or {}
            if verdict.get("plugin_id") != plugin_id:
                continue
            if version is not None and verdict.get("plugin_version") != version:
                continue
            current, reasons = is_verdict_current(verdict,
                                                  current_keys=keys)
            result["verdicts"].append({"tier": tier, "entry": entry,
                                        "current": current,
                                        "stale_reasons": reasons})
    curated_current = [v for v in result["verdicts"]
                       if v["tier"] == "curated" and v["current"]]
    curated_stale = [v for v in result["verdicts"]
                     if v["tier"] == "curated" and not v["current"]]
    if curated_current:
        entry = curated_current[0]["entry"]
        result.update(eligible=True, tier="curated", current=True,
                      label="curated tier, current verdict",
                      as_of=entry.get("as_of") or _entry_as_of(
                          entry.get("verdict") or {}))
    elif curated_stale:
        entry = curated_stale[0]["entry"]
        result.update(tier="curated", current=False,
                      label="curated tier but stale (as-of display, "
                            "never hidden; DESIGN.md 11)",
                      stale_reasons=curated_stale[0]["stale_reasons"],
                      as_of=entry.get("as_of") or _entry_as_of(
                          entry.get("verdict") or {}))
    elif result["verdicts"]:
        best = result["verdicts"][0]
        entry = best["entry"]
        result.update(
            tier="open", current=best["current"],
            label=("open tier: self-attested, appendix-only"
                   + ("" if best["current"]
                      else ", and stale (as-of display; DESIGN.md 11)")),
            stale_reasons=best["stale_reasons"],
            as_of=entry.get("as_of") or _entry_as_of(entry.get("verdict")
                                                     or {}))
    return result


# --- recording (verdicts and facts are data, never executable) -----------------------


def record_verdict(verdict: dict, *, tier: str, recorded_by: str,
                   verified_by: str, attestation: str = "self-attested",
                   limitations=None, notes: str | None = None,
                   registry_root=None, recorded_at: str | None = None) -> Path:
    """Append one verdict entry to registry/<tier>/<plugin_id>.json,
    validated against registry-verdict/1. The entry records its full key
    (as_of) and its provenance (recorded_by, recorded_at, verified_by,
    attestation). Honesty rule: the curated tier is framework-CI
    re-verified (DESIGN.md 11) and no framework CI exists, so no curated
    verdict may be recorded yet — callers record open-tier self-attested
    verdicts only."""
    from framework.records import now_rfc3339_ms
    if tier not in TIERS:
        raise RegistryError(f"unknown tier {tier!r} (known: {list(TIERS)})")
    plugin_id = (verdict or {}).get("plugin_id")
    if not plugin_id:
        raise RegistryError("the verdict carries no plugin_id")
    if tier == "curated":
        raise RegistryError(
            "no framework CI exists: the curated tier is framework-CI "
            "re-verified (DESIGN.md 11); record an open-tier "
            "self-attested verdict instead")
    entry = {
        "verdict": verdict,
        "attestation": attestation,
        "recorded_by": recorded_by,
        "recorded_at": recorded_at or now_rfc3339_ms(),
        "verified_by": verified_by,
        "as_of": _entry_as_of(verdict),
        "limitations": list(limitations or []),
    }
    root = Path(registry_root) if registry_root is not None else REGISTRY_DIR
    path = root / tier / f"{plugin_id}.json"
    if path.is_file():
        doc = _load_and_validate(path, _VERDICT_VALIDATOR, "verdict file")
    else:
        doc = {"schema": 1, "plugin": plugin_id, "tier": tier,
               "notes": notes or "", "entries": []}
    doc["entries"].append(entry)
    error = jsonschema.exceptions.best_match(
        _VERDICT_VALIDATOR.iter_errors(doc))
    if error is not None:
        raise RegistryError(f"{path}: schema violation: {error.message}")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path


def record_facts(doc: dict, *, registry_root=None) -> Path:
    """Write registry/facts/<plugin_id>.json, validated against
    registry-facts/1 (selection-rule facts with provenance and expiry,
    separate from verdicts; DESIGN.md 11)."""
    plugin_id = (doc or {}).get("plugin")
    if not plugin_id:
        raise RegistryError("the fact doc carries no plugin")
    error = jsonschema.exceptions.best_match(
        _FACT_VALIDATOR.iter_errors(doc))
    if error is not None:
        raise RegistryError(f"facts {plugin_id}: schema violation: "
                            f"{error.message}")
    root = Path(registry_root) if registry_root is not None else REGISTRY_DIR
    path = root / "facts" / f"{plugin_id}.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n",
                    encoding="utf-8")
    return path
