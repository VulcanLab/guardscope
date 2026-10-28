"""The correlation fidelity check (DESIGN.md 5, "Fidelity check (conformance
kit, gating)"): send ONE marked call through the control per transport,
collect the emitted decision record, assert the marked (action_id, attempt)
appears in it, and publish per-control, per-transport capability flags
("product X preserves `_meta`"). Capability preservation is a measured,
per-control capability, never a contract assumption: the manifest's
correlation claims (echoes_meta / echoes_header, DESIGN.md 3 describe()) are
verified by this check and never trusted.

Transport-coupled, issuer-agnostic: run_fidelity_check(issuer, collector)
takes an issuer(transport, action_id, attempt) that sends the marked
tools/call on the given transport ("mcp_meta" injects the params._meta
namespaced keys, "http_header" sets the x-inspection-* headers, DESIGN.md 5
carriers 1 and 2) and a collector() that returns the records the control
emitted since. Unit tests wire fakes; the live path wires both against the
compose stack in a later pass (the CLI `fidelity` subcommand validates its
config only and requires a running topology).

publish_fidelity_report() writes plugins/<id>/fidelity.json: the
version-keyed capability facts (control version, transport, result,
timestamp) that back the manifest's correlation claims in the registry story
(DESIGN.md 11).
"""

import json
from pathlib import Path

import yaml

from framework.records import now_rfc3339_ms

REPO_ROOT = Path(__file__).resolve().parent.parent

# The transports a fidelity check can mark (DESIGN.md 5 carriers 1 and 2;
# the exact-match join (carrier 3) and the heuristics (carrier 4) are
# reconciliation-time attribution, not wire carriers a control echoes).
TRANSPORTS = ("mcp_meta", "http_header")


class FidelityConfigError(ValueError):
    """The fidelity-check config failed validation."""


def _attempt_of(record: dict) -> int:
    try:
        return int(record.get("attempt", 0) or 0)
    except (TypeError, ValueError):
        return 0


def run_fidelity_check(issuer, collector, *, action_id=None, attempt: int = 0,
                       transports=TRANSPORTS) -> dict:
    """Issue one marked call per transport and report per-transport
    capability flags (DESIGN.md 5).

    issuer(transport, action_id, attempt) sends the marked tools/call;
    collector() returns the decision records emitted since the call. When
    action_id is None a per-transport probe id is used (so one transport's
    echo cannot satisfy another transport's assertion); an explicit
    action_id is used verbatim for every transport.
    """
    unknown = [t for t in transports if t not in TRANSPORTS]
    if unknown:
        raise ValueError(f"unknown transports {unknown!r} "
                         f"(known: {list(TRANSPORTS)})")
    per_transport = {}
    for transport in transports:
        probe_id = (action_id if action_id is not None
                    else f"fidelity-check:{transport}")
        issuer(transport, probe_id, attempt)
        records = [r for r in (collector() or []) if isinstance(r, dict)]
        echoing = [r for r in records
                  if r.get("action_id") == probe_id
                  and _attempt_of(r) == attempt]
        per_transport[transport] = {
            "action_id": probe_id,
            "attempt": attempt,
            "records_collected": len(records),
            "records_echoing": len(echoing),
            # the id appears in the emitted record (DESIGN.md 5); an emitted
            # record that does not echo it is a strip
            "result": "pass" if echoing else "fail",
            "ts": now_rfc3339_ms(),
        }
    return {
        "schema": 1,   # bare stamp (DESIGN.md 4: no type names in data files)
        "id": "fidelity-check",
        "status": ("pass" if all(v["result"] == "pass"
                                 for v in per_transport.values()) else "fail"),
        "preserves_meta": (per_transport["mcp_meta"]["result"] == "pass"
                           if "mcp_meta" in per_transport else None),
        "preserves_header": (per_transport["http_header"]["result"] == "pass"
                             if "http_header" in per_transport else None),
        "per_transport": per_transport,
        "attempt": attempt,
    }


def publish_fidelity_report(plugin_id: str, report: dict, *,
                             plugins_dir=None) -> Path:
    """Write plugins/<id>/fidelity.json (DESIGN.md 11 per-product capability
    facts): version-keyed entries (control version, transport, result,
    timestamp) taken from the plugin's immutable manifest version plus the
    check's per-transport results. Overwrites any previous verdict for the
    same control version (verdicts expire when the version changes; the
    control version in each entry is the expiry key)."""
    plugins_dir = (Path(plugins_dir) if plugins_dir is not None
                   else REPO_ROOT / "plugins")
    manifest_path = plugins_dir / plugin_id / "manifest.json"
    if not manifest_path.is_file():
        raise ValueError(f"unknown plugin {plugin_id!r} "
                         f"(no manifest at {manifest_path})")
    control_version = (json.loads(manifest_path.read_text(encoding="utf-8"))
                       .get("version") or "unknown")
    doc = {
        "schema": 1,   # bare stamp (DESIGN.md 4)
        "plugin": plugin_id,
        "control_version": control_version,
        "preserves_meta": report.get("preserves_meta"),
        "preserves_header": report.get("preserves_header"),
        "attempt": report.get("attempt"),
        "checks": [
            {"control_version": control_version, "transport": transport,
             "result": detail["result"], "timestamp": detail["ts"]}
            for transport, detail in sorted(report["per_transport"].items())
        ],
        "updated": now_rfc3339_ms(),
    }
    out = plugins_dir / plugin_id / "fidelity.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")
    return out


def load_fidelity_config(path, *, plugins_dir=None) -> dict:
    """Load and validate a fidelity-check config (the `guardscope fidelity`
    input). Fields: plugin (required; must be a registered control with a
    manifest), gateway_url (required; the endpoint the marked tools/call is
    issued at), transports (optional; subset of the checkable carriers,
    default both), schema (optional; must be the bare 1 stamp).

    The live issuer/collector wiring over the compose stack lands in a later
    pass; this validates the inputs only.
    """
    p = Path(path)
    try:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise FidelityConfigError(f"cannot read fidelity config {p}: {exc}")
    if not isinstance(doc, dict):
        raise FidelityConfigError("fidelity config must be a mapping")

    schema = doc.get("schema", 1)
    if schema != 1:
        raise FidelityConfigError(
            f"the schema stamp is the bare literal 1 (DESIGN.md 4); "
            f"got {schema!r}")

    plugin = doc.get("plugin")
    if not isinstance(plugin, str) or not plugin.strip():
        raise FidelityConfigError("plugin is required (the control the "
                                   "marked calls cross)")
    plugins_dir = (Path(plugins_dir) if plugins_dir is not None
                   else REPO_ROOT / "plugins")
    manifest = plugins_dir / plugin / "manifest.json"
    if not manifest.is_file():
        raise FidelityConfigError(f"unknown plugin {plugin!r} "
                                   f"(no manifest at {manifest})")
    manifest_doc = json.loads(manifest.read_text(encoding="utf-8"))
    if manifest_doc.get("kind") != "control":
        raise FidelityConfigError(
            f"plugin {plugin!r} is a {manifest_doc.get('kind')!r}, not a "
            f"control; the fidelity check marks calls through a control")

    gateway_url = doc.get("gateway_url")
    if not isinstance(gateway_url, str) or not gateway_url.strip():
        raise FidelityConfigError("gateway_url is required (the marked "
                                  "tools/call endpoint of the compose stack)")
    if not gateway_url.startswith(("http://", "https://")):
        raise FidelityConfigError(
            f"gateway_url must be an http(s) URL, got {gateway_url!r}")

    transports = doc.get("transports", list(TRANSPORTS))
    if not isinstance(transports, list) or not transports:
        raise FidelityConfigError("transports must be a non-empty list")
    unknown = [t for t in transports if t not in TRANSPORTS]
    if unknown:
        raise FidelityConfigError(f"unknown transports {unknown!r} "
                                   f"(known: {list(TRANSPORTS)})")

    return {"plugin": plugin, "gateway_url": gateway_url,
            "transports": list(transports),
            "control_version": manifest_doc.get("version")}
