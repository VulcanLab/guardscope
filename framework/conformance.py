"""The conformance kit (DESIGN.md 3 "two conformance levels", 11 "Registry
& governance").

DESIGN.md 3 defines the two levels verbatim:

  L1 (translation)   schema-valid records from a recorded canonical-run log
                     set + reconciliation to expected outcomes.
  L2 (native)        full lifecycle + correlation check; a `native` badge
                     requires L2 plus at least one harness-run path.

DESIGN.md 11 makes the kit registry-relevant: "Manifest verification
(declaring is not the same as conforming)" and verdicts are registry facts
keyed by (plugin version, contract version, framework line, suite version,
golden-fixture hash). Every verdict this module produces is a plain JSON
object carrying its own key components, suitable for registry ingestion.

L1 (run_l1) takes a recorded canonical-run log set — v0 AuditEntry lines
(the gateway decisions.jsonl format) or decision-record/1 lines, auto-detected
— validates every record against the schema, maps a v0 set through the same
reader-side mapping the runner uses (framework/records, DESIGN.md 4), runs
the C1-C4 reconcile (framework/reconcile) against the pinned baseline spec,
and compares per-action-class outcomes to the expected outcomes.

L2 (run_l2) drives a ControlContract implementer through the full lifecycle
per DESIGN.md 3 — provision, configure (the policy fingerprint asserted
against the emitted records' policy hash), ready (enforcement proven via
the runner-issued test action, never assumed), a canonical replay of the
design's inspected classes through the control, collect (flush ack, record
count), teardown (idempotent) — then runs L1 over the collected records AND
the fidelity check (framework/fidelity; per-transport capability flags are
published in the verdict, never trusted as manifest claims). L2 passes only
if the lifecycle, L1, and fidelity check all pass. The `native` badge
additionally requires at least one harness-run path: a run dir with a
non-empty dispatch stream (harness_run_evidence); absent or empty evidence
denies the badge with a reason while the verdict is still recorded.

Honesty rules (DESIGN.md 1: outcomes are derived only by the reconciler;
11: declaring is not conforming): L1 outcome labels are the golden run's
translation-level classification — L1 carries no kernel evidence of its
own, and the verdict says so. Nothing here trusts a manifest claim that a
check did not verify.
"""

import hashlib
import json
from pathlib import Path

import yaml

from framework.contracts import CONTROL_CONTRACT_VERSION, enforcement_ready
from framework.fidelity import run_fidelity_check
from framework.records import (
    RecordValidationError, V0_DEFAULT_PLUGIN, V0_DEFAULT_PRODUCT,
    audit_entry_to_decision_record, new_ulid, validate_decision_record,
)
from framework import reconcile as reconcile_lib

REPO_ROOT = Path(__file__).resolve().parent.parent

# The kit's own version (embedded in every verdict; DESIGN.md 11: the kit is
# core-shipped and its verdicts are registry facts).
KIT_VERSION = "1"

# The conformance suite version: the golden fixture set + expected outcomes
# this kit verifies against. Bumping it expires every recorded verdict keyed
# to the previous suite (DESIGN.md 11: verdicts expire when any key changes).
SUITE_VERSION = "1"

# The framework line the verdict was recorded under (DESIGN.md 11 verdict
# key). There is no public release yet; this is the development line that
# shipped the kit, and a public release line replaces the value at the first
# release.
FRAMEWORK_LINE = "m2"

# The pinned baseline spec (baseline-15, the only registered workload pack
# this pass, DESIGN.md 8): the canonical action surface every golden set is
# reconciled against.
BASELINE_SPEC = REPO_ROOT / "trace" / "traces" / "baseline.yaml"

# The suite's canonical golden fixture this pass: the trimmed live t1 run
# (the AGT gateway's recorded v0 AuditEntry log + run manifest + outcomes,
# copied from the 2026-10-28 acceptance run; the log's sha256 matches the
# artifact hash recorded in its own manifest). DESIGN.md 2 places golden
# fixtures in the core science layer; this one lives under tests/fixtures as
# recorded live-run data until the suite grows a core golden/ directory.
SUITE_GOLDEN_RUN_DIR = (REPO_ROOT / "tests" / "fixtures" / "live-runs"
                        / "t1-pi-t1-2")

# Expected per-action-class outcomes for the t1 golden fixture: the live run
# classified 4 http_tool_call actions checked-allowed and the 11 actions of
# the non-inspected classes bypassed (the recorded outcomes.json carries the
# same counts). Compact form: one outcome per class, expanded against the
# spec's per-class ground truth.
T1_EXPECTED_OUTCOMES = {
    "http_tool_call": "checked-allowed",
    "stdio_tool_call": "bypassed",
    "direct_network": "bypassed",
    "process_spawn": "bypassed",
    "file_write": "bypassed",
    "credential_access": "bypassed",
}

# The reference policy L2 configures when the caller pins none: it denies
# nothing (the readiness tool is always denied by the reference lifecycle
# itself), so every replayed action is checked-allowed and the expected
# outcomes decide the verdict.
L2_REFERENCE_POLICY = {
    "policy_id": "l2-reference",
    "policy_version": "1",
    "deny_tools": [],
}

# Candidate log paths inside a recorded run dir (the live layout keeps the
# gateway log under gateway/; the trimmed fixture is flat).
_GOLDEN_LOG_CANDIDATES = (
    "decisions.jsonl",
    "gateway/decisions.jsonl",
    "decision-records.jsonl",
    "gateway/decision-records.jsonl",
)

# Format identifiers of the two accepted golden-log line shapes.
FORMAT_V0 = "v0-audit-entry"
FORMAT_RECORD = "decision-record/1"


class ConformanceError(ValueError):
    """The golden log set or expected outcomes are not usable as given."""


def _load_baseline_spec(path: Path = BASELINE_SPEC) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


# --- golden log sets --------------------------------------------------------------


def _read_jsonl(path: Path) -> tuple[list[dict], list[str]]:
    """Parse a JSONL log; malformed lines are problems, never silent drops."""
    lines, problems = [], []
    for i, raw in enumerate(Path(path).read_text(encoding="utf-8")
                             .splitlines(), 1):
        line = raw.strip()
        if not line:
            continue
        try:
            parsed = json.loads(line)
        except json.JSONDecodeError as exc:
            problems.append(f"line {i}: not JSON ({exc})")
            continue
        lines.append(parsed)
    return lines, problems


def golden_log_set_from_run_dir(run_dir, *, plugin_id,
                                 plugin_version: str | None = None,
                                 product: str | None = None,
                                 product_version: str | None = None,
                                 slot_id: str = "gateway") -> dict:
    """Build a golden log set from a recorded canonical-run directory.

    Reads the decision log (first of _GOLDEN_LOG_CANDIDATES present) and the
    run manifest (run_id, design, the measurement window, the deployed
    product version). The v0 producer identity for the mapping comes from
    the arguments: plugin_id (required), plugin_version (default: the
    plugin's manifest version under plugins/), product (default: the AGT
    product for the AGT plugin, else the plugin id), product_version
    (default: the run manifest's gateway package version).
    """
    run_dir = Path(run_dir)
    log_path = next((run_dir / rel for rel in _GOLDEN_LOG_CANDIDATES
                     if (run_dir / rel).is_file()), None)
    if log_path is None:
        raise ConformanceError(
            f"no golden log under {run_dir} (looked for "
            f"{list(_GOLDEN_LOG_CANDIDATES)})")
    manifest_path = run_dir / "manifest.json"
    if not manifest_path.is_file():
        raise ConformanceError(
            f"no run manifest at {manifest_path} (the golden set needs the "
            f"run_id, design, and measurement window)")
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    lines, problems = _read_jsonl(log_path)
    versions = manifest.get("versions") or {}
    if plugin_version is None:
        manifest_json = (REPO_ROOT / "plugins" / plugin_id / "manifest.json")
        plugin_version = (json.loads(manifest_json.read_text(
            encoding="utf-8"))["version"] if manifest_json.is_file()
            else "unknown")
    return {
        "format": "auto",
        "lines": lines,
        "parse_problems": problems,
        "source": log_path.name,
        "run_id": manifest.get("run_id") or run_dir.name,
        "design": manifest.get("design"),
        "window": ((manifest.get("timing") or {}).get("window_epoch_ns")),
        "window_slack_ns": 1_000_000_000,
        "stream": {
            "slot_id": slot_id,
            "plugin": plugin_id,
            "plugin_version": plugin_version,
            "product": (product if product is not None
                        else (V0_DEFAULT_PRODUCT if plugin_id == V0_DEFAULT_PLUGIN
                              else plugin_id)),
            "product_version": (product_version if product_version is not None
                               else versions.get("gateway_package_version",
                                                 "unknown")),
        },
    }


def normalize_golden_log_set(golden_log_set, *, plugin_id: str | None = None,
                             plugin_version: str | None = None) -> dict:
    """Accept the dict form, a recorded run dir path, or a JSONL file path;
    return the dict form (a copy)."""
    if isinstance(golden_log_set, dict):
        golden = dict(golden_log_set)
        golden.setdefault("format", "auto")
        golden.setdefault("lines", [])
        golden.setdefault("parse_problems", [])
        golden.setdefault("window", None)
        # The golden-set key is window_slack_ns: it is covered by
        # golden_fixture_hash, which the seeded registry verdict
        # (registry/open/agt-gateway.json) pins, so the recorded key name
        # stays; accept the renamed key from newer callers too.
        if "window_slack_ns" not in golden:
            golden["window_slack_ns"] = golden.get(
                "window_tolerance_ns", 1_000_000_000)
        golden.setdefault("window_slack_ns", 1_000_000_000)
        return golden
    if isinstance(golden_log_set, (str, Path)):
        path = Path(golden_log_set)
        if path.is_dir():
            if plugin_id is None:
                raise ConformanceError(
                    "a run-dir golden set needs plugin_id (the plugin "
                    "under test)")
            return golden_log_set_from_run_dir(path, plugin_id=plugin_id,
                                               plugin_version=plugin_version)
        if path.is_file():
            lines, problems = _read_jsonl(path)
            return {"format": "auto", "lines": lines,
                    "parse_problems": problems, "source": path.name,
                    "run_id": None, "design": None, "window": None,
                    "window_slack_ns": 1_000_000_000, "stream": {}}
    raise ConformanceError(
        "golden_log_set must be the dict form, a recorded run dir, or a "
        f"JSONL file; got {type(golden_log_set).__name__}")


def _canonical_json(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False)


def golden_fixture_hash(golden_log_set) -> str:
    """The golden-fixture component of the verdict key (DESIGN.md 11): a
    sha256 over the canonical form of the golden set (its lines and the run
    context that scopes them). Any change to the log or its context changes
    the hash and expires recorded verdicts."""
    golden = normalize_golden_log_set(golden_log_set)
    return hashlib.sha256(_canonical_json({
        "format": golden.get("format"),
        "lines": golden.get("lines"),
        "run_id": golden.get("run_id"),
        "design": golden.get("design"),
        "window": golden.get("window"),
        "window_slack_ns": golden.get("window_slack_ns"),
        "stream": golden.get("stream"),
    }).encode("utf-8")).hexdigest()


def suite_golden_log_set() -> dict:
    """The suite's canonical golden fixture (see SUITE_GOLDEN_RUN_DIR)."""
    return golden_log_set_from_run_dir(SUITE_GOLDEN_RUN_DIR,
                                        plugin_id=V0_DEFAULT_PLUGIN)


def suite_golden_fixture_hash() -> str:
    return golden_fixture_hash(suite_golden_log_set())


# --- L1 (translation, DESIGN.md 3) ------------------------------------------------


def _detect_format(line) -> str | None:
    if not isinstance(line, dict):
        return None
    if line.get("schema") == 1 and "decision" in line \
            and "enforcement_point" in line:
        return FORMAT_RECORD
    if "tool_name" in line and isinstance(line.get("allowed"), bool):
        return FORMAT_V0
    return None


def _normalize_expected(expected_outcomes: dict, spec: dict) -> dict:
    """Expand the compact form (class -> one outcome string for every spec
    instance of the class) against the spec's per-class ground truth; the
    explicit form (class -> {outcome: count}) passes through."""
    gt: dict[str, int] = {}
    for a in spec.get("actions", []):
        gt[a["class"]] = gt.get(a["class"], 0) + 1
    out = {}
    for cls, value in (expected_outcomes or {}).items():
        if isinstance(value, str):
            out[cls] = {value: gt.get(cls)}
        elif isinstance(value, dict):
            out[cls] = dict(value)
        else:
            raise ConformanceError(
                f"expected outcome for {cls!r} must be an outcome string or "
                f"an {{outcome: count}} mapping; got {value!r}")
    return out


def _derived_outcomes(report: dict | None) -> dict:
    """Per-action-class outcome counts derived from the C1-C4 report
    (reconciler-only derivation, DESIGN.md 1, 4): evaluated actions are
    checked (allowed/denied); actions of a class the design does not
    inspect are bypassed (the design's topology: no enforcement point on
    the class); an inspected action with no decision is uncovered (the C3
    failure territory). L1 carries no kernel evidence — the labels are the
    translation-level classification, recorded as such in the verdict."""
    derived: dict[str, dict[str, int]] = {}
    for row in (report or {}).get("per_action") or []:
        if row.get("evaluated"):
            outcome = ("checked-allowed" if row.get("allowed")
                       else "checked-denied")
        elif row.get("crosses_enforcement_point"):
            outcome = "uncovered"
        else:
            outcome = "bypassed"
        derived.setdefault(row["class"], {})
        derived[row["class"]][outcome] = \
            derived[row["class"]].get(outcome, 0) + 1
    return derived


def _run_l1_core(golden: dict, expected_outcomes: dict, *, plugin_id,
                 plugin_version, suite_version: str, spec: dict) -> dict:
    """The L1 engine over a normalized golden set (see run_l1)."""
    checks = []

    def check(cid: str, ok: bool, detail: str) -> None:
        checks.append({"id": cid, "status": "pass" if ok else "fail",
                       "detail": detail})

    # -- the log lines -----------------------------------------------------
    lines = list(golden.get("lines") or [])
    problems = list(golden.get("parse_problems") or [])
    check("L1-parse", not problems,
          f"{len(lines)} golden log line(s) parsed" if not problems
          else "; ".join(problems))

    # -- format auto-detection (v0 AuditEntry vs decision-record/1) --------
    detected = [_detect_format(l) for l in lines]
    present = {f for f in detected if f}
    unknown = [i + 1 for i, f in enumerate(detected) if f is None]
    fmt = None
    if len(lines) == 0:
        check("L1-format", False, "the golden log set is empty")
    elif unknown:
        check("L1-format", False,
              f"line(s) {unknown} match neither the v0 AuditEntry nor the "
              f"decision-record/1 shape")
    elif len(present) > 1:
        check("L1-format", False,
              f"mixed formats in one golden set: {sorted(present)} (a "
              f"golden set is one recorded stream)")
    else:
        fmt = present.pop()
        check("L1-format", True,
              f"auto-detected {fmt} ({len(lines)} lines)")

    # -- schema validity (every record, DESIGN.md 3 L1) --------------------
    records: list[dict] = []
    record_problems: list[str] = []
    if fmt == FORMAT_V0:
        # the same reader-side mapping the runner uses (DESIGN.md 4: the v0
        # format stays a valid input; the mapped record carries ingested
        # provenance pointing back at the original line)
        stream = dict(golden.get("stream") or {})
        run_id = golden.get("run_id") or "golden-run"
        slot_id = stream.get("slot_id", "gateway")
        stream_id = stream.get("stream_id") or f"{run_id}:{slot_id}"
        for i, entry in enumerate(lines):
            try:
                records.append(audit_entry_to_decision_record(
                    entry, run_id=run_id, stream_id=stream_id, seq=i,
                    product_version=stream.get("product_version", "unknown"),
                    plugin_version=(plugin_version if plugin_version is not None
                                    else stream.get("plugin_version",
                                                    "unknown")),
                    plugin=stream.get("plugin", plugin_id),
                    product=stream.get("product", plugin_id),
                    slot_id=slot_id,
                    source=golden.get("source", "decisions.jsonl"),
                    line=i + 1))
            except RecordValidationError as exc:
                record_problems.append(f"line {i + 1}: {exc}")
    elif fmt == FORMAT_RECORD:
        for i, record in enumerate(lines):
            try:
                validate_decision_record(record)
                records.append(record)
            except RecordValidationError as exc:
                record_problems.append(f"line {i + 1}: {exc}")
    elif fmt is None and golden.get("format") not in ("auto", None):
        check("L1-schema", False,
              f"the golden set declares format {golden['format']!r} but the "
              f"lines do not match it")
    check("L1-schema", not record_problems,
          f"{len(records)} record(s) valid against decision-record/1"
          if not record_problems else "; ".join(record_problems))

    # -- the records declare the plugin under test --------------------------
    bad_producer = [
        f"line {i + 1}: producer {((r.get('producer') or {}).get('plugin'))!r}"
        f"/{((r.get('producer') or {}).get('plugin_version'))!r}"
        for i, r in enumerate(records)
        if ((r.get("producer") or {}).get("plugin") != plugin_id
            or (r.get("producer") or {}).get("plugin_version")
            != plugin_version)]
    check("L1-producer", not bad_producer,
          f"every record declares producer {plugin_id}/{plugin_version}"
          if not bad_producer else "; ".join(bad_producer))

    # -- the C1-C4 reconcile over the pinned baseline spec ------------------
    design = golden.get("design")
    report = None
    if design is None:
        check("L1-reconcile", False,
              "the golden set carries no design (the C1-C4 topology input)")
    else:
        try:
            entries = reconcile_lib.decision_records_to_log_entries(records)
        except ValueError as exc:
            check("L1-reconcile", False, f"record->log-view mapping: {exc}")
            entries = None
        if entries is not None:
            window = golden.get("window")
            window_pair = ((int(window["start"]), int(window["end"]))
                           if window else None)
            try:
                report = reconcile_lib.compute(
                    spec, entries, problems, design, window_pair,
                    int(golden.get("window_slack_ns") or 1_000_000_000))
            except ValueError as exc:
                check("L1-reconcile", False, str(exc))
            else:
                checks.extend(report.get("checks") or [])

    # -- per-action-class outcomes vs the expected outcomes -----------------
    derived = _derived_outcomes(report)
    expected = _normalize_expected(expected_outcomes, spec)
    mismatches = []
    for cls in sorted(set(expected) | set(derived)):
        exp = expected.get(cls)
        got = derived.get(cls, {})
        if exp != got:
            mismatches.append(f"{cls}: expected {exp}, derived {got}")
    check("L1-outcomes", not mismatches,
          "derived per-class outcomes match the expected outcomes "
          f"({len(derived)} class(es))" if not mismatches
          else "; ".join(mismatches))

    findings = [c for c in checks if c["status"] != "pass"]
    return {
        "level": "L1",
        "kit_version": KIT_VERSION,
        "plugin_id": plugin_id,
        "plugin_version": plugin_version,
        "suite_version": suite_version,
        # the verdict key components (DESIGN.md 11): a verdict is valid only
        # for the exact key it was recorded under
        "contract_version": CONTROL_CONTRACT_VERSION,
        "framework_line": FRAMEWORK_LINE,
        "golden_fixture_hash": golden_fixture_hash(golden),
        "golden_set": {
            "run_id": golden.get("run_id"),
            "design": design,
            "window": golden.get("window"),
            "format": fmt,
            "lines": len(lines),
            "records": len(records),
        },
        "checks": checks,
        "findings": findings,
        "derived_outcomes": derived,
        "coverage": (report or {}).get("coverage"),
        "status": "pass" if not findings else "fail",
    }


def run_l1(golden_log_set, expected_outcomes, *, plugin_id, plugin_version,
           suite_version: str, spec: dict | None = None) -> dict:
    """L1 translation conformance (DESIGN.md 3): validate a recorded
    canonical-run log set against decision-record/1 (a v0 set runs through
    the reader-side mapping first), reconcile it through C1-C4 against the
    pinned baseline spec, and compare per-action-class outcomes to the
    expected outcomes. Returns a structured verdict (JSON, registry-ready).
    """
    if not plugin_id:
        raise ConformanceError("plugin_id (the plugin under test) is required")
    golden = normalize_golden_log_set(golden_log_set, plugin_id=plugin_id,
                                      plugin_version=plugin_version)
    return _run_l1_core(golden, expected_outcomes, plugin_id=plugin_id,
                        plugin_version=plugin_version,
                        suite_version=suite_version,
                        spec=spec if spec is not None
                        else _load_baseline_spec())


# --- L2 (native, DESIGN.md 3) ------------------------------------------------------


def _harness_run_badge(harness_run_evidence) -> dict:
    """The `native` badge gate (DESIGN.md 3: a native badge requires L2 plus
    at least one harness-run path). The evidence is a path to a run dir with
    a non-empty dispatch stream; absent or empty evidence denies the badge
    with a reason and the verdict is still recorded."""
    if harness_run_evidence is None:
        return {"native": False,
                "reason": "no harness-run evidence supplied: the native "
                          "badge requires at least one harness-run path "
                          "(DESIGN.md 3)",
                "evidence": None}
    path = Path(harness_run_evidence)
    stream = path if path.is_file() else path / "dispatch-records.jsonl"
    if not stream.is_file():
        return {"native": False,
                "reason": f"no dispatch stream at {stream}: the native badge "
                          f"requires a harness-run path (DESIGN.md 3)",
                "evidence": str(path)}
    from framework.records import validate_dispatch_record
    valid = 0
    for raw in stream.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            validate_dispatch_record(json.loads(line))
            valid += 1
        except (ValueError, RecordValidationError):
            pass
    if valid == 0:
        return {"native": False,
                "reason": f"the dispatch stream at {stream} carries no "
                          f"valid dispatch-record/1 line: the badge is "
                          f"denied, the verdict is still recorded",
                "evidence": str(path)}
    return {"native": True,
            "reason": f"{valid} dispatch record(s) in the harness run at "
                      f"{path} (at least one harness-run path, DESIGN.md 3)",
            "evidence": str(path)}


def run_l2(control, *, issuer, collector, golden_log_set, expected_outcomes,
           suite_version: str, harness_run_evidence=None,
           policy_descriptor: dict | None = None, issue_action=None,
           plugins_dir=None, spec: dict | None = None) -> dict:
    """L2 native conformance (DESIGN.md 3): drive the FULL control lifecycle
    (provision -> configure -> ready -> canonical replay -> collect ->
    teardown), run L1 over the collected records AND the correlation
    fidelity check, and gate the `native` badge on harness-run evidence.

    golden_log_set: dict or JSONL-path form only (the run-dir form needs
        plugin_id, which run_l2 does not receive; use run_l1 for that form).
    control: a ControlContract implementer (InProcessControl works for
    tests). issuer/collector: the fidelity-check interfaces (framework/fidelity;
    issuer(transport, action_id, attempt), collector() -> records emitted
    since). golden_log_set: the golden fixture providing the design (the
    topology that decides which classes cross) and the verdict's
    golden-fixture hash. policy_descriptor: the policy to configure
    (default: L2_REFERENCE_POLICY, deny nothing). issue_action: how to drive
    one action through the control's enforcement point (default: the
    control's own evaluate, the in-process path; a live topology wires the
    runner's injection here). plugins_dir: when given and the plugin ships a
    manifest there, the fidelity capability flags are published to
    plugins/<id>/fidelity.json (framework/fidelity).
    """
    from framework.fidelity import publish_fidelity_report

    golden = normalize_golden_log_set(golden_log_set)
    spec = spec if spec is not None else _load_baseline_spec()
    design = golden.get("design")
    run_id = f"l2-{new_ulid()}"
    checks = []

    def check(cid: str, ok: bool, detail: str) -> None:
        checks.append({"id": cid, "status": "pass" if ok else "fail",
                       "detail": detail})

    def run_step(cid: str, fn, ok=lambda r: True, detail=lambda r: str(r)):
        """One lifecycle step: a contract violation (exception or failed
        assertion) is a finding in the verdict, never a crash — a conformance
        run completes so the findings picture is whole."""
        try:
            result = fn()
            check(cid, bool(ok(result)), str(detail(result)))
            return result
        except Exception as exc:   # noqa: BLE001 — record, don't crash
            check(cid, False, f"{type(exc).__name__}: {exc}")
            return None

    # -- describe (DESIGN.md 3) ---------------------------------------------
    described = run_step("L2-describe", control.describe,
                        ok=lambda d: isinstance(d, dict)
                        and bool(d.get("plugin")) and bool(d.get("plugin_version"))
                        and bool(d.get("record_source"))
                        and d.get("can_enforce") in ("enforce", "observe"),
                        detail=lambda d: f"plugin {d.get('plugin')!r}/"
                                         f"{d.get('plugin_version')!r}, "
                                         f"record_source "
                                         f"{d.get('record_source')!r}")
    described = described if isinstance(described, dict) else {}
    plugin_id = described.get("plugin")
    plugin_version = described.get("plugin_version")

    # -- provision (DESIGN.md 3: slot-typed, runner-assigned stream id) -----
    slot = {"id": "l2-control", "kind": (described.get("slot_kinds")
                                         or ["embedded"])[0],
            "stream_id": f"{run_id}:control", "run_id": run_id}
    provisioned = run_step(
        "L2-provision", lambda: control.provision(slot),
        ok=lambda r: isinstance(r, dict) and bool(r.get("handle"))
        and (r.get("attach") or {}).get("stream_id") == slot["stream_id"],
        detail=lambda r: f"handle {r.get('handle')!r}, attach "
                         f"{r.get('attach')!r}")

    # -- configure (DESIGN.md 3: idempotent, returns a policy fingerprint) --
    descriptor = policy_descriptor or dict(L2_REFERENCE_POLICY)
    fingerprint = run_step(
        "L2-configure", lambda: control.configure(descriptor),
        ok=lambda r: isinstance(r, str) and r != "",
        detail=lambda r: f"policy fingerprint {r!r}")

    # -- ready (DESIGN.md 3: enforcement proven, never assumed) -------------
    has_evaluate = hasattr(control, "evaluate")
    readiness_note = None
    if has_evaluate:
        run_step("L2-ready-proof",
                 lambda: enforcement_ready(control, None),
                 ok=lambda r: r is True,
                 detail=lambda r: ("the runner-issued test action produced "
                                   "its deny decision record (DESIGN.md 3)"
                                   if r else
                                   "the readiness test action did not "
                                   "produce a deny decision record: "
                                   "enforcement is not proven"))
    else:
        readiness_note = ("the control exposes no in-process enforcement "
                          "point (no evaluate), so the kit could only call "
                          "ready() itself; an independent runner-issued "
                          "test-action proof requires the runner topology")
    run_step("L2-ready", control.ready, ok=lambda r: r is True,
             detail=lambda r: "ready()" if r else
                               "ready() did not pass")
    # the capture window opens only after readiness (DESIGN.md 9): flush the
    # readiness records so the replay's collected stream is the window
    flushed = run_step(
        "L2-window", control.collect,
        ok=lambda r: isinstance(r, dict) and r.get("flush_ack") is True,
        detail=lambda r: f"{r.get('record_count')} readiness/organic "
                         f"record(s) flushed before the window opened")

    # -- the canonical replay of the design's inspected classes -------------
    inspected = reconcile_lib.INSPECTED_CLASSES.get(design, set())
    actions = [a for a in spec.get("actions", [])
               if a.get("class") in inspected]
    issue = issue_action or (control.evaluate if has_evaluate else None)

    def _replay():
        for action in actions:
            issue({"action_id": action["id"],
                   # canonical action -> the enforcement point's tool name
                   # (the same inverse routing the C1-C4 log view uses)
                   "tool": reconcile_lib._tool_for(action) or action["op"],
                   "class": action["class"],
                   "protocol": ("http" if action["class"] == "http_tool_call"
                                 else "stdio"),
                   "parameters": action.get("args") or {}})
        return len(actions)

    if issue is None:
        check("L2-replay", False,
              "no in-process enforcement point (control.evaluate) and no "
              "issue_action: the kit cannot drive the canonical replay; a "
              "live L2 run goes through the runner topology")
    elif design is None:
        check("L2-replay", False,
              "the golden set carries no design (the replay topology input)")
    else:
        run_step("L2-replay", _replay,
                 ok=lambda n: n == len(actions),
                 detail=lambda n: f"{n} action(s) of the design's inspected "
                                  f"classes {sorted(inspected)} driven "
                                  f"through the control")

    # -- collect (DESIGN.md 3: flush-then-report) ---------------------------
    collected = run_step(
        "L2-collect", control.collect,
        ok=lambda r: isinstance(r, dict) and r.get("flush_ack") is True
        and r.get("record_count") == len(actions)
        and r.get("record_count") == len(r.get("records") or []),
        detail=lambda r: f"record_count {r.get('record_count')} (driven "
                         f"{len(actions)}), seq_range {r.get('seq_range')}, "
                         f"flush_ack {r.get('flush_ack')}")
    records = (collected or {}).get("records") or []

    # -- the policy fingerprint asserted against the emitted records --------
    mismatched = [r.get("record_id") or i for i, r in enumerate(records)
                  if ((r.get("policy") or {}).get("policy_hash")
                      != fingerprint)]
    check("L2-policy-fingerprint",
          bool(records) and fingerprint is not None and not mismatched,
          f"every emitted record's policy.policy_hash matches the "
          f"configure() fingerprint" if not mismatched else
          f"record(s) {mismatched} carry a policy hash that does not match "
          f"the configure() fingerprint {fingerprint!r} (DESIGN.md 3)")

    # -- the correlation fidelity check (DESIGN.md 5, gating) --------------
    fidelity = run_step("L2-fidelity",
                        lambda: run_fidelity_check(issuer, collector),
                        ok=lambda r: isinstance(r, dict)
                        and r.get("status") == "pass",
                        detail=lambda r: f"status {r.get('status')}, "
                                         f"preserves_meta "
                                         f"{r.get('preserves_meta')}, "
                                         f"preserves_header "
                                         f"{r.get('preserves_header')}")
    fidelity = fidelity if isinstance(fidelity, dict) else {}
    published_to = None
    if plugins_dir is not None and plugin_id:
        manifest = Path(plugins_dir) / plugin_id / "manifest.json"
        if manifest.is_file():
            published_to = run_step(
                "L2-fidelity-publish",
                lambda: publish_fidelity_report(
                    plugin_id, fidelity, plugins_dir=plugins_dir),
                ok=lambda p: p is not None,
                detail=lambda p: f"capability flags published to {p}")

    # -- teardown (DESIGN.md 3: crash-safe, idempotent) -----------------------
    def _teardown():
        control.teardown()
        control.teardown()   # idempotent: the second call must not raise
    run_step("L2-teardown", _teardown,
             detail=lambda r: "teardown ran twice without error (idempotent, "
                              "DESIGN.md 3)")

    # -- L1 over the collected records (the same engine, native records) ----
    l1 = _run_l1_core(
        {"format": FORMAT_RECORD, "lines": records, "parse_problems": [],
         "source": "collected", "run_id": run_id, "design": design,
         "window": None, "window_slack_ns": 1_000_000_000,
         "stream": {"plugin": plugin_id, "plugin_version": plugin_version}},
        expected_outcomes, plugin_id=plugin_id, plugin_version=plugin_version,
        suite_version=suite_version, spec=spec)

    badge = _harness_run_badge(harness_run_evidence)
    lifecycle_findings = [c for c in checks if c["status"] != "pass"]
    findings = lifecycle_findings + list(l1.get("findings") or [])
    return {
        "level": "L2",
        "kit_version": KIT_VERSION,
        "plugin_id": plugin_id,
        "plugin_version": plugin_version,
        "suite_version": suite_version,
        "contract_version": CONTROL_CONTRACT_VERSION,
        "framework_line": FRAMEWORK_LINE,
        # the verdict key's golden fixture: the suite fixture the
        # expectations were pinned against (DESIGN.md 11)
        "golden_fixture_hash": golden_fixture_hash(golden),
        "lifecycle": {
            "run_id": run_id,
            "design": design,
            "slot": slot,
            "provisioned": provisioned is not None,
            "policy_fingerprint_matched": not mismatched,
            "readiness_note": readiness_note,
            "driven_actions": len(actions),
            "records_collected": len(records),
            "records_flushed_before_window": ((flushed or {}).get(
                "record_count") if isinstance(flushed, dict) else None),
            "fidelity_published_to": (str(published_to)
                                      if published_to else None),
            "harness_run_evidence": badge["evidence"],
        },
        "describe": described,
        "checks": checks,
        "l1": l1,
        "fidelity": fidelity,
        # the measured, per-control capability flags (DESIGN.md 5: never a
        # contract assumption)
        "capability_flags": {
            "preserves_meta": fidelity.get("preserves_meta"),
            "preserves_header": fidelity.get("preserves_header"),
        },
        "badge": badge,
        "findings": findings,
        "status": ("pass" if not findings and l1.get("status") == "pass"
                    and fidelity.get("status") == "pass" else "fail"),
    }
