"""Experiment execution wiring (DESIGN.md 6, 9): experiment file -> live
runs -> framework artifacts.

execute_experiment() is the bridge between the experiment-file layer and the
runner machinery:

1. load + validate the experiment (framework/experiment.py, DESIGN.md 6);
   load-time errors propagate unchanged;
2. expand the plan (resolve()): one run descriptor per requested design;
3. drive each run through an injectable executor (default: a thin adapter
   over runner/run.py's run_design, the programmatic entry extracted for
   this purpose; the runner CLI is unchanged);
4. assemble the framework run manifest per run: the experiment file hash,
   the resolved fields including defaults_applied (DESIGN.md 6: recorded
   defaults are facts), the fixture fingerprint (base compose file id +
   sha256, the control-binding overlay's sha256 when the run binds one,
   plus enforcement_config when the design deploys one; DESIGN.md 7
   base+overlay, DESIGN.md 10 comparability key), plugin versions (plugins/*/manifest.json), the
   sensor version (env/versions.env; the runner-managed measuring
   instrument, informational only, DESIGN.md 9), the decision records
   (mapped to decision-record/1 via the v0 AuditEntry reader-side mapping,
   DESIGN.md 4, written to <out_root>/<run-id>/decision-records.jsonl), the
   C1-C4 coverage recomputed over the mapped records (framework/reconcile)
   with a consistency assertion against the coverage the run itself
   computed (a mismatch is a finding, never silently trusted, DESIGN.md 9),
   C5 id consistency (framework/c5.py) and C6 denial effectiveness
   (framework/c6.py) with their findings, the outcome counts with a
   verified flag (kernel corroboration; DESIGN.md 9: the primary reported
   numbers come from verified results only), the evidence class, and
   degraded flags.

Degraded no-eBPF mode (DESIGN.md 9: the default path for users without
kernel privileges): sensor=False skips the runner's sensor entirely; every
output of such a run is labeled self-reported / unverified, C6 is skipped
with a note (never a finding), and `prevented` outcome entries are marked
as unverified claims: prevented is an outside-the-policy block whose
effect-absence half needs the sensor to verify (claims never
self-upgrade).

The execution path assumes the Linux testbed host (Docker, compose, arm64);
unit tests inject a fake run_executor so nothing here calls Docker.
"""

import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from framework.experiment import (  # noqa: E402
    ResolvedExperiment, RunDescriptor, load_experiment, resolve,
)
from framework.records import (  # noqa: E402
    V0_DEFAULT_PLUGIN, V0_DEFAULT_PRODUCT, map_audit_entries,
    now_rfc3339_ms,
)
from framework.overlay import MOCK_HARNESS_ID, overlay_abs_path  # noqa: E402
from framework import reconcile as reconcile_lib  # noqa: E402
from framework.workdir import resolve_workdir  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parent.parent
COMPOSE_DIR = REPO_ROOT / "compose"
VERSIONS_ENV = REPO_ROOT / "env" / "versions.env"
# baseline-15 is the only registered workload pack this pass (DESIGN.md 8);
# the canonical trace spec is its content and the denominator of every
# coverage number.
BASELINE_SPEC = REPO_ROOT / "trace" / "traces" / "baseline.yaml"

# DESIGN.md 9: evidence class of a run driven through the real harness.
# Mock-harness runs are a DIFFERENT evidence class (DESIGN.md 8, 9: "mock-
# run"; "Harness-run and mock-run cells are reported separately, never
# aggregated"): the mock harness is the path-originator fixture, so a run
# driven through it is labeled mock-run everywhere (run summary, execution
# manifest, merged report). A run without kernel evidence (the degraded
# no-eBPF mode) is self-reported (DESIGN.md 9: "every output it produces is
# labeled self-reported / unverified") regardless of which harness drove
# it — claims never self-upgrade, and mock-run still requires kernel
# confirmation ("the path exists and escapes, kernel-confirmed").
EVIDENCE_CLASS = "harness-run"
EVIDENCE_CLASS_MOCK = "mock-run"
EVIDENCE_CLASS_SELF_REPORTED = "self-reported"

# DESIGN.md 8: the harness whose runs carry the mock-run evidence class
# (framework/overlay.py MOCK_HARNESS_ID; the constant lives with the
# fixture/overlay machinery).


def _profile_window_tolerance(harness: str) -> int:
    """The harness profile's window tolerance (runner/profiles/<h>.yaml); the
    run's own coverage used it, so the recompute must too."""
    profile = yaml.safe_load((REPO_ROOT / "runner" / "profiles" /
                              f"{harness}.yaml").read_text())
    return int(profile.get("window_tolerance_ns", 1_000_000_000))

# The deployed policy artifact per design: the enforcement_config component
# of the fixture fingerprint (DESIGN.md 10: "fixture fingerprint, including
# enforcement_config"). t4/t5 run the harness allow-all permission chain v1
# with no policy file; t0 has no enforcement point at all.
ENFORCEMENT_CONFIG_FILES = {
    "t1": "gateway/policy.yaml",
    "t2": "gateway/policy.yaml",
    "t3": "gateway/policy-t3.yaml",
}

# Harness-intrinsic (t6): the in-process policy mounted into the harness
# adapter's container; pi and openclaw ship separate copies.
def _enforcement_config_file(design: str, harness: str):
    if design == "t6":
        return f"harnesses/{harness}/config/t6-policy.json"
    return ENFORCEMENT_CONFIG_FILES.get(design)

# Harness record streams (t4/t5/t6): the decision log is written by the
# harness adapter, so the producer identity comes from the harness side.
# (product key, version key) in env/versions.env.
HARNESS_PRODUCT_KEYS = {
    "pi": ("PI_PACKAGE", "PI_VERSION"),
    "openclaw": ("OPENCLAW_IMAGE", "OPENCLAW_VERSION"),
}

SENSOR_ABSENT = "sensor-absent"


# --- data types -----------------------------------------------------------------


@dataclass
class RunSummary:
    """The framework view of one executed run (DESIGN.md 9 output + the
    per-run facts DESIGN.md 6 asks the manifest to record)."""
    run_id: str
    design: str
    fixture: str
    control: str | None
    control_binding: str
    harness: str
    workload: str
    off_matrix: bool
    observation_only: bool
    run_dir: str
    run_record: str | None
    decision_records: str
    decision_record_count: int
    fixture_fingerprint: dict
    evidence_class: str
    degraded: list[str]
    status: str
    coverage: dict | None
    coverage_consistent: bool | None
    findings: list[dict]
    effective_counts: dict | None = None
    ground_truth_counts: dict | None = None
    spec_sha256: str | None = None
    c5: dict | None = None
    c6: dict | None = None
    outcome_counts: dict | None = None

    def to_dict(self) -> dict:
        return {
            "run_id": self.run_id,
            "design": self.design,
            "fixture": self.fixture,
            "control": self.control,
            "control_binding": self.control_binding,
            "harness": self.harness,
            "workload": self.workload,
            "off_matrix": self.off_matrix,
            "observation_only": self.observation_only,
            "run_dir": self.run_dir,
            "run_record": self.run_record,
            "decision_records": {"path": self.decision_records,
                                 "count": self.decision_record_count},
            "fixture_fingerprint": self.fixture_fingerprint,
            "evidence_class": self.evidence_class,
            "degraded": list(self.degraded),
            "status": self.status,
            "coverage": self.coverage,
            "coverage_consistent": self.coverage_consistent,
            "findings": list(self.findings),
            "effective_counts": self.effective_counts,
            "ground_truth_counts": self.ground_truth_counts,
            "spec_sha256": self.spec_sha256,
            "c5": self.c5,
            "c6": self.c6,
            "outcome_counts": self.outcome_counts,
        }


@dataclass
class ExecutionResult:
    experiment: ResolvedExperiment
    runs: list[RunSummary]
    manifest_path: Path
    manifest: dict = field(default_factory=dict)


# --- pinned identities (fingerprint inputs, DESIGN.md 10) ------------------------


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_env_versions(path: Path = VERSIONS_ENV) -> dict:
    """Parse the KEY=VALUE versions.env (comments and blanks ignored).

    The same parsing the runner uses (runner/runrecord.py load_versions);
    kept local so the framework imports nothing from the runner package.
    """
    out = {}
    for line in Path(path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip()
    return out


def plugin_versions() -> dict:
    """Every plugin manifest under plugins/ (DESIGN.md 11: claims, immutable
    per version): id -> {version, kind}. The manifest is the claim; the run
    manifest records which plugin versions the experiment resolved against."""
    out = {}
    if not (REPO_ROOT / "plugins").is_dir():
        return out
    for manifest_path in sorted((REPO_ROOT / "plugins").glob("*/manifest.json")):
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        out[manifest.get("id", manifest_path.parent.name)] = {
            "version": manifest.get("version"),
            "kind": manifest.get("kind"),
        }
    return out


def _manifest_version(plugin_id: str, versions: dict | None = None) -> str:
    versions = versions if versions is not None else plugin_versions()
    return (versions.get(plugin_id) or {}).get("version") or "unknown"


def sensor_version(versions: dict | None = None) -> dict:
    """The runner-managed sensor (Tracee; DESIGN.md 9: one sensor per run,
    runner-owned). Informational here: the sensor must never share the
    contract of the components it measures, and its health report is a run
    input owned by the runner."""
    versions = versions if versions is not None else load_env_versions()
    return {
        "instrument": "tracee",
        "version": versions.get("TRACEE_VERSION", "unknown"),
        "image": versions.get("TRACEE_IMAGE", "unknown"),
        "image_digest": versions.get("TRACEE_DIGEST", "unknown"),
    }


def fixture_fingerprint(descriptor: RunDescriptor) -> dict:
    """Fixture identity (DESIGN.md 10 comparability key): the merged
    fixture id, the BASE compose file realizing the design for this harness
    (project name + sha256), the CONTROL-BINDING OVERLAY's sha256 when the
    run binds one (the base+overlay composition, DESIGN.md 7: a base hash
    change — a design restructure — and an overlay change — a control
    version bump — are separately visible), plus the deployed
    enforcement_config artifact when the design pins one. For a custom
    fixture (experiment fixture block) no compose file is pinned this
    pass: the fingerprint records the declared name and a note."""
    fingerprint: dict = {"id": descriptor.fixture}
    # the base compose file realizing the design FOR THIS HARNESS: the mock
    # harness's fixtures are compose/t{N}-mock.yaml (own compose projects,
    # distinct container prefixes); the real harnesses run compose/t{N}.yaml
    compose_name = f"{descriptor.design}-mock.yaml" \
        if descriptor.harness == MOCK_HARNESS_ID else \
        f"{descriptor.design}.yaml"
    compose = COMPOSE_DIR / compose_name
    # only the reference ids pin the base: the composed id when a control
    # fills the slot, the bare id when control is null (a custom fixture
    # block must not be silently pinned to a base by naming)
    base_id = f"reference-rig/{descriptor.design}"
    composed_id = f"{base_id}+{descriptor.control}"
    pins_base = (descriptor.fixture == composed_id
                 or (descriptor.control is None
                     and descriptor.fixture == base_id))
    if pins_base and compose.is_file():
        doc = yaml.safe_load(compose.read_text(encoding="utf-8")) or {}
        fingerprint["compose"] = {
            "path": f"compose/{compose_name}",
            "id": doc.get("name"),
            "sha256": sha256_file(compose),
        }
    else:
        fingerprint["compose"] = None
        fingerprint["note"] = ("custom fixture: no compose file pinned this "
                               "pass (DESIGN.md 7 custom fixtures are "
                               "registry-tracked data)")
    # the control-binding overlay (DESIGN.md 7 base+overlay): recorded
    # separately from the base so either side's change moves the
    # fingerprint on its own
    if descriptor.overlay:
        overlay = overlay_abs_path(descriptor.overlay)
        fingerprint["overlay"] = {
            "path": descriptor.overlay,
            "sha256": sha256_file(overlay),
        } if overlay.is_file() else None
    config_rel = _enforcement_config_file(descriptor.design, descriptor.harness)
    config_path = REPO_ROOT / config_rel if config_rel else None
    if config_path is not None and config_path.is_file():
        fingerprint["enforcement_config"] = {
            "path": config_rel,
            "sha256": sha256_file(config_path),
        }
    return fingerprint


# --- the default executor (thin adapter over the runner machinery) ----------------


def default_run_executor(descriptor: RunDescriptor, run_id: str,
                         out_root: Path, sensor: bool = True,
                         workdir: Path | None = None) -> dict:
    """Drive one run through the existing runner machinery (runner/run.py
    run_design: compile -> replay -> capture -> map -> reconcile -> record)
    and return the run outcome the manifest assembly needs.

    sensor=False drives the runner's degraded no-eBPF path (run_design
    sensor=False: no sensor container is expected, no kernel evidence is
    captured; DESIGN.md 9) for hosts without kernel privileges. workdir is
    the writable root the run's artifacts derive from (framework/
    workdir.py: replay staging + compile cache; None resolves it --workdir /
    GUARDSCOPE_WORKDIR > cwd).

    Runs on the Linux testbed host only (Docker, compose, arm64). The
    outcome dict is the documented contract between the runner side and the
    framework assembly below (and the shape a test fake returns):

      run_id, harness, design          the run identity
      out_dir                          the run's artifact directory
      run_record                       run-record.json path (or None)
      status                           reconciliation status
      coverage                         the coverage report the run computed
                                       over its decision log (None when the
                                       design has no enforcement point)
      window_epoch_ns                  the measurement window (or None)
      decision_log                     raw v0 AuditEntry decisions.jsonl of
                                       the run's enforcement point (or None)
      decision_stream                  producer identity for the mapping:
                                       slot_id, plugin, plugin_version,
                                       product, product_version
      sensor_present                   the sensor actually produced kernel
                                       evidence in this run (detected from
                                       the run dir's artifacts below; there is
                                       no separate sensor-health artifact —
                                       run_one hard-fails a broken sensor
                                       capture, and a non-empty
                                       tracee-events.json is the started-
                                       and-captured evidence)
      effective_counts, ground_truth_counts, spec_sha256
      dispatch_records                the adapter's dispatch-record/1 stream
                                     (M2a: runs/<id>/dispatch-records.jsonl,
                                     or None when the design dispatched no
                                     tool calls)
      native_decision_records       the enforcement point's native
                                     decision-record/1 stream (M2a:
                                     gateway/decision-records.jsonl, or
                                     None when the control emits only the
                                     v0 AuditEntry stream)
    """
    runner_dir = str(REPO_ROOT / "runner")
    if runner_dir not in sys.path:
        sys.path.insert(0, runner_dir)
    import run as run_mod  # runner/run.py (sys.path holds the runner dir)

    summary = run_mod.run_design(descriptor.harness, descriptor.design,
                                 run_id, runs_dir=Path(out_root),
                                 sensor=sensor, workdir=workdir)
    out_dir = Path(summary["out_dir"])
    run_record_path = out_dir / "run-record.json"
    run_record = (json.loads(run_record_path.read_text(encoding="utf-8"))
                  if run_record_path.is_file() else {})
    replay_path = out_dir / "replay-result.json"
    replay = (json.loads(replay_path.read_text(encoding="utf-8"))
              if replay_path.is_file() else {})

    # the enforcement-point record the run captured (gateway/ under the run
    # dir for every design that has one; None for t0)
    decision_log = out_dir / "gateway" / "decisions.jsonl"
    has_log = descriptor.design != "t0" and decision_log.is_file()

    # producer identity of the decision stream: harness-adapter records for
    # the harness-intrinsic designs (t4/t5/t6), the selected control's
    # gateway records otherwise (DESIGN.md 7 placement table)
    versions = load_env_versions()
    manifests = plugin_versions()
    if descriptor.design in ("t4", "t5", "t6"):
        product_key, version_key = HARNESS_PRODUCT_KEYS.get(
            descriptor.harness, (None, None))
        stream = {
            "slot_id": "harness",
            "plugin": descriptor.harness,
            "plugin_version": _manifest_version(descriptor.harness, manifests),
            "product": versions.get(product_key, descriptor.harness)
            if product_key else descriptor.harness,
            "product_version": versions.get(version_key, "unknown")
            if version_key else "unknown",
        }
    else:
        control = descriptor.control or V0_DEFAULT_PLUGIN
        stream = {
            "slot_id": "gateway",
            "plugin": control,
            "plugin_version": _manifest_version(control, manifests),
            "product": V0_DEFAULT_PRODUCT,
            "product_version": versions.get("GATEWAY_PACKAGE_VERSION",
                                             "unknown"),
        }

    return {
        "run_id": run_id,
        "harness": descriptor.harness,
        "design": descriptor.design,
        "out_dir": str(out_dir),
        "run_record": str(run_record_path) if run_record_path.is_file()
        else None,
        "status": summary["status"],
        "coverage": run_record.get("coverage"),
        "window_epoch_ns": replay.get("window_epoch_ns"),
        "decision_log": str(decision_log) if has_log else None,
        "decision_stream": stream,
        # size check only: the raw capture can be gigabytes (a full read
        # would spike memory after the run already completed)
        "sensor_present": sensor and (out_dir / "tracee-events.json").is_file()
                        and (out_dir / "tracee-events.json").stat().st_size > 0,
        "effective_counts": summary.get("effective_counts"),
        "ground_truth_counts": summary.get("ground_truth_counts"),
        "spec_sha256": summary.get("spec_sha256"),
        # M2a: the two C5 input streams (DESIGN.md 9); the runner copies the
        # adapter's dispatch records next to the replay log and the gateway's
        # native stream next to its v0 AuditEntry log.
        "dispatch_records": (str(out_dir / "dispatch-records.jsonl")
                              if (out_dir / "dispatch-records.jsonl").is_file()
                              else None),
        "native_decision_records": (str(out_dir / "gateway" /
                                         "decision-records.jsonl")
                                     if (out_dir / "gateway" /
                                        "decision-records.jsonl").is_file()
                                     else None),
    }


# --- per-run assembly: mapping, recomputed coverage, findings ---------------------


def _load_spec(path: Path = BASELINE_SPEC) -> dict:
    """The canonical trace spec of the resolved workload (baseline-15, the
    only registered pack this pass; DESIGN.md 8)."""
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def _coverage_projection(report: dict) -> dict:
    """The comparison projection for the consistency assertion: everything
    of the C1-C4 report that must be identical when coverage is recomputed
    from the mapped decision records (the round trip through the v0 mapping
    is exact, DESIGN.md 4; any difference is a finding)."""
    per_class = {
        cls: (v.get("covered"), v.get("ground_truth"), v.get("inspected"))
        for cls, v in (report.get("coverage") or {}).items()
    }
    per_action = {
        row.get("id"): (row.get("evaluated"), row.get("decisions"),
                        row.get("allowed"), row.get("verdict"))
        for row in report.get("per_action") or []
    }
    return {
        "status": report.get("status"),
        "coverage": per_class,
        "checks": {c.get("id"): c.get("status")
                   for c in report.get("checks") or []},
        "decisions": {k: (report.get("decisions") or {}).get(k)
                      for k in ("total", "in_window", "out_of_window")},
        "per_action": per_action,
    }


def _projection_diff(reported: dict, recomputed: dict) -> list[str]:
    diffs = []
    for key in ("status", "coverage", "checks", "decisions", "per_action"):
        if reported.get(key) != recomputed.get(key):
            diffs.append(f"{key}: reported {reported.get(key)!r} != "
                         f"recomputed {recomputed.get(key)!r}")
    return diffs


def _map_decision_records(outcome: dict, run_id: str,
                          out_dir: Path) -> tuple[list[dict], list[str]]:
    """Map the run's raw v0 AuditEntry decision log to decision-record/1
    (DESIGN.md 4: the v0 format stays a valid input via the declared
    reader-side mapping). Malformed lines are kept as parse problems so the
    recomputed C1 sees exactly what the run's own C1 saw."""
    log = outcome.get("decision_log")
    if not log:
        return [], []
    entries, problems = reconcile_lib.load_decisions(Path(log))
    stream = dict(outcome.get("decision_stream") or {})
    slot_id = stream.get("slot_id", "gateway")
    records = map_audit_entries(
        entries,
        run_id=run_id,
        stream_id=stream.get("stream_id") or f"{run_id}:{slot_id}",
        product_version=stream.get("product_version", "unknown"),
        plugin_version=stream.get("plugin_version", "unknown"),
        slot_id=slot_id,
        plugin=stream.get("plugin", V0_DEFAULT_PLUGIN),
        product=stream.get("product", V0_DEFAULT_PRODUCT),
    )
    return records, problems


def _load_jsonl(path: Path) -> tuple[list[dict], list[str]]:
    """Parse a JSONL record stream; returns (records, problems). A malformed
    line is a problem, never a silent drop (DESIGN.md 9: findings, never
    silently trusted)."""
    records, problems = [], []
    for i, raw_line in enumerate(Path(path).read_text(encoding="utf-8")
                                 .splitlines(), 1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError as exc:
            problems.append(f"{Path(path).name} line {i}: {exc}")
    return records, problems


def _c5_report(outcome: dict, run_id: str, window, tolerance: int,
               inspected_action_ids: set | None = None) -> dict:
    """Run C5 (id consistency, DESIGN.md 9) over one run's dispatch records
    and native decision stream when both artifacts are present; either
    absent (or empty) => C5 skipped with a note, never a finding (the v0-only
    M1 topology stays a valid result; carrier-less records are skipped
    inside the check, not here)."""
    from framework.c5 import run_c5

    def _artifact(name: str, hinted, default: Path) -> tuple[str | None, str]:
        """(path, why-absent) for one C5 input; empty files count as absent."""
        path = Path(hinted) if hinted else default
        if path.is_file() and path.read_text(encoding="utf-8").strip():
            return str(path), ""
        if not path.is_file():
            return None, f"{name}: no {path.name} on disk"
        return None, f"{name}: {path.name} is empty"

    dispatch_path, why_dispatch = _artifact(
        "dispatch_records", outcome.get("dispatch_records"),
        Path(outcome["out_dir"]) / "dispatch-records.jsonl")
    native_path, why_native = _artifact(
        "native_decision_records", outcome.get("native_decision_records"),
        Path(outcome["out_dir"]) / "gateway" / "decision-records.jsonl")
    absent = [w for w in (why_dispatch, why_native) if w]
    if absent:
        return {"id": "C5", "status": "skipped",
                "note": ("; ".join(absent) +
                         "; C5 not run (absent artifacts are a skip with a "
                         "note, not a finding, DESIGN.md 9)")}

    dispatch_records, dispatch_problems = _load_jsonl(Path(dispatch_path))
    native_records, native_problems = _load_jsonl(Path(native_path))
    if dispatch_problems or native_problems:
        return {"id": "C5", "status": "fail",
                "note": "unparseable record stream",
                "findings": [{"id": "C5-parse", "status": "fail",
                               "detail": "; ".join(dispatch_problems
                                                    + native_problems)}]}
    window_pair = ((int(window["start"]), int(window["end"]))
                  if window else None)
    return run_c5(dispatch_records, native_records, run_id=run_id,
                  window=window_pair, window_tolerance_ns=tolerance,
                  inspected_action_ids=inspected_action_ids)


def _c6_report(outcome: dict, run_id: str, window, tolerance: int,
               records: list[dict]) -> dict:
    """Run C6 (denial effectiveness, DESIGN.md 9) over one run's deny
    records against the run's kernel evidence. Sensor absent (the degraded
    no-eBPF mode) => skipped with a note, never a finding: there is no
    kernel evidence to verify absence against, and claims never
    self-upgrade. With the sensor present but no mapped-actions stream,
    run_c6 itself skips with a note."""
    from framework.c6 import run_c6

    if not outcome.get("sensor_present", True):
        return {"id": "C6", "status": "skipped",
                "note": ("no kernel sensor in this run (degraded no-eBPF "
                         "mode): denial effectiveness cannot be verified "
                         "against kernel evidence; C6 not run (a skip with "
                         "a note, never a finding; DESIGN.md 9)"),
                "denies": {"records": 0}, "per_deny": [], "findings": []}

    # the native decision stream joins the mapped v0 records (the same two
    # streams C5 uses; a deny may appear in either or both)
    out_dir = Path(outcome["out_dir"])
    native_path = Path(outcome.get("native_decision_records")
                       or (out_dir / "gateway" / "decision-records.jsonl"))
    all_records = list(records)
    if native_path.is_file() and native_path.read_text(encoding="utf-8").strip():
        native, _ = _load_jsonl(native_path)
        all_records += native
    window_pair = ((int(window["start"]), int(window["end"]))
                   if window else None)
    return run_c6(out_dir, all_records, window=window_pair,
                  window_tolerance_ns=tolerance, run_id=run_id)


def _outcome_counts(outcome: dict, out_dir: Path,
                    sensor_present: bool) -> dict | None:
    """The run's instance-level outcome counts (runner outcomes.json), with
    the DESIGN.md 9 verified/unverified distinction: outcome counts are
    verified only when kernel corroboration exists (the sensor produced
    evidence); in a sensor-less run they are claimed-only (`verified:
    false`), and every `prevented` entry carries a per-action note that it
    is an unverified claim — prevented is blocking outside the policy with
    no decision record, and its kernel-verified half (the absence of the
    action's effect) cannot be verified without the sensor; claims never
    self-upgrade."""
    hinted = outcome.get("outcomes")
    path = Path(hinted) if hinted else out_dir / "outcomes.json"
    if not path.is_file():
        return None
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return None
    per_class: dict[str, dict[str, int]] = {}
    rows = doc.get("per_action") or []
    for row in rows:
        per_class.setdefault(row.get("class", "?"), {}).setdefault(
            row.get("outcome", "?"), 0)
        per_class[row.get("class", "?")][row.get("outcome", "?")] += 1
    counts = {"schema": doc.get("schema"),
              "status": doc.get("status"),
              "counts": doc.get("counts"),
              "per_class": per_class,
              "verified": bool(sensor_present)}
    if not sensor_present:
        counts["prevented_unverified"] = [
            {"id": row.get("id"), "class": row.get("class"),
             "note": ("unverified claim: no kernel sensor ran in this run "
                      "(degraded no-eBPF mode); prevented requires kernel "
                      "verification of the action's effect absence "
                      "(DESIGN.md 9) and claims never self-upgrade")}
            for row in rows if row.get("outcome") == "prevented"]
    return counts


def _assemble_run_summary(descriptor: RunDescriptor, outcome: dict,
                          run_id: str, out_root: Path,
                          spec: dict) -> RunSummary:
    out_dir = Path(out_root) / run_id
    out_dir.mkdir(parents=True, exist_ok=True)

    # decision records: mapped through the v0 AuditEntry reader-side mapping
    # and written next to the run's artifacts (DESIGN.md 4, 9)
    records, parse_problems = _map_decision_records(outcome, run_id, out_dir)
    decision_records_path = out_dir / "decision-records.jsonl"
    decision_records_path.write_text(
        "".join(json.dumps(r, sort_keys=True) + "\n" for r in records),
        encoding="utf-8")

    # C1-C4 recomputed over the mapped records (framework/reconcile), then
    # the consistency assertion against the coverage the run itself computed
    # over the same log: a mismatch is a finding, never silently trusted
    recomputed = None
    consistent = None
    findings: list[dict] = []
    window = outcome.get("window_epoch_ns")
    tolerance = _profile_window_tolerance(descriptor.harness)
    if records or outcome.get("coverage") is not None:
        recomputed = reconcile_lib.compute(
            spec,
            reconcile_lib.decision_records_to_log_entries(records),
            parse_problems, descriptor.design,
            (int(window["start"]), int(window["end"])) if window else None,
            tolerance)
        findings += [dict(check) for check in recomputed.get("checks") or []
                    if check.get("status") != "pass"]
        reported = outcome.get("coverage")
        if reported is not None:
            diffs = _projection_diff(_coverage_projection(reported),
                                     _coverage_projection(recomputed))
            consistent = not diffs
            if diffs:
                findings.append({
                    "id": "coverage-consistency",
                    "status": "fail",
                    "detail": ("the coverage the run computed over its "
                               "decision log does not match coverage "
                               "recomputed from the mapped decision "
                               f"records ({descriptor.design}): "
                               + "; ".join(diffs)),
                })

    degraded: list[str] = []
    sensor_present = bool(outcome.get("sensor_present", True))
    if not sensor_present:
        degraded.append(SENSOR_ABSENT)

    # C5 (DESIGN.md 9): id consistency between the harness dispatch records
    # and the native decision stream. Skipped with a note when either
    # artifact is absent; its findings join the run's findings (a stripping
    # control is a defect, not a coverage input).
    # Stripping scope (DESIGN.md 5): only the design's inspected classes
    # can cross an enforcement point; dispatches of other classes are
    # expected to have no echo.
    inspected = reconcile_lib.INSPECTED_CLASSES.get(descriptor.design, set())
    inspected_ids = {a["id"] for a in spec.get("actions", [])
                     if a.get("class") in inspected} or None
    c5 = _c5_report(outcome, run_id, window, tolerance, inspected_ids)
    if c5.get("status") == "fail":
        findings += [dict(f) for f in c5.get("findings") or []]

    # C6 (DESIGN.md 9): denial effectiveness — every deny record is checked
    # against the run's kernel evidence. Findings (a deny with the action's
    # kernel signature present, C6-ineffective) join the run's findings; a
    # sensor-less run skips C6 with a note, never a finding.
    c6 = _c6_report(outcome, run_id, window, tolerance, records)
    if c6.get("status") == "fail":
        findings += [dict(f) for f in c6.get("findings") or []]

    # the run's outcome counts, with the DESIGN.md 9 verified flag: in a
    # sensor-less run they are claims (verified: false) and every prevented
    # entry is marked an unverified claim
    outcome_counts = _outcome_counts(outcome, out_dir, sensor_present)

    return RunSummary(
        run_id=run_id,
        design=descriptor.design,
        fixture=descriptor.fixture,
        control=descriptor.control,
        control_binding=descriptor.control_binding,
        harness=descriptor.harness,
        workload=descriptor.workload,
        off_matrix=descriptor.off_matrix,
        observation_only=descriptor.observation_only,
        run_dir=str(out_dir),
        run_record=outcome.get("run_record"),
        decision_records=str(decision_records_path),
        decision_record_count=len(records),
        fixture_fingerprint=fixture_fingerprint(descriptor),
        # DESIGN.md 8, 9: the evidence class. A mock-harness run is
        # "mock-run" (the path-originator fixture: "the path exists and
        # escapes this topology, kernel-confirmed; no agent in the loop");
        # a real-harness run is "harness-run"; without kernel evidence
        # every output is self-reported / unverified (DESIGN.md 9) whichever
        # harness drove it (claims never self-upgrade)
        evidence_class=(EVIDENCE_CLASS_SELF_REPORTED if not sensor_present
                        else EVIDENCE_CLASS_MOCK
                        if descriptor.harness == MOCK_HARNESS_ID
                        else EVIDENCE_CLASS),
        degraded=degraded,
        status=outcome.get("status", "unknown"),
        coverage=recomputed,
        coverage_consistent=consistent,
        findings=findings,
        effective_counts=outcome.get("effective_counts"),
        ground_truth_counts=outcome.get("ground_truth_counts"),
        spec_sha256=outcome.get("spec_sha256"),
        c5=c5,
        c6=c6,
        outcome_counts=outcome_counts,
    )


# --- execution -------------------------------------------------------------------


def _fresh_run_id(out_root: Path, base: str) -> str:
    """A run id whose artifact dir does not exist yet (the runner refuses to
    overwrite a run dir; repeated executions of the same experiment must not
    collide)."""
    run_id = base
    n = 1
    while (Path(out_root) / run_id).exists():
        n += 1
        run_id = f"{base}-{n}"
    return run_id


def _sensor_aware_default_executor(sensor: bool, workdir: Path | None = None):
    """The default executor bound to the requested sensor mode (sensor=False
    is the degraded no-eBPF mode, DESIGN.md 9) and the experiments workdir
    (framework/workdir.py). The flags are passed as keywords only when the
    executor accepts them: the runner-side default_run_executor does; an
    injected executor keeping the plain (descriptor, run_id, out_root)
    contract (the test fakes) is called unchanged — fakes report sensor
    presence through their outcome dict (`sensor_present`), which is what
    the assembly actually consumes."""
    import inspect

    def executor(descriptor: RunDescriptor, run_id: str, out_root: Path) -> dict:
        fn = default_run_executor   # module attribute: tests monkeypatch it
        params = inspect.signature(fn).parameters
        kw = {}
        if "sensor" in params:
            kw["sensor"] = sensor
        if "workdir" in params:
            kw["workdir"] = workdir
        return fn(descriptor, run_id, out_root, **kw)

    return executor


def _load_execution_history(manifest_path: Path) -> dict | None:
    """Load the experiment's existing execution manifest for append
    (DESIGN.md 10: cell collisions keep both rows; a rerun must not make
    the earlier runs vanish from the manifest). Returns None when no
    manifest exists yet. A corrupt manifest is never silently replaced:
    overwriting it would destroy run history, so the error propagates.
    An old-format manifest (runs only, no history fields) loads as-is:
    execute_experiment synthesizes its history fields on append."""
    if not manifest_path.is_file():
        return None
    try:
        previous = json.loads(manifest_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"{manifest_path}: not parseable as JSON; refusing to "
            f"overwrite an unreadable execution manifest (run history "
            f"would be lost; fix or move the file manually)") from exc
    if not isinstance(previous, dict):
        raise ValueError(f"{manifest_path}: not an object; refusing to "
                         f"overwrite an unreadable execution manifest")
    return previous


def _execution_entries(previous: dict | None,
                       experiment_sha256: str,
                       executed_at: str) -> tuple[list, list]:
    """(prior run entries, execution-history entries) for the append.

    The manifest's `runs` lists every run ever executed under this
    experiment (no entry is ever removed) and each execution appends its
    run entries; `executions` is the per-execution history (executed_at,
    run ids, the experiment hash and the sensor pins it resolved
    against). An old-format manifest (no history fields) synthesizes one
    history entry from its own facts, so a rerun never drops the earlier
    runs' provenance (backward compatible)."""
    if previous is None:
        return [], []
    prior_runs = previous.get("runs")
    if not isinstance(prior_runs, list):
        raise ValueError(
            "the existing execution manifest has no usable 'runs' list; "
            "refusing to overwrite it (run history would be lost)")
    # no entry is ever removed: a non-dict run entry is corruption, and
    # the manifest is refused (the same policy as every other corruption)
    if any(not isinstance(r, dict) for r in prior_runs):
        raise ValueError(
            "the existing execution manifest has a corrupt run entry; "
            "refusing to overwrite it (run history would be lost)")
    executions = previous.get("executions")
    if isinstance(executions, list) and executions:
        history = [dict(e) for e in executions if isinstance(e, dict)]
    else:
        # old format: one prior execution, its facts taken from the
        # manifest's own fields (created, runs, experiment, sensor)
        history = [{
            "executed_at": previous.get("created"),
            "run_ids": [r.get("run_id") for r in prior_runs],
            "experiment_sha256": (previous.get("experiment") or {}).get(
                "sha256"),
            "sensor": previous.get("sensor"),
        }]
    return prior_runs, history


def execute_experiment(experiment_path, *, run_executor=None,
                        out_root=None, sensor: bool = True,
                        workdir=None) -> ExecutionResult:
    """Load, validate, and execute an experiment file (DESIGN.md 6, 9).

    One run per requested design, driven through `run_executor(descriptor,
    run_id, out_root)` (default: the runner machinery via
    default_run_executor, testbed host only). sensor=False drives the
    degraded no-eBPF mode (DESIGN.md 9): the default executor runs the
    runner's sensor-less path and every run is labeled self-reported /
    degraded. Per run the framework writes decision-records.jsonl (the v0
    AuditEntry log mapped to decision-record/1) under <out_root>/<run-id>/
    and appends the run summary to the execution manifest written to
    <out_root>/<experiment-id>/execution.json.

    All writable artifacts land under the experiments workdir
    (framework/workdir.py): out_root defaults to <workdir>/runs and the
    runner's replay staging + compile cache derive from the same workdir
    (an explicit out_root wins for the run outputs; GUARDSCOPE_STAGING_DIR
    overrides the staging root on the runner side). With no --workdir flag
    and no GUARDSCOPE_WORKDIR env, the process cwd is the workdir, so
    running from the repo root behaves exactly as before.

    The manifest is append-oriented (DESIGN.md 10: collisions keep both
    rows): every execution of the same experiment file APPENDS its run
    entries to `runs` (the complete run history; no entry is ever
    removed) and records the per-execution facts in `executions`;
    `current_run_ids` names the latest execution's runs. A rerun
    therefore surfaces as collision rows in a merged report, never as a
    replacement of the earlier runs.

    Load-time errors (ExperimentError and friends) propagate unchanged; a
    failing run propagates the executor's error. A run whose recomputed
    coverage disagrees with the coverage it reported is recorded with a
    coverage-consistency finding, not an exception (DESIGN.md 9: findings,
    never silently trusted).
    """
    experiment_path = Path(experiment_path)
    experiment = load_experiment(experiment_path)
    plan = resolve(experiment)
    # the writable root: --workdir > GUARDSCOPE_WORKDIR > cwd
    # (framework/workdir.py); out_root defaults to its runs/ subdir
    resolved_workdir = resolve_workdir(workdir)
    if out_root is None:
        out_root = resolved_workdir / "runs"
    # the default executor is bound to the sensor mode and the workdir here
    # (a fake run_executor keeps its (descriptor, run_id, out_root) contract)
    executor = run_executor or _sensor_aware_default_executor(sensor,
                                                             resolved_workdir)
    out_root = Path(out_root)
    experiment_id = experiment_path.stem

    spec = _load_spec()
    run_summaries: list[RunSummary] = []
    for descriptor in plan.runs:
        run_id = _fresh_run_id(out_root, f"{experiment_id}-{descriptor.design}")
        outcome = executor(descriptor, run_id, out_root)
        run_summaries.append(
            _assemble_run_summary(descriptor, outcome, run_id, out_root, spec))

    now = now_rfc3339_ms()
    exec_dir = out_root / experiment_id
    exec_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = exec_dir / "execution.json"
    # append-oriented history (DESIGN.md 10: cell collisions keep both
    # rows; a rerun never replaces the earlier runs at the manifest level)
    previous = _load_execution_history(manifest_path)
    prior_runs, executions = _execution_entries(
        previous, sha256_file(experiment_path), now)
    manifest = {
        "schema": 1,   # bare stamp (DESIGN.md 4: no type names in data files)
        "created": (previous.get("created") if previous is not None else None) or now,
        "experiment": {
            "path": str(experiment_path),
            "sha256": sha256_file(experiment_path),
            "resolved": experiment.to_dict(),
        },
        "plugin_versions": plugin_versions(),
        "sensor": sensor_version(),
    }
    new_run_entries = []
    for summary in run_summaries:
        entry = summary.to_dict()
        entry["executed_at"] = now
        new_run_entries.append(entry)
    executions.append({"executed_at": now,
                       "run_ids": [e["run_id"] for e in new_run_entries],
                       "experiment_sha256": manifest["experiment"]["sha256"],
                       "sensor": manifest["sensor"]})
    manifest["executions"] = executions
    manifest["runs"] = prior_runs + new_run_entries
    manifest["current_run_ids"] = [e["run_id"] for e in new_run_entries]
    manifest_path.write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n", encoding="utf-8")
    return ExecutionResult(experiment=experiment, runs=run_summaries,
                           manifest_path=manifest_path, manifest=manifest)
