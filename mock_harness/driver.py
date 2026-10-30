"""CLI driver for the path-originator mock harness (v1).

  python3 -m mock_harness.driver --trace trace/traces/baseline.yaml \
      [--plan <plan.yaml>] --out <dir> \
      [--select a031,a032] [--mode {all,escape,twins}] \
      [--run-id ID] [--placement placement.json]

Reads the canonical trace spec (the single source of the action list,
order, and arguments — compiled through the harness compiler so the
originators' argv/url/path shapes match the harness replay byte-for-byte),
verifies the pinned spec + path-manifest sidecars, cross-checks the path
manifest against the spec (refuses to run on drift), then executes the
selected actions in trace order via the originators, unconditionally and
policy-blind.

Outputs in --out:
  action-log.jsonl   one record per action (id, class, op, arguments,
                     variant, origin channel, timestamps, exit status,
                     provenance fields) — identical across runs with the
                     same config modulo timing/pid fields (see the digest)
  run-manifest.json  trace hash, mock harness version + git state, plan,
                     selection, window, placement descriptor (placeholder
                     unless --placement), the action-log digest, and the
                     deferred-children join results

Exit status: 0 when every action recorded status ok, 1 on any action
error (the errors themselves are data — the mock harness never aborts mid-run),
2 on setup/validation failures (bad spec/plan/manifest pins).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import jsonschema
import yaml

from mock_harness import (
    ACTION_RECORD_SCHEMA, ESCAPE_CLASSES, MOCK_HARNESS_VERSION,
    PLAN_SCHEMA, RUN_MANIFEST_SCHEMA, TWIN_CLASSES,
)
from mock_harness import originators, trace_spec

REPO_ROOT = Path(__file__).resolve().parent.parent
MANIFEST_PATH = Path(__file__).resolve().parent / "manifest.yaml"
PLAN_SCHEMA_PATH = Path(__file__).resolve().parent / "plan-schema.json"
RECORD_SCHEMA_PATH = Path(__file__).resolve().parent / "record.schema.json"

DEFAULT_PLAN = {
    "schema": PLAN_SCHEMA,
    "inter_action_delay_s": 0.0,
    "join_timeout_s": 10.0,
    "routes": {"http": "raw"},
}

# Fields excluded from the action-log digest: run-to-run wall clock and
# process identity (pids). Everything else in a record is a deterministic
# function of (trace spec, plan, originator behavior).
DIGEST_EXCLUDES = ["started_epoch_ns", "ended_epoch_ns", "pid", "*_pid"]

# --- dispatch records (harness adapter contract, reduced form; DESIGN.md 3, 4) ---
#
# One dispatch-record/1 line per TOOL-CALL attempt, emitted next to the
# action log (dispatch-records.jsonl). The driver is the id authority on the
# workload side: the twins carry the canonical trace action ids onto the
# transports (originators.py injects them) and this layer records one line
# per attempt with the carrier used — mirroring harnesses/pi/adapter/
# replay.ts writeDispatchRecord, so the dispatch tooling (C5, M2a) is shared
# between the real harnesses and the mock harness (DESIGN.md 3: "the mock
# harness formally implements this contract in reduced form ... so the
# dispatch tooling is shared").
#
# Carriers per twin (DESIGN.md 5 priority order):
#   stdio twin + gateway-routed http twin  params._meta namespaced keys
#                                          io.inspection/action_id + attempt
#                                          -> carrier_used "mcp_meta"
#   raw http twin                          x-inspection-action-id /
#                                          x-inspection-attempt headers via
#                                          the http_request interface
#                                          -> carrier_used "http_header"
# Process-level actions (direct_network, process_spawn, file_write,
# credential_access) get NO dispatch record: no tool-dispatch boundary
# exists for them, so no carrier can travel (the M2a decision, DESIGN.md 3
# inject(); recorded here as a fact, and their kernel evidence remains the
# only attribution path). run_id comes from the runner-stamped env
# INSPECTION_RUN_ID (docker exec -e), fallback "unattributed" — the same
# convention as the real harness adapters.
DISPATCH_SCHEMA_STAMP = 1
DISPATCH_CARRIER_META = "mcp_meta"
DISPATCH_CARRIER_HEADER = "http_header"
DISPATCH_RUN_ID_FALLBACK = "unattributed"
TOOL_CALL_CLASSES = frozenset({"stdio_tool_call", "http_tool_call"})


def dispatch_run_id() -> str:
    """The run identity the dispatch records carry (runner-stamped env)."""
    return os.environ.get("INSPECTION_RUN_ID") or DISPATCH_RUN_ID_FALLBACK


def carrier_for(plan: dict, action: dict) -> str | None:
    """The correlation carrier the twins set for this action, or None when
    no carrier exists (process-level actions)."""
    cls = action["class"]
    if cls == "stdio_tool_call":
        return DISPATCH_CARRIER_META
    if cls == "http_tool_call":
        raw_route = (plan.get("routes") or {}).get("http", "raw") == "raw"
        return DISPATCH_CARRIER_HEADER if raw_route else DISPATCH_CARRIER_META
    return None


def dispatch_record(action_id: str, carrier: str, status: str,
                    error: str | None) -> dict:
    """One dispatch-record/1 (bare schema:1 stamp, DESIGN.md 4): run_id,
    action_id, attempt 0 (single-pass, no retries), dispatched_at,
    carrier_used, and exactly one of result | error."""
    record = {
        "schema": DISPATCH_SCHEMA_STAMP,
        "run_id": dispatch_run_id(),
        "action_id": action_id,
        "attempt": 0,
        "dispatched_at": datetime.now(timezone.utc).isoformat(
            timespec="milliseconds"),
        "carrier_used": carrier,
    }
    if error is not None:
        record["error"] = {"message": error}
    else:
        record["result"] = {"status": status}
    return record


# --- setup: spec, path manifest, plan ----------------------------------------

def _validator(schema_path: Path):
    schema = json.loads(schema_path.read_text())
    cls = jsonschema.validators.validator_for(schema)
    cls.check_schema(schema)
    return cls(schema)


def load_path_manifest() -> dict:
    """Load the pinned path manifest and verify its .sha256 sidecar."""
    manifest = yaml.safe_load(MANIFEST_PATH.read_text())
    _validator(Path(__file__).resolve().parent / "manifest.schema.json").validate(manifest)
    sidecar = MANIFEST_PATH.with_suffix(MANIFEST_PATH.suffix + ".sha256")
    if not sidecar.is_file():
        raise ValueError(f"path manifest sidecar missing: {sidecar}")
    expected = sidecar.read_text().split()[0]
    if trace_spec.canonical_sha256(MANIFEST_PATH) != expected:
        raise ValueError(f"path manifest hash mismatch: {MANIFEST_PATH}")
    return manifest


def check_manifest_matches_spec(manifest: dict, spec: dict) -> list[str]:
    """Drift guard: the manifest declares the spec's paths; ids/classes/ops
    must match 1:1 (the manifest never feeds execution, so a stale manifest
    is a documentation bug this check catches at driver start)."""
    problems = []
    spec_actions = {a["id"]: a for a in spec["actions"]}
    manifest_ids = [p["id"] for p in manifest["paths"]]
    if manifest_ids != list(spec_actions):
        problems.append(f"manifest paths {manifest_ids} != spec actions "
                        f"{list(spec_actions)}")
    for path in manifest["paths"]:
        action = spec_actions.get(path["id"])
        if not action:
            continue
        if path["class"] != action["class"]:
            problems.append(f"{path['id']}: class {path['class']!r} != {action['class']!r}")
        if path["operation"] != action["op"]:
            problems.append(f"{path['id']}: operation {path['operation']!r} != {action['op']!r}")
    return problems


def load_plan(plan_path: Path | None) -> tuple[dict, str, str | None]:
    """Load + validate a plan file, or return the built-in default plan."""
    if plan_path is None:
        return dict(DEFAULT_PLAN), "default", None
    plan = yaml.safe_load(plan_path.read_text())
    _validator(PLAN_SCHEMA_PATH).validate(plan)
    return plan, str(plan_path), trace_spec.raw_sha256(plan_path)


def check_plan_against_spec(plan: dict, spec: dict) -> list[str]:
    """Cross-checks JSON Schema cannot express: action ids exist, and the
    variant is only selected for process_spawn actions."""
    problems = []
    ids = {a["id"] for a in spec["actions"]}
    by_id = {a["id"]: a for a in spec["actions"]}
    for action_id, override in (plan.get("actions") or {}).items():
        if action_id not in ids:
            problems.append(f"plan selects unknown action {action_id!r}")
            continue
        if by_id[action_id]["class"] != "process_spawn":
            problems.append(f"{action_id}: variant {override.get('variant')!r} "
                            "selected for a non-process_spawn class")
    for route in ("http", "stdio"):
        if (plan.get("routes") or {}).get(route) == "gateway" and \
                not (plan.get("routes") or {}).get("gateway_url"):
            if not os.environ.get("GATEWAY_URL"):
                problems.append(f"routes.{route}=gateway requires "
                                "routes.gateway_url (or env GATEWAY_URL)")
    return problems


def select_actions(spec: dict, mode: str, select: list[str] | None) -> list[dict]:
    """Selection preserves trace order. mode presets are class-derived (the
    escape preset = the four escape classes; twins = the two tool classes);
    --select takes precedence over --mode."""
    if select:
        wanted = {s.strip() for s in select if s.strip()}
        spec_ids = {a["id"] for a in spec["actions"]}
        missing = sorted(wanted - spec_ids)
        if missing:
            raise ValueError(f"--select: unknown action ids {missing}")
        return [a for a in spec["actions"] if a["id"] in wanted]
    if mode == "escape":
        return [a for a in spec["actions"] if a["class"] in ESCAPE_CLASSES]
    if mode == "twins":
        return [a for a in spec["actions"] if a["class"] in TWIN_CLASSES]
    return list(spec["actions"])


# --- provenance / git state ---------------------------------------------------

def git_state() -> dict:
    """Best-effort git provenance; recorded null when unavailable (the
    checkout may not be a git work tree). When git is not installed, skip
    the calls entirely: a missing-binary subprocess call leaves a failed
    execve attempt in every PATH entry, and those kernel events land in the capture
    (the mock harness runs its provenance stamp after its window closes)."""
    import shutil
    if shutil.which("git") is None:
        return {"commit": None, "dirty": None,
                "note": "git not installed in the runtime image"}
    try:
        commit = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=5)
        dirty = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "status", "--porcelain"],
            capture_output=True, text=True, timeout=5)
        if commit.returncode != 0 or dirty.returncode != 0:
            raise subprocess.CalledProcessError(commit.returncode, "git")
        return {"available": True,
                "commit": commit.stdout.strip(),
                "dirty": bool(dirty.stdout.strip())}
    except Exception:
        return {"available": False, "commit": None, "dirty": None}


# --- records / digest ----------------------------------------------------------

def variant_for(plan: dict, action: dict) -> str:
    override = (plan.get("actions") or {}).get(action["id"]) or {}
    return override.get("variant", originators.default_variant(action))


def normalize_record(record: dict):
    """Drop the run-to-run timing/process-identity fields (deep copy)."""
    def strip(value):
        if isinstance(value, dict):
            out = {}
            for key, val in value.items():
                if key in ("started_epoch_ns", "ended_epoch_ns"):
                    continue
                if key == "pid" or (key.endswith("_pid") and key != "pid"):
                    continue
                out[key] = strip(val)
            return out
        if isinstance(value, list):
            return [strip(v) for v in value]
        return value
    return strip(record)


def log_digest(records: list[dict]) -> str:
    """SHA-256 over the normalized records: two runs with the same config
    produce the same digest (timing/pid fields excluded, documented in the
    run manifest's digest_excludes)."""
    normalized = [normalize_record(r) for r in records]
    payload = "".join(
        json.dumps(r, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        + "\n" for r in normalized)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# --- deferred-children join -----------------------------------------------------

def join_deferred(ctx: originators.RunContext, timeout_s: float) -> list[dict]:
    """Bounded join of outstanding (outliving/daemon) children so no
    process outlives the run: direct children are reaped via waitpid
    (WNOHANG polling); reparented daemon workers are checked (kill 0) —
    their exit code is unobservable to us by construction."""
    results: list[dict] = []
    pending = list(ctx.deferred)
    deadline = time.monotonic() + timeout_s
    while pending and time.monotonic() < deadline:
        still: list[dict] = []
        for entry in pending:
            state, code = originators.syscalls.child_exit_state(entry["pid"])
            if state == "exited":
                results.append({**entry, "joined": True, "exit_code": code})
            elif state == "foreign" and not originators.syscalls.alive(entry["pid"]):
                results.append({**entry, "joined": True, "exit_code": None,
                                "note": "reparented worker exited (exit code "
                                        "unobservable: reaped by init)"})
            else:
                still.append(entry)
        pending = still
        if pending:
            time.sleep(0.02)
    results.extend({**e, "joined": False, "exit_code": None,
                    "note": "still alive at join timeout"} for e in pending)
    return sorted(results, key=lambda e: (e["id"], e["pid"]))


# --- run ------------------------------------------------------------------------

def execute(spec_path: Path, plan: dict, out_dir: Path, mode: str = "all",
            select: list[str] | None = None, run_id: str = "mock-run",
            placement: dict | None = None, plan_source: str = "default",
            plan_sha256: str | None = None,
            manifest: dict | None = None) -> dict:
    """Execute the selected actions in trace order and write the artifacts.

    Returns the run manifest dict. Raises ValueError on setup/validation
    failures (caller exits 2); action failures are recorded as data.
    """
    spec = trace_spec.load_spec(spec_path)
    sidecar_verified = trace_spec.verify_sidecar(spec_path)
    if sidecar_verified is False:
        raise ValueError(f"trace spec hash mismatch against sidecar: {spec_path}")

    manifest = manifest if manifest is not None else load_path_manifest()
    problems = (check_manifest_matches_spec(manifest, spec)
                 + check_plan_against_spec(plan, spec))
    if problems:
        raise ValueError("setup validation failed: " + "; ".join(problems))

    actions = select_actions(spec, mode, select)
    ctx = originators.RunContext(run_id, plan)

    out_dir.mkdir(parents=True, exist_ok=True)
    log_path = out_dir / "action-log.jsonl"
    dispatch_path = out_dir / "dispatch-records.jsonl"
    records: list[dict] = []
    dispatch_records: list[dict] = []

    window_start = time.time_ns()
    with log_path.open("w", encoding="utf-8") as log, \
            dispatch_path.open("w", encoding="utf-8") as dlog:
        for index, action in enumerate(actions):
            compiled = trace_spec.compile_action(action)
            fn = originators.resolve_originator(action)
            variant = variant_for(plan, action)
            ctx.action_id = action["id"]
            channel = originators.origin_channel(fn, variant, ctx)
            started = time.time_ns()
            status, error, detail = "ok", None, {}
            try:
                detail = fn(compiled, ctx, variant) or {}
            except Exception as exc:  # recorded as data; execution continues
                status, error, detail = "error", str(exc), {}
            ended = time.time_ns()
            carrier = carrier_for(plan, action)
            if carrier is not None:
                # one dispatch record per tool-call attempt (DESIGN.md 4);
                # emission must never fail the run
                try:
                    rec = dispatch_record(action["id"], carrier, status, error)
                    dispatch_records.append(rec)
                    dlog.write(json.dumps(rec, separators=(",", ":"),
                                          ensure_ascii=False) + "\n")
                except Exception:  # noqa: BLE001 — never fail on emission
                    pass
            deferred = bool(detail.pop("deferred", False))
            record = {
                "schema": ACTION_RECORD_SCHEMA,
                "run_id": run_id,
                "id": action["id"],
                "class": action["class"],
                "op": action["op"],
                "target": action["target"],
                "arguments": action.get("args") or {},
                "variant": variant,
                "origin_channel": channel,
                "origin_channel_detail": originators.origin_channel_detail(
                    fn, variant, ctx),
                "status": status,
                "error": error,
                "detail": detail,
                "started_epoch_ns": started,
                "ended_epoch_ns": ended,
                "provenance": "mock-harness",
                "originator": {
                    "mock_harness_version": MOCK_HARNESS_VERSION,
                    "function": fn.__name__,
                    "action_index": index,
                    "deferred": deferred,
                },
            }
            records.append(record)
            log.write(json.dumps(record, separators=(",", ":"),
                                 ensure_ascii=False) + "\n")
            delay = float(plan.get("inter_action_delay_s") or 0.0)
            if delay and index < len(actions) - 1:
                time.sleep(delay)
    ctx.close()
    window_end = time.time_ns()

    # A plan file that omits join_timeout_s gets the schema-documented
    # default (jsonschema does not inject defaults); only an explicit
    # value (including 0 = do not join) overrides it.
    join_timeout = plan.get("join_timeout_s")
    joined = join_deferred(
        ctx, float(join_timeout) if join_timeout is not None
        else DEFAULT_PLAN["join_timeout_s"])
    failed = sum(1 for r in records if r["status"] != "ok")

    run_manifest = {
        "schema": RUN_MANIFEST_SCHEMA,
        "run_id": run_id,
        "created": datetime.now(timezone.utc).isoformat(),
        "mock_harness": {
            "version": MOCK_HARNESS_VERSION,
            "manifest_sha256": trace_spec.canonical_sha256(MANIFEST_PATH),
            "git": git_state(),
        },
        "trace": {
            "path": str(spec_path),
            "canonical_sha256": trace_spec.canonical_sha256(spec_path),
            "raw_sha256": trace_spec.raw_sha256(spec_path),
            "sidecar_verified": sidecar_verified,
        },
        "path_manifest": {
            "path": str(MANIFEST_PATH),
            "sha256": trace_spec.canonical_sha256(MANIFEST_PATH),
            "sidecar_verified": True,
            "matches_spec": True,
        },
        "plan": {"source": plan_source, "sha256": plan_sha256, "content": plan},
        "selection": {
            "mode": mode,
            "select": select,
            "executed_ids": [r["id"] for r in records],
        },
        "window_epoch_ns": {"start": window_start, "end": window_end},
        "placement": {
            "descriptor": placement,
            "attached": placement is not None,
            "note": ("attached per run" if placement is not None else
                     "PLACEHOLDER: attach the harness-trust-domain placement "
                     "descriptor per run via driver --placement (the wrapper "
                     "that runs the mock harness inside the harness trust "
                     "domain is a later concern)"),
        },
        "action_log": {
            "path": "action-log.jsonl",
            "records": len(records),
            "ok": len(records) - failed,
            "failed": failed,
            "digest": log_digest(records),
            "digest_algorithm": "sha256",
            "digest_excludes": list(DIGEST_EXCLUDES),
            "digest_note": ("digest over all action records with the "
                            "excluded fields removed; identical across runs "
                            "with the same trace+plan"),
        },
        "dispatch_records": {
            "path": "dispatch-records.jsonl",
            "records": len(dispatch_records),
            "tool_call_actions": sum(1 for a in actions
                                      if a["class"] in TOOL_CALL_CLASSES),
            "note": ("one dispatch-record/1 per tool-call attempt (DESIGN.md "
                     "4); process-level actions get no dispatch record — no "
                     "carrier exists (the M2a decision, DESIGN.md 3)"),
        },
        "deferred_join": joined,
        "summary": {"ok": failed == 0, "executed": len(records), "failed": failed},
    }
    (out_dir / "run-manifest.json").write_text(
        json.dumps(run_manifest, indent=1, sort_keys=True) + "\n",
        encoding="utf-8")
    return run_manifest


# --- CLI ------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                     epilog=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trace", type=Path,
                        default=trace_spec.DEFAULT_TRACE,
                        help="canonical trace spec (default: the pinned baseline)")
    parser.add_argument("--plan", type=Path, default=None,
                        help="run plan (mock_harness/plan-schema.json); "
                             "default: the built-in default plan")
    parser.add_argument("--out", type=Path, required=True,
                        help="output directory (action-log.jsonl + run-manifest.json)")
    parser.add_argument("--select", default=None,
                        help="comma-separated action ids to execute (spec order)")
    parser.add_argument("--mode", default="all",
                        choices=["all", "escape", "twins"],
                        help="preset: all 15 paths; escape = the four escape "
                             "classes; twins = the two tool-call classes")
    parser.add_argument("--run-id", default="mock-run")
    parser.add_argument("--placement", type=Path, default=None,
                        help="placement descriptor JSON attached to the run "
                             "manifest (the harness-trust-domain wrapper)")
    args = parser.parse_args(argv)

    try:
        manifest = load_path_manifest()
        plan, plan_source, plan_sha256 = load_plan(args.plan)
        select = ([s.strip() for s in args.select.split(",")]
                  if args.select else None)
        placement = (json.loads(args.placement.read_text())
                    if args.placement else None)
    except (ValueError, OSError, jsonschema.ValidationError,
            json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    try:
        run_manifest = execute(
            args.trace, plan, args.out, mode=args.mode, select=select,
            run_id=args.run_id, placement=placement, plan_source=plan_source,
            plan_sha256=plan_sha256, manifest=manifest)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    summary = run_manifest["summary"]
    print(json.dumps({
        "run_id": run_manifest["run_id"],
        "executed": summary["executed"],
        "failed": summary["failed"],
        "ok": summary["ok"],
        "action_log": str(args.out / "action-log.jsonl"),
        "run_manifest": str(args.out / "run-manifest.json"),
        "digest": run_manifest["action_log"]["digest"],
    }, indent=1))
    return 0 if summary["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
