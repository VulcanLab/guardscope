#!/usr/bin/env python3
"""Run-record assembly (C8, M6).

Assembles the T0 run record (JSON) and its companion manifest.json for one
replay run, per the T0 done-criteria:

  run-record.json
    - canonical trace hash (SHA-256 of the spec, canonical + raw forms)
    - per-action-class ground-truth counts (six classes)
    - mapped Tracee events, each traceable back to the raw stream
      (provenance.raw_index) — the in-scope kernel records post-noise
    - reconciliation verdict (pass/fail with checks + leftovers)
    - pinned versions: harness, Tracee, kernel, container image digests

  manifest.json
    versions, hashes (spec + every retained artifact), timing

Inputs are the retained per-run artifacts; reconciliation (C7) is executed
inside this command (reconcile.py is the library). The command exits nonzero
when reconciliation fails, but still writes both records so failures are
auditable.

Usage:
  python3 runner/runrecord.py --harness pi --run-id pi-20260910-1 \
      --mapped runs/pi/mapped-actions.jsonl \
      --replay runs/pi/replay-result.json \
      [--tracee-raw runs/pi/tracee-events.jsonl] \
      [--replay-log runs/pi/replay-log.jsonl] \
      [--target-logs runs/pi/target-logs/] \
      [--design t1 --gateway-log runs/<id>/gateway/decisions.jsonl \
       --gateway-policy gateway/policy.yaml] \
      [--container-id ...] [--versions env/versions.env] \
      --out-dir runs/pi-20260910-1

T1 runs add the inspection-coverage section (T1-4, coverage.py): the
enforcement-point decision log parsed, scoped to the replay window, and
mapped 1:1 onto the canonical http_tool_call actions; coverage.json,
decisions.jsonl, and policy.yaml are hashed into the manifest.
"""

import argparse
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / "runner"))

import reconcile as rec_mod  # noqa: E402
import coverage as cov_mod  # noqa: E402
import outcomes as out_mod  # noqa: E402

SCHEMA = "inspection-run-record/1"
MANIFEST_SCHEMA = "inspection-run-manifest/1"

# harness -> pinned-version keys in env/versions.env
VERSION_KEYS = {
    "openclaw": {"version": "OPENCLAW_VERSION",
                 "image": "OPENCLAW_IMAGE",
                 "image_digest": "OPENCLAW_IMAGE_DIGEST"},
    "pi": {"version": "PI_VERSION",
           "image": "PI_NODE_BASE_IMAGE",
           "image_digest": "PI_NODE_BASE_IMAGE_DIGEST"},
}


def sha256_file(path: Path) -> str | None:
    if not path or not Path(path).is_file():
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def load_versions(path: Path) -> dict:
    """Parse a KEY=VALUE versions.env (comments and blanks ignored)."""
    out = {}
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        out[key.strip()] = val.strip()
    return out


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def assemble(spec_path: Path, profile: dict, replay: dict, mapped: list[dict],
             target_logs: list[dict] | None, container_id: str | None,
             versions: dict, harness: str, run_id: str,
             design: str = "t0", gateway_log: Path | None = None,
             gateway_policy: Path | None = None,
             window_slack_ns: int = 1_000_000_000) -> tuple[dict, dict, dict]:
    """Run reconciliation and build (run_record, manifest, report).

    design != t0 additionally computes the inspection-coverage section
    (T1-4) from the enforcement-point decision log: coverage/ runner
    (coverage.py), scoped to the replay window, with the decisions and the
    deployed policy hashed into the manifest as auditable artifacts."""
    report = rec_mod.Reconciler(
        rec_mod.load_spec(spec_path), profile, replay, mapped,
        target_logs, container_id, design=design).run()

    sys.path.insert(0, str(HERE / "trace"))
    from hash_spec import canonical_hash as ch, raw_hash as rh  # noqa: E402

    rules = yaml.safe_load((HERE / "sensor" / "mapping" / "rules.yaml").read_text())

    vkeys = VERSION_KEYS[harness]
    harness_version = versions.get(vkeys["version"], "unknown")
    harness_image = versions.get(vkeys["image"], "unknown")
    harness_digest = versions.get(vkeys["image_digest"], "unknown")

    pinned = {
        "harness": harness,
        "harness_version": harness_version,
        "harness_image": harness_image,
        "harness_image_digest": harness_digest,
        "tracee_version": versions.get("TRACEE_VERSION", "unknown"),
        "tracee_image": versions.get("TRACEE_IMAGE", "unknown"),
        "tracee_image_digest": versions.get("TRACEE_DIGEST", "unknown"),
        "kernel": versions.get("KERNEL_VERSION", "unknown"),
        "kernel_arch": versions.get("KERNEL_ARCH", "unknown"),
        "docker": versions.get("DOCKER_VERSION", "unknown"),
        "compose": versions.get("COMPOSE_VERSION", "unknown"),
        "mapping_version": rules.get("version"),
    }

    # --- T1-4: inspection coverage from the enforcement point ----------------
    # design t0 (bare harness) has no enforcement point: no coverage section.
    coverage_report = None
    if design != "t0":
        if gateway_log is None:
            raise ValueError("design != t0 requires --gateway-log "
                             "(decisions.jsonl from the enforcement point)")
        decisions, parse_problems = cov_mod.load_decisions(gateway_log)
        w = replay.get("window_epoch_ns") or {}
        coverage_report = cov_mod.compute(
            rec_mod.load_spec(spec_path), decisions, parse_problems, design,
            (int(w["start"]), int(w["end"])) if w else None, window_slack_ns)
        pinned["gateway_package"] = versions.get("GATEWAY_PACKAGE", "unknown")
        pinned["gateway_package_version"] = versions.get(
            "GATEWAY_PACKAGE_VERSION", "unknown")
        pinned["gateway_policy_version"] = versions.get(
            "GATEWAY_POLICY_VERSION", "unknown")

    # mapped Tracee events retained in the record: every in-scope record
    # (the reconciliation accounting set), each traceable to the raw stream
    # via provenance.raw_index
    scoped = report["kernel"].pop("scoped_records", [])

    # instance-level outcome classification (checked/bypassed/prevented per
    # action instance — the RQ1 coverage-matrix artifact)
    outcomes = out_mod.compute(rec_mod.load_spec(spec_path), replay,
                               coverage_report, design)

    run_record = {
        "schema": SCHEMA,
        "run_id": run_id,
        "created": now_iso(),
        "harness": harness,
        "design": design,
        "prevented_classes": sorted(rec_mod.PREVENTED_CLASSES.get(design, set())),
        "profile": profile["profile"],
        "container_id": container_id,
        "spec": {
            "name": report["spec"]["name"],
            "version": report["spec"]["version"],
            "path": str(spec_path),
            "canonical_sha256": ch(spec_path),
            "raw_sha256": rh(spec_path),
        },
        "mapping": {"version": rules.get("version"),
                    "rules": "sensor/mapping/rules.yaml"},
        "window_epoch_ns": report["window_epoch_ns"],
        "ground_truth_counts": report["ground_truth_counts"],
        "effective_counts": report["effective_counts"],
        "replay": {"ok": replay.get("ok"), "executed": replay.get("executed"),
                   "failed": replay.get("failed"),
                   "per_action": replay.get("results")},
        "served": report["served"],
        "kernel": {
            "scope": report["scope"],
            "noise_count": report["kernel"]["noise_count"],
            "noise": report["kernel"]["noise"],
            "per_class": report["kernel"]["per_class"],
            "mapped_events": [r for r in scoped if r.get("class") != "unmapped"],
            "unmapped_scoped": [r for r in scoped if r.get("class") == "unmapped"],
        },
        "reconciliation": {"status": report["status"], "checks": report["checks"],
                           "leftovers": report["leftovers"]},
        "coverage": coverage_report,
        "outcomes": outcomes,
        "pinned": pinned,
    }

    manifest = {
        "schema": MANIFEST_SCHEMA,
        "run_id": run_id,
        "harness": harness,
        "design": design,
        "created": run_record["created"],
        "spec_sha256": run_record["spec"]["canonical_sha256"],
        "mapping_version": pinned["mapping_version"],
        "reconciliation": report["status"],
        "coverage": (coverage_report or {}).get("status") if design != "t0" else None,
        "versions": pinned,
        "timing": {
            "window_epoch_ns": report["window_epoch_ns"],
            "runrecord_created": run_record["created"],
        },
    }
    return run_record, manifest, report


def add_artifact_hashes(manifest: dict, artifacts: dict[str, Path]) -> None:
    manifest["artifacts"] = {
        name: {"path": str(path), "sha256": sha256_file(path),
               "bytes": path.stat().st_size if path and path.is_file() else None}
        for name, path in artifacts.items() if path
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--harness", required=True, choices=["openclaw", "pi"])
    ap.add_argument("--run-id", default=None)
    ap.add_argument("--spec", type=Path, default=HERE / "trace" / "traces" / "baseline.yaml")
    ap.add_argument("--mapped", type=Path, required=True)
    ap.add_argument("--replay", type=Path, required=True)
    ap.add_argument("--replay-log", type=Path, default=None)
    ap.add_argument("--tracee-raw", type=Path, default=None,
                    help="raw Tracee event stream (manifest hash only)")
    ap.add_argument("--target-logs", action="append", default=[])
    ap.add_argument("--container-id", default=None)
    ap.add_argument("--versions", type=Path, default=HERE / "env" / "versions.env")
    ap.add_argument("--design", default="t0", choices=sorted(cov_mod.INSPECTED_CLASSES),
                    help="deployment design (t0 bare harness; t1 adds the "
                         "gateway coverage section)")
    ap.add_argument("--gateway-log", type=Path, default=None,
                    help="decisions.jsonl from the enforcement point (t1+)")
    ap.add_argument("--gateway-policy", type=Path, default=None,
                    help="deployed gateway policy.yaml (manifest-hashed, t1+)")
    ap.add_argument("--window-slack-ns", type=int, default=1_000_000_000)
    ap.add_argument("--out-dir", type=Path, required=True)
    args = ap.parse_args()

    profile_path = HERE / "runner" / "profiles" / f"{args.harness}.yaml"
    profile = rec_mod.load_profile(profile_path)
    replay = rec_mod.load_replay(args.replay)
    mapped = rec_mod.load_mapped(args.mapped)
    target_logs = rec_mod.load_target_logs(args.target_logs) if args.target_logs else None
    versions = load_versions(args.versions)

    run_id = args.run_id or (f"{args.harness}-"
                             f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}")
    run_record, manifest, report = assemble(
        args.spec, profile, replay, mapped, target_logs, args.container_id,
        versions, args.harness, run_id, design=args.design,
        gateway_log=args.gateway_log, gateway_policy=args.gateway_policy,
        window_slack_ns=args.window_slack_ns)

    artifacts = {
        "tracee-events": args.tracee_raw,
        "mapped-actions": args.mapped,
        "replay-result": args.replay,
        "replay-log": args.replay_log,
    }
    if args.design != "t0":
        artifacts["gateway-decisions"] = args.gateway_log
        artifacts["gateway-policy"] = args.gateway_policy
    add_artifact_hashes(manifest, artifacts)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    (args.out_dir / "run-record.json").write_text(
        json.dumps(run_record, indent=1, sort_keys=True) + "\n")
    (args.out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n")

    print(json.dumps({"run_id": run_id,
                      "reconciliation": report["status"],
                      "coverage": (run_record.get("coverage") or {}).get("status"),
                      "effective_counts": report["effective_counts"],
                      "run_record": str(args.out_dir / "run-record.json"),
                      "manifest": str(args.out_dir / "manifest.json")}, indent=1))
    cov_status = (run_record.get("coverage") or {}).get("status", "pass")
    out_status = (run_record.get("outcomes") or {}).get("status", "pass")
    ok = (report["status"] == "pass" and cov_status == "pass"
          and out_status == "pass")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())