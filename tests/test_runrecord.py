"""Run-record + manifest assembly tests (C8, M6 acceptance).

Assembles a run record and manifest from synthetic retained artifacts (the
correct-run fixture stream from test_reconcile) and asserts the T0
done-criteria fields: canonical trace hash, per-class ground-truth counts,
mapped events traceable to raw events (provenance.raw_index), pinned
versions, and artifact hashes in the manifest.

Run from experiments/mediation/:  python3 -m pytest tests/test_runrecord.py -v
"""

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

INSPECTION_ROOT = Path(__file__).resolve().parent.parent
RUNRECORD_PATH = INSPECTION_ROOT / "runner" / "runrecord.py"
HASH_SPEC_PATH = INSPECTION_ROOT / "trace" / "hash_spec.py"
SPEC_PATH = INSPECTION_ROOT / "trace" / "traces" / "baseline.yaml"

sys.path.insert(0, str(INSPECTION_ROOT / "tests"))
from test_reconcile import (  # noqa: E402
    ACTIONS, CONTAINER, GROUND_TRUTH, SPEC, WIN_START,
    correct_openclaw_stream, replay_result, target_logs,
)


def _load_module():
    spec = importlib.util.spec_from_file_location("runrecord", RUNRECORD_PATH)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


rr = _load_module()

VERSIONS_ENV = """\
KERNEL_VERSION=7.1.13-402.asahi.fc43.aarch64+16k
KERNEL_ARCH=aarch64
TRACEE_IMAGE=aquasec/tracee
TRACEE_VERSION=v0.24.1
TRACEE_DIGEST=sha256:cfbbfee9
MAPPING_VERSION=6
DOCKER_VERSION=29.8.0
COMPOSE_VERSION=5.5.1
OPENCLAW_VERSION=2026.9.3
OPENCLAW_IMAGE=ghcr.io/openclaw/openclaw
OPENCLAW_IMAGE_DIGEST=sha256:6cb72e15
PI_VERSION=0.85.1
PI_PACKAGE=@earendil-works/pi-coding-agent
PI_NODE_BASE_IMAGE=node:24-bookworm-slim
PI_NODE_BASE_IMAGE_DIGEST=sha256:2fe369e9
"""


def write_artifacts(tmp_path):
    runs = tmp_path / "runs" / "pi-test"
    runs.mkdir(parents=True, exist_ok=True)
    mapped = runs / "mapped-actions.jsonl"
    mapped.write_text("".join(json.dumps(r, separators=(",", ":")) + "\n"
                              for r in correct_openclaw_stream()))
    replay = runs / "replay-result.json"
    replay.write_text(json.dumps(replay_result(), indent=1))
    raw = runs / "tracee-events.jsonl"
    raw.write_text('{"eventName":"execve"}\n' * 3)
    logs = tmp_path / "target-logs"
    logs.mkdir(exist_ok=True)
    (logs / "http-endpoint.log").write_text(
        "".join(json.dumps(l) + "\n" for l in target_logs()))
    versions = tmp_path / "versions.env"
    versions.write_text(VERSIONS_ENV)
    return runs, mapped, replay, raw, logs, versions


def assemble(tmp_path, harness="pi"):
    runs, mapped, replay, raw, logs, versions_env = write_artifacts(tmp_path)
    return run_cmd(tmp_path, runs, raw, logs, versions_env, harness)


def run_cmd(tmp_path, runs, raw, logs, versions_env, harness="pi"):
    out_dir = tmp_path / "out"
    cmd = [sys.executable, str(RUNRECORD_PATH),
           "--harness", harness, "--run-id", "pi-test",
           "--spec", str(SPEC_PATH),
           "--mapped", str(runs / "mapped-actions.jsonl"),
           "--replay", str(runs / "replay-result.json"),
           "--tracee-raw", str(raw),
           "--target-logs", str(logs),
           "--versions", str(versions_env),
           "--out-dir", str(out_dir)]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return proc, out_dir


def test_assemble_passes_and_writes_records(tmp_path):
    proc, out_dir = assemble(tmp_path)
    assert proc.returncode == 0, proc.stderr
    record = json.loads((out_dir / "run-record.json").read_text())
    manifest = json.loads((out_dir / "manifest.json").read_text())
    assert record["schema"] == rr.SCHEMA
    assert record["reconciliation"]["status"] == "pass"
    assert manifest["reconciliation"] == "pass"


def test_run_record_carries_canonical_trace_hash(tmp_path):
    proc, out_dir = assemble(tmp_path)
    assert proc.returncode == 0, proc.stderr
    record = json.loads((out_dir / "run-record.json").read_text())
    expected = subprocess.run([sys.executable, str(HASH_SPEC_PATH), str(SPEC_PATH)],
                              capture_output=True, text=True).stdout.strip()
    assert record["spec"]["canonical_sha256"] == expected
    assert record["spec"]["name"] == "baseline-t0"


def test_run_record_ground_truth_counts(tmp_path):
    proc, out_dir = assemble(tmp_path)
    assert proc.returncode == 0, proc.stderr
    record = json.loads((out_dir / "run-record.json").read_text())
    assert record["ground_truth_counts"] == {
        "stdio_tool_call": 3, "http_tool_call": 4, "direct_network": 2,
        "process_spawn": 2, "file_write": 2, "credential_access": 2}
    assert record["effective_counts"] == record["ground_truth_counts"]
    assert len(record["replay"]["per_action"]) == len(ACTIONS)


def test_run_record_mapped_events_traceable_to_raw(tmp_path):
    """Every embedded mapped event carries provenance.raw_index pointing back
    into the retained raw stream."""
    proc, out_dir = assemble(tmp_path)
    assert proc.returncode == 0, proc.stderr
    record = json.loads((out_dir / "run-record.json").read_text())
    events = record["kernel"]["mapped_events"]
    assert events and record["kernel"]["unmapped_scoped"]
    for e in events + record["kernel"]["unmapped_scoped"]:
        assert 0 <= e["provenance"]["raw_index"] < len(correct_openclaw_stream())


def test_run_record_pinned_versions(tmp_path):
    proc, out_dir = assemble(tmp_path)
    assert proc.returncode == 0, proc.stderr
    record = json.loads((out_dir / "run-record.json").read_text())
    pinned = record["pinned"]
    assert pinned["kernel"] == "7.1.13-402.asahi.fc43.aarch64+16k"
    assert pinned["tracee_version"] == "v0.24.1"
    assert pinned["mapping_version"] == 6
    assert pinned["harness"] == "pi" and pinned["harness_version"] == "0.85.1"
    assert pinned["tracee_image_digest"] == "sha256:cfbbfee9"
    manifest = json.loads((out_dir / "manifest.json").read_text())
    assert manifest["versions"] == pinned


def test_manifest_artifact_hashes(tmp_path):
    proc, out_dir = assemble(tmp_path)
    assert proc.returncode == 0, proc.stderr
    manifest = json.loads((out_dir / "manifest.json").read_text())
    runs = tmp_path / "runs" / "pi-test"
    sha = lambda p: hashlib.sha256(Path(p).read_bytes()).hexdigest()
    assert manifest["artifacts"]["mapped-actions"]["sha256"] == \
        sha(runs / "mapped-actions.jsonl")
    assert manifest["artifacts"]["replay-result"]["sha256"] == \
        sha(runs / "replay-result.json")
    assert manifest["artifacts"]["tracee-events"]["sha256"] == \
        sha(runs / "tracee-events.jsonl")
    assert manifest["spec_sha256"] == record_hash(tmp_path)


def record_hash(tmp_path):
    import yaml
    data = yaml.safe_load(SPEC_PATH.read_text())
    return hashlib.sha256(json.dumps(
        data, sort_keys=True, separators=(",", ":"),
        ensure_ascii=False).encode()).hexdigest()


def test_run_record_fails_on_corrupted_mapping(tmp_path):
    """Acceptance: a deliberately corrupted mapping must make assembly exit
    nonzero while still writing auditable records."""
    runs, mapped, replay, raw, logs, versions = write_artifacts(tmp_path)
    corrupted = []
    for r in correct_openclaw_stream():
        if (r["class"] == "credential_access"
                and "token" in r["detail"].get("target", "")):
            r = {**r, "class": "file_write"}
        corrupted.append(r)
    (runs / "mapped-actions.jsonl").write_text(
        "".join(json.dumps(r, separators=(",", ":")) + "\n" for r in corrupted))
    proc, out_dir = run_cmd(tmp_path, runs, raw, logs, versions)
    assert proc.returncode == 1, proc.stdout
    record = json.loads((out_dir / "run-record.json").read_text())
    assert record["reconciliation"]["status"] == "fail"
    assert record["reconciliation"]["leftovers"]
    failed = {c["id"] for c in record["reconciliation"]["checks"]
              if c["status"] == "fail"}
    assert "R3-kernel-credential_access" in failed


def test_missing_replay_window_rejected(tmp_path):
    runs, mapped, replay, raw, logs, versions = write_artifacts(tmp_path)
    bad = json.loads((runs / "replay-result.json").read_text())
    del bad["window_epoch_ns"]
    (runs / "replay-result.json").write_text(json.dumps(bad))
    proc, _ = run_cmd(tmp_path, runs, raw, logs, versions)
    assert proc.returncode != 0