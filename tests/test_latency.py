"""Per-call latency analysis tests (runner/latency.py) — docker-free unit
tests over synthetic run dirs.

Run from experiments/mediation/:  python3 -m pytest tests/test_latency.py -v
"""

import importlib.util
import json
import sys
from pathlib import Path

INSPECTION_ROOT = Path(__file__).resolve().parent.parent
LATENCY_PATH = INSPECTION_ROOT / "runner" / "latency.py"


def _load_module():
    spec = importlib.util.spec_from_file_location("latency", LATENCY_PATH)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = mod
    spec.loader.exec_module(mod)
    return mod


lat = _load_module()


def write_run(runs_dir: Path, run_id: str, harness: str, design: str,
              durations: dict[str, float], recon: str = "pass"):
    d = runs_dir / run_id
    d.mkdir(parents=True, exist_ok=True)
    (d / "run-record.json").write_text(json.dumps({
        "run_id": run_id, "harness": harness, "design": design,
        "reconciliation": {"status": recon}}))
    (d / "replay-result.json").write_text(json.dumps({
        "results": [{"id": k, "class": "x", "op": "x",
                     "started_ns": 0, "ended_ns": int(v * 1e6)}
                    for k, v in durations.items()]}))


def test_collect_includes_only_passing_runs_with_timestamps(tmp_path):
    write_run(tmp_path, "pi-t0-r1", "pi", "t0", {"a011": 10.0})
    write_run(tmp_path, "pi-t0-r2", "pi", "t0", {"a011": 20.0}, recon="fail")
    d = tmp_path / "pi-t1-r1"
    d.mkdir()
    (d / "run-record.json").write_text(json.dumps(
        {"run_id": "x", "harness": "pi", "design": "t1",
         "reconciliation": {"status": "pass"}}))
    (d / "replay-result.json").write_text(json.dumps(
        {"results": [{"id": "a011", "class": "x", "op": "x"}]}))  # no timestamps
    data = lat.collect(tmp_path)
    assert set(data["t0"]["pi"]) == {"pi-t0-r1"}      # failed run excluded
    assert "t1" not in data                            # no-timestamp run excluded


def test_median_map_and_overheads(tmp_path):
    for i, ms in enumerate((10.0, 20.0, 30.0)):
        write_run(tmp_path, f"pi-t0-r{i}", "pi", "t0", {"a011": ms})
    for i, ms in enumerate((14.0, 24.0, 34.0)):
        write_run(tmp_path, f"pi-t1-r{i}", "pi", "t1", {"a011": ms})
    report = lat.overheads(lat.collect(tmp_path))
    pi = report["pi"]
    assert pi["t0_baseline_ms"] == {"a011": 20.0}
    t1 = pi["designs"]["t1"]
    assert t1["per_action_median_ms"] == {"a011": 24.0}
    assert t1["overhead_vs_t0_ms"] == {"a011": 4.0}
    assert t1["per_action_spread_ms"]["a011"] == {"median": 24.0, "min": 14.0,
                                                  "max": 34.0}


def test_within_family_marginal(tmp_path):
    for i, ms in enumerate((30.0, 40.0)):
        write_run(tmp_path, f"pi-t0-r{i}", "pi", "t0", {"a011": ms})
    for i, ms in enumerate((10.0, 20.0)):
        write_run(tmp_path, f"pi-t4-r{i}", "pi", "t4", {"a011": ms})
    for i, ms in enumerate((25.0, 35.0)):
        write_run(tmp_path, f"pi-t6-r{i}", "pi", "t6", {"a011": ms})
    report = lat.overheads(lat.collect(tmp_path))
    t6 = report["pi"]["designs"]["t6"]
    assert t6["marginal_vs_t4"]["median_ms"] == {"a011": 15.0}
