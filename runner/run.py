#!/usr/bin/env python3
"""Runner CLI (C9, M7 + T1-5): compile | run | rerun | reconcile | report.

Orchestrates the full pipeline per run:  canonical trace -> compile (+ diff
check against the spec) -> replay in the harness under Tracee -> map raw
Tracee events -> reconcile expected-vs-observed -> run record + retained raw
traces. All raw artifacts land under runs/<run-id>/ (first-class artifacts,
T0 done-criterion 4).

Designs (--design): t0 = bare harness (T0 topology, no enforcement point);
t1 = gateway for HTTP tools (compose/t1.yaml): the harness container is the
t1-* service, and the run additionally captures the enforcement-point record
(gateway decisions.jsonl + deployed policy.yaml into runs/<id>/gateway/)
and embeds the inspection-coverage section in the run record (T1-4).

Subcommands:
  compile    compile the canonical spec for the harness(es); --check diff
  run        one full run for one harness (compile -> replay -> record)
  rerun      N consecutive runs for one harness + reproducibility verdict
             (identical effective per-class counts across runs, T0 criterion 2)
  reconcile  re-run reconciliation + run-record assembly from retained
             artifacts (no replay) — debugging/re-mapping entry point
  report     summary table (per harness x per class counts) + done-criteria
             checklist over the run records of one design

Usage:
  python3 runner/run.py compile [--harness pi|openclaw|all]
  python3 runner/run.py run --harness pi --run-id pi-m7-1 [--design t0|t1]
  python3 runner/run.py rerun --harness pi --runs 2 --label t1 [--design t1]
  python3 runner/run.py reconcile --harness pi --run-dir runs/pi-m7-1 [--design t1]
  python3 runner/run.py report [--design t0|t1] [--runs-dir runs] [--out runs/report.json]

Exit codes: 0 pass, 1 reconciliation/coverage/reproducibility failure (records
still written), 2 usage/environment error.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / "runner"))

import reconcile as rec_mod  # noqa: E402
import runrecord as rr_mod  # noqa: E402
import coverage as cov_mod  # noqa: E402
import outcomes as out_mod  # noqa: E402

SIX_CLASSES = rec_mod.SIX_CLASSES
BASELINE = HERE / "trace" / "traces" / "baseline.yaml"
HASH_SIDECAR = HERE / "trace" / "traces" / "baseline.yaml.sha256"
RULES = HERE / "sensor" / "mapping" / "rules.yaml"
MAP_EVENTS = HERE / "sensor" / "mapping" / "map_events.py"
VERSIONS = HERE / "env" / "versions.env"
DEFAULT_RUNS_DIR = HERE / "runs"

MOCK_HARNESS_REPO_MOUNT = "/repo"          # compose mounts the repo read-only here
MOCK_DRIVER_TRACE = "trace/traces/baseline.yaml"   # resolved against /repo

HARNESSES = {
    "pi": {
        "container": "t0-pi",
        "compile_py": HERE / "trace" / "compile" / "pi" / "compile.py",
        "compiled": HERE / "trace" / "compile" / "pi" / "out" / "baseline.compiled.json",
        "replay_dir": DEFAULT_RUNS_DIR / "pi",
        "trigger": "pi",
        "replay_mount": "/workspace/replay",
        # T4/T5 runs are two-phase (command phase + agent run driven by the
        # scripted provider, including pi's first-prompt MCP tool wait); the
        # budget must cover both phases comfortably.
        "timeout_s": 300,
    },
    "openclaw": {
        "container": "t0-openclaw",
        "compile_py": HERE / "trace" / "compile" / "openclaw" / "compile.py",
        "compiled": HERE / "trace" / "compile" / "openclaw" / "out" / "baseline.compiled.json",
        "replay_dir": DEFAULT_RUNS_DIR / "openclaw",
        "trigger": "openclaw",
        "replay_mount": "/workspace/replay",
        "url": "http://127.0.0.1:28789",
        "token": "inspection-t0-token",
        "timeout_s": 120,
    },
    # The mock harness (the path-originator fixture, DESIGN.md 8): the
    # driver runs IN the fixture container (compose/t{N}-mock.yaml) via
    # docker exec — same pattern as pi, one exec per run — and reads the
    # canonical trace directly (no compiled-trace step: the driver compiles
    # each action through the same pi compiler in-container). Plan per
    # design: t0 runs the driver's built-in default plan (raw http route +
    # local stdio session); t1/t2 run the pinned gateway-route plan for the
    # http twin so it crosses the design's enforcement point (the
    # inspected-twin parity, DESIGN.md 8); t3 routes BOTH twins via the
    # gateway (the stdio twin's fs tools are proxied behind it — the T3
    # topology where the stdio transport is eliminated).
    "mock-harness": {
        "container": "t0-mock",
        "replay_dir": DEFAULT_RUNS_DIR / "mock",
        "trigger": "mock",
        "replay_mount": "/workspace/replay",
        "timeout_s": 120,
    },
}

# Deployment designs (main.tex Table 1). t0 = bare harness (no enforcement
# point); t1 = gateway for HTTP tools (compose/t1.yaml): every container name
# gains the t1- prefix and the enforcement-point record is captured per run.
DESIGNS = {
    "t0": {"prefix": "t0", "compose": "t0.yaml", "gateway": False},
    "t1": {"prefix": "t1", "compose": "t1.yaml", "gateway": True},
    # t2 = t1 + forced network egress (targets/egress-jail + compose/t2.yaml):
    # the two one-shot jail containers apply the default-deny netns policy and
    # exit; run_one docker-waits them BEFORE the replay so a run never starts
    # uninspected (see targets/egress-jail/apply.sh).
    # t2/t3 forced egress: direct connections to net-peer are rejected at the
    # harness netns output hook (targets/egress-jail/apply.sh)
    "t2": {"prefix": "t2", "compose": "t2.yaml", "gateway": True,
           "egress_jails": ["t2-egress-jail-pi", "t2-egress-jail-openclaw"]},
    # t3: gateway as sole enforcement point (fs tools proxied behind it) on
    # top of T2's forced egress
    "t3": {"prefix": "t3", "compose": "t3.yaml", "gateway": True,
           "egress_jails": ["t3-egress-jail-pi", "t3-egress-jail-openclaw"]},
    # t4: harness-native enforcement (pi permission chain). The
    # enforcement-point record is the adapter's decisions.jsonl on the replay
    # volume (same AuditEntry loader as the gateway's) — no policy file; the
    # record is copied from the replay dir, not docker-exec'd from a gateway.
    # Validated on the pi and openclaw harnesses (openclaw's before_tool_call
    # hook — see harnesses/openclaw/T4-INVESTIGATION.md).
    "t4": {"prefix": "t4", "compose": "t4.yaml", "gateway": True,
           "enforcement_record": "harness"},
    # t5: harness-native enforcement + gateway (the http tool calls cross
    # BOTH points via the http-stdio server's MCP_GATEWAY_URL forwarding).
    # Coverage input = the harness record (the union: both tool classes);
    # the gateway's record + policy are captured as the seam artifact.
    "t5": {"prefix": "t5", "compose": "t5.yaml", "gateway": True,
           "enforcement_record": "harness", "seam_gateway": True},
    # t6: in-process policy engine (T6_MODE + declarative policy mounted into
    # the harness). Same placement as t4; the policy file is captured per run
    # as the auditable policy artifact.
    "t6": {"prefix": "t6", "compose": "t6.yaml", "gateway": True,
           "enforcement_record": "harness", "harness_policy": "/opt/inspection/t6-policy.json"},
}


def harness_cfg(harness: str, design: str = "t0") -> dict:
    """Per-harness run config for a deployment design (containers are
    name-prefixed per compose project; t0 and t1 cannot run simultaneously)."""
    if design not in DESIGNS:
        raise ValueError(f"unknown design {design!r} (known: {sorted(DESIGNS)})")
    # t4: validated on the pi and openclaw harnesses (openclaw's
    # before_tool_call hook — see harnesses/openclaw/T4-INVESTIGATION.md)
    if design in ("t4", "t5", "t6") and harness not in ("pi", "openclaw"):
        raise ValueError(f"design {design} uses the harness-native "
                         "enforcement surface; validated on the pi and "
                         "openclaw harnesses (see T4-INVESTIGATION.md)")
    # the mock-harness fixtures exist for t0..t3 (compose/t{N}-mock.yaml;
    # plugins/mock-harness/manifest.json declares the same set)
    if harness == "mock-harness" and design not in ("t0", "t1", "t2", "t3"):
        raise ValueError(f"design {design} has no mock-harness fixture "
                         "(fixtures exist for t0, t1, t2, t3; "
                         "compose/t0-mock.yaml..t3-mock.yaml)")
    cfg = dict(HARNESSES[harness])
    prefix = DESIGNS[design]["prefix"]
    cfg["container"] = f"{prefix}-{harness}"
    cfg["design"] = design
    cfg["prefix"] = prefix
    if harness == "mock-harness":
        # the mock fixtures are their own compose projects: every container
        # name carries the t{N}-mock- prefix and the harness service itself
        # is t{N}-mock (harness_cfg callers derive the target/gateway/tracee
        # container names from cfg["prefix"], so one prefix covers all)
        cfg["container"] = f"{prefix}-mock"
        cfg["prefix"] = f"{prefix}-mock"
        # the twins' routes are plan data: t1/t2 run the pinned gateway
        # plan for the http twin in-container (mock_harness/plans/t{N}.json);
        # t3 routes BOTH twins via the gateway (the stdio twin's fs tools are
        # proxied behind it, no local server child); t0 keeps the built-in
        # default plan (raw http fetch + local stdio session, no enforcement
        # point to cross)
        if design in ("t1", "t2", "t3"):
            cfg["mock_plan"] = (f"{MOCK_HARNESS_REPO_MOUNT}/mock_harness/"
                               f"plans/{design}.json")
    return cfg


# shared target-log files (targets/common.py): toy-mcp-fs lives in the
# harness container; the network targets are standalone services (container
# names are per-design, see pull_target_logs)
TARGET_LOGS = {
    "toy-mcp-fs": None,           # in-harness container
    "http-endpoint": "http-endpoint",
    "net-peer": "net-peer",
}

# Tracee flushes events in batches (M6 finding: window-end lag 0.1-1 s).
# Grace before the docker-logs capture, and a longer wait before the single
# defensive re-capture when the first snapshot missed the window entirely.
TRACEE_FLUSH_GRACE_S = 3.0
TRACEE_RECAPTURE_WAIT_S = 10.0


# --- shell helpers ---------------------------------------------------------------


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    kw.setdefault("text", True)
    kw.setdefault("capture_output", True)
    proc = subprocess.run(cmd, **kw)
    if proc.returncode != 0 and kw.get("check", False):
        raise RuntimeError(f"command failed ({proc.returncode}): {' '.join(map(str, cmd))}\n"
                           f"{proc.stdout}\n{proc.stderr}")
    return proc


def docker_exec(container: str, cmd: str, check: bool = True) -> subprocess.CompletedProcess:
    return sh(["docker", "exec", container, "sh", "-c", cmd], check=check)


def container_id(name: str) -> str:
    proc = sh(["docker", "inspect", "-f", "{{.Id}}", name], check=True)
    return proc.stdout.strip()


def in_window_mapped(mapped_path: Path, window: dict, container_id: str | None,
                     tolerance_ns: int = 1_000_000_000) -> int:
    """Count mapped records inside the replay window for the harness
    container (0 -> the capture raced Tracee's flush; see run_one)."""
    if not Path(mapped_path).is_file():
        return 0
    lo = int(window["start"]) - tolerance_ns
    hi = int(window["end"]) + tolerance_ns
    n = 0
    with open(mapped_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line.startswith("{"):
                continue
            rec = json.loads(line)
            ts = rec.get("ts")
            if ts is None or not lo <= ts <= hi:
                continue
            if container_id is not None and (rec.get("container") or "") != container_id:
                continue
            n += 1
    return n


# --- pipeline stages -------------------------------------------------------------


def check_spec_hash() -> None:
    proc = sh([sys.executable, str(HERE / "trace" / "hash_spec.py"),
               "--check", str(HASH_SIDECAR), str(BASELINE)])
    if proc.returncode != 0:
        raise RuntimeError("canonical spec hash does not match its sidecar — "
                           "the spec changed; re-run trace/hash_spec.py --write-sidecar "
                           "and review the change")


def compile_harness(harness: str) -> Path:
    """Compile the canonical spec; --check must diff clean against it."""
    cfg = HARNESSES[harness]
    sh([sys.executable, str(cfg["compile_py"]), str(BASELINE),
        "--out", str(cfg["compiled"])], check=True)
    proc = sh([sys.executable, str(cfg["compile_py"]), str(BASELINE), "--check"])
    if proc.returncode != 0:
        raise RuntimeError(f"{harness}: compiled trace does not match the canonical spec")
    return cfg["compiled"]


def chown_target_logs(prefix: str = "t0") -> None:
    """Hand the shared target-log volume to uid 1000 (openclaw's node user).

    pi runs as root (can append regardless); openclaw runs as node (1000) and
    silently fails to append to root-owned files (targets/common.py tolerates
    the OSError) — chown before EVERY run, whichever harness ran last.
    Executed from a root context: the openclaw container user is root.
    """
    for container in (f"{prefix}-openclaw", f"{prefix}-pi"):
        proc = docker_exec(container, "chown -R 1000:1000 /var/log/targets 2>/dev/null || true",
                           check=False)
        if proc.returncode == 0:
            return
    print("warn: could not chown the target-logs volume (no root harness container?)",
          file=sys.stderr)


def mock_trigger_command(cfg: dict, run_id: str) -> list[str]:
    """The docker-exec argv that runs the mock-harness driver in the fixture
    container (pure argv construction, unit-tested): the runner stamps the
    run identity as env (the driver's dispatch records read
    INSPECTION_RUN_ID; DESIGN.md 4), sets the container cwd to the mounted
    repo, and runs `python3 -m mock_harness.driver` with the canonical trace
    + the per-design plan (harness_cfg: t1/t2 the pinned gateway route for
    the http twin, t3 the pinned gateway route for BOTH twins, t0 the
    driver's built-in default plan)."""
    cmd = ["docker", "exec",
           "-e", f"INSPECTION_RUN_ID={run_id}",
           # the repo mount is read-only; bytecode writes would fail with
           # EROFS and surface as unmatched kernel events
           "-e", "PYTHONDONTWRITEBYTECODE=1",
           "-w", MOCK_HARNESS_REPO_MOUNT,
           cfg["container"],
           "python3", "-m", "mock_harness.driver",
           "--trace", MOCK_DRIVER_TRACE,
           "--out", f"{cfg['replay_mount']}/{run_id}",
           "--run-id", run_id,
           "--mode", "all"]
    if cfg.get("mock_plan"):
        cmd += ["--plan", cfg["mock_plan"]]
    return cmd


def mock_replay_result(driver_run_dir: Path) -> dict:
    """Driver artifacts -> the replay-layer dict the shared reconcile/
    runrecord machinery consumes (the same shape the pi/openclaw adapters'
    replay-result.json carries): per-action results with id/class/op/status
    and the driver manifest's window_epoch_ns (the measurement window for
    capture/reconcile — the driver opens and closes it around the action
    loop)."""
    action_log = [json.loads(line) for line in
                  (driver_run_dir / "action-log.jsonl").read_text(
                      encoding="utf-8").splitlines() if line.strip()]
    driver_manifest = json.loads(
        (driver_run_dir / "run-manifest.json").read_text(encoding="utf-8"))
    window = driver_manifest.get("window_epoch_ns") or {}
    results = [{"id": r["id"], "class": r["class"], "op": r["op"],
               "status": r["status"], "error": r.get("error")}
               for r in action_log]
    failed = sum(1 for r in results if r["status"] != "ok")
    return {"ok": failed == 0,
            "executed": len(results), "failed": failed,
            "results": results,
            "window_epoch_ns": {"start": int(window.get("start") or 0),
                                 "end": int(window.get("end") or 0)},
            "mock_harness_digest": (driver_manifest.get("action_log")
                                    or {}).get("digest")}


def trigger_mock(cfg: dict, run_id: str, timeout_s: float) -> Path:
    """docker-exec the mock-harness driver in the fixture container and
    return the run's directory on the host (the mounted replay volume).

    The driver exits 0 when every action recorded status ok, 1 on any action
    error (the errors are data — design t2 direct-network refusals are the
    expected error status, adjudicated downstream by the prevented-class
    machinery), 2 on setup failures (bad pins/plan — a hard error)."""
    cmd = mock_trigger_command(cfg, run_id)
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout_s)
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"mock driver timed out after {timeout_s}s: "
                           f"{' '.join(cmd)}") from exc
    if proc.returncode == 2:
        raise RuntimeError(f"mock driver setup failed: {proc.stderr}")
    if proc.returncode not in (0, 1):
        raise RuntimeError(f"mock driver failed ({proc.returncode}): "
                           f"{proc.stderr}")
    # the driver runs as root in the container; hand the mounted artifacts
    # back to the host user (the same pattern as the openclaw trigger)
    docker_exec(cfg["container"],
                f"chown -R {os.getuid()}:{os.getgid()} "
                f"{cfg['replay_mount']}/{run_id}", check=False)
    out = Path(cfg["replay_dir"]) / run_id
    if not (out / "run-manifest.json").is_file():
        raise RuntimeError(f"mock driver did not write its run manifest "
                           f"({out / 'run-manifest.json'} missing)")
    return out


def trigger_replay(harness: str, run_id: str, timeout_s: float,
                   cfg: dict | None = None) -> tuple[dict, Path]:
    """Execute the compiled trace in the harness (no LLM); returns
    (replay result dict, replay-log path in the host replay dir)."""
    cfg = cfg or HARNESSES[harness]
    replay_dir = cfg["replay_dir"]

    if cfg["trigger"] == "mock":
        # the mock trigger: docker-exec the driver in the fixture container
        # (no compiled-trace staging — the driver reads the canonical spec
        # in-container; the replay-log slot carries the driver's
        # action-log.jsonl, copied into the run dir as replay-log.jsonl)
        driver_run_dir = trigger_mock(cfg, run_id, timeout_s)
        return mock_replay_result(driver_run_dir), driver_run_dir / "action-log.jsonl"

    compiled = cfg["compiled"]

    if cfg["trigger"] == "pi":
        import trigger_pi
        result = trigger_pi.run_replay(compiled, replay_dir, cfg["container"], timeout_s,
                                       design=cfg.get("design", "t0"), run_id=run_id)
        return result, replay_dir / "replay-log.jsonl"

    import trigger_openclaw as to
    # clean the previous run's replay log AND the enforcement-point record
    # (the t4/t6 hook appends decisions.jsonl; stale entries would pollute);
    # the dispatch records (M2a) join the cleanup list for the same reason
    docker_exec(cfg["container"],
                f"rm -f {cfg['replay_mount']}/replay-log.jsonl "
                f"{cfg['replay_mount']}/replay-result.json "
                f"{cfg['replay_mount']}/decisions.jsonl "
                f"{cfg['replay_mount']}/dispatch-records.jsonl", check=False)
    # M2a: stage the run identity for the adapter's dispatch records. The
    # long-lived OpenClaw gateway process cannot receive per-run env, so the
    # driver stages it as a file on the mounted replay volume; the adapters
    # (adapter/index.js, adapter/t4.js) read it with env INSPECTION_RUN_ID
    # as the fallback.
    (replay_dir / "run-id").write_text(f"{run_id}\n")
    if cfg.get("design") in ("t4", "t5", "t6") and cfg.get("trigger") == "openclaw":
        result = to.run_replay_t4(Path(compiled), replay_dir, cfg["container"],
                                   cfg["url"], cfg["token"], timeout_s)
        docker_exec(cfg["container"],
                    f"chown -R {os.getuid()}:{os.getgid()} {cfg['replay_mount']}", check=False)
        return result, replay_dir / "replay-log.jsonl"
    trace = json.loads(Path(compiled).read_text())
    to.wait_gateway(cfg["url"], cfg["token"], timeout_s=timeout_s)
    payload = to.invoke(cfg["url"], cfg["token"], trace,
                        idempotency_key=f"replay-{run_id}")
    result = payload.get("result") if isinstance(payload.get("result"), dict) else payload
    # hand the replay dir back to the host user (adapter writes as node)
    docker_exec(cfg["container"],
                f"chown -R {os.getuid()}:{os.getgid()} {cfg['replay_mount']}", check=False)
    return result, replay_dir / "replay-log.jsonl"


def capture_tracee(out_path: Path, container: str) -> None:
    with open(out_path, "wb") as fh:
        proc = subprocess.run(["docker", "logs", container],
                              stdout=fh, stderr=subprocess.DEVNULL)
    if proc.returncode != 0:
        raise RuntimeError(f"could not capture Tracee events from {container}")


def map_events(raw: Path, out_path: Path) -> None:
    sh([sys.executable, str(MAP_EVENTS), "--rules", str(RULES),
        "--in", str(raw), "--out", str(out_path)], check=True)


def pull_target_logs(out_dir: Path, cfg: dict) -> Path:
    """Copy each target's served-action log out of the shared volume."""
    out_dir.mkdir(parents=True, exist_ok=True)
    for name, service in TARGET_LOGS.items():
        c = service and f"{cfg['prefix']}-{service}" or cfg["container"]
        proc = docker_exec(c, f"cat /var/log/targets/{name}.log 2>/dev/null", check=False)
        (out_dir / f"{name}.log").write_text(proc.stdout or "")
    return out_dir


def pull_gateway_log(out_dir: Path, prefix: str, subdir: str = "gateway") -> Path:
    """Copy the enforcement-point record out of the gateway container:
    decisions.jsonl (the persistent gateway-logs volume; coverage.py scopes
    it to the replay window) and the deployed policy.yaml (manifest-hashed
    auditable artifact, T1-4). M2a: also the gateway's native
    decision-record/1 stream (decision-records.jsonl), retained per run for
    the C5 id-consistency check. Returns the run's record dir."""
    d = out_dir / subdir
    d.mkdir(parents=True, exist_ok=True)
    proc = docker_exec(f"{prefix}-gateway", "cat /var/log/gateway/decisions.jsonl 2>/dev/null",
                       check=False)
    (d / "decisions.jsonl").write_text(proc.stdout or "")
    proc = docker_exec(f"{prefix}-gateway", "cat $GATEWAY_POLICY 2>/dev/null", check=False)
    (d / "policy.yaml").write_text(proc.stdout or "")
    proc = docker_exec(f"{prefix}-gateway",
                       "cat /var/log/gateway/decision-records.jsonl 2>/dev/null",
                       check=False)
    (d / "decision-records.jsonl").write_text(proc.stdout or "")
    return d


def pull_harness_log(out_dir: Path, harness: str,
                     policy_container_path: str | None = None) -> Path:
    """T4/T6: the enforcement-point record is the harness log — the adapter's
    decisions.jsonl on the replay volume (runs/<harness>/ on the host). Same
    AuditEntry loader as the gateway's. For T6 the in-process policy file is
    additionally captured (manifest-hashed, like the gateway's policy.yaml).
    Returns the run's gateway/ dir so the runrecord/coverage plumbing is
    shared."""
    d = out_dir / "gateway"
    d.mkdir(parents=True, exist_ok=True)
    src = DEFAULT_RUNS_DIR / harness / "decisions.jsonl"
    text = src.read_text() if src.is_file() else ""
    (d / "decisions.jsonl").write_text(text)
    if policy_container_path:
        container = f"t6-{harness}"
        proc = docker_exec(container, f"cat {policy_container_path} 2>/dev/null", check=False)
        (d / "policy.json").write_text(proc.stdout or "")
    return d


def enforcement_artifacts(design: str, gateway_dir: Path | None,
                          out_dir: Path) -> dict[str, Path]:
    """Design-aware enforcement-point artifacts (manifest-hashed).
    t1-t3: the gateway's decisions + deployed policy.yaml. t4: the harness
    record only (allow-all permissions v1 — no policy file). t5: the harness
    record + the seam artifacts (the second point's decisions + deployed
    policy). t6: the harness record + the in-process policy.json."""
    arts: dict[str, Path] = {}
    if gateway_dir is not None:
        arts["gateway-decisions"] = gateway_dir / "decisions.jsonl"
        pol = gateway_dir / "policy.yaml"
        if not pol.is_file():
            pol = gateway_dir / "policy.json"
        if pol.is_file():
            arts["gateway-policy"] = pol
    if DESIGNS[design].get("seam_gateway"):
        seam = out_dir / "seam-gateway"
        arts["seam-gateway-decisions"] = seam / "decisions.jsonl"
        arts["seam-gateway-policy"] = seam / "policy.yaml"
    return arts


# --- one full run ----------------------------------------------------------------


NO_SENSOR_NOTE = ("degraded no-eBPF mode (DESIGN.md 9): no kernel sensor "
                  "ran; every outcome this run reports is a self-reported "
                  "claim, unverified")


def assemble_sensorless(spec_path: Path, profile: dict, replay: dict,
                        target_logs: list[dict] | None,
                        container_id: str | None, versions: dict,
                        harness: str, run_id: str, design: str = "t0",
                        gateway_log: Path | None = None,
                        gateway_policy: Path | None = None,
                        window_tolerance_ns: int = 1_000_000_000
                        ) -> tuple[dict, dict, dict]:
    """Assemble the run record + manifest for a degraded no-sensor run
    (DESIGN.md 9: "Degraded no-eBPF mode ... every output it produces is
    labeled self-reported / unverified. The claimed-vs-verified distinction
    is preserved even without the sensor").

    The kernel-dependent stages are SKIPPED and recorded as skipped, never
    silent: the R1-R5 reconciliation needs kernel ground truth (R3/R4/R5
    and the effective counts are kernel-derived), so the record's
    reconciliation section records status skipped-no-sensor with a note,
    and effective_counts stays null — claims never self-upgrade. What still
    computes: the replay layer, the served layer availability, the
    decision-log coverage (C1-C4, kernel-free), and the instance-level
    outcome classification from the replay statuses. `prevented` entries
    are replay-status claims without kernel corroboration: each is
    annotated as an unverified claim (prevented = deny record + verified
    absence of the kernel signature; without the sensor there is nothing
    to verify absence against).

    Returns (run_record, manifest, report) with the same shape as
    rr_mod.assemble so run_one's tail is shared; report.status is
    "skipped-no-sensor" (the audit view), while run_one reports the
    pipeline status separately.
    """
    spec = rec_mod.load_spec(spec_path)
    rules = yaml.safe_load((HERE / "sensor" / "mapping" / "rules.yaml")
                            .read_text())
    pinned = rr_mod.pinned_versions(versions, harness, rules)

    # decision-log coverage (C1-C4): kernel-free, same computation a
    # sensor run performs over the enforcement-point record
    coverage_report = None
    if design != "t0":
        if gateway_log is None:
            raise ValueError("design != t0 requires the enforcement-point "
                             "decisions log even without the sensor")
        decisions, parse_problems = cov_mod.load_decisions(gateway_log)
        w = replay.get("window_epoch_ns") or {}
        coverage_report = cov_mod.compute(
            spec, decisions, parse_problems, design,
            (int(w["start"]), int(w["end"])) if w else None,
            window_tolerance_ns)
        pinned["gateway_package"] = versions.get("GATEWAY_PACKAGE", "unknown")
        pinned["gateway_package_version"] = versions.get(
            "GATEWAY_PACKAGE_VERSION", "unknown")
        pinned["gateway_policy_version"] = versions.get(
            "GATEWAY_POLICY_VERSION", "unknown")

    # instance-level outcomes from the replay + coverage layers only;
    # prevented entries are marked unverified claims (kernel corroboration
    # is impossible without the sensor; DESIGN.md 9)
    outcomes = out_mod.compute(spec, replay, coverage_report, design)
    for row in outcomes["per_action"]:
        if row["outcome"] == "prevented":
            row["note"] = ("unverified claim: no kernel sensor ran in this "
                           "run (degraded no-eBPF mode); prevented requires "
                           "kernel verification (DESIGN.md 9)")

    sys.path.insert(0, str(HERE / "trace"))
    from hash_spec import canonical_hash as ch, raw_hash as rh  # noqa: E402

    gt_counts = {c: sum(1 for a in spec["actions"] if a["class"] == c)
                 for c in rec_mod.SIX_CLASSES}
    created = rr_mod.now_iso()
    run_record = {
        "schema": rr_mod.SCHEMA,
        "run_id": run_id,
        "created": created,
        "harness": harness,
        "design": design,
        "prevented_classes": sorted(
            rec_mod.PREVENTED_CLASSES.get(design, set())),
        "profile": profile["profile"],
        "container_id": container_id,
        "sensor": {"present": False, "mode": "no-sensor",
                   "note": NO_SENSOR_NOTE},
        "spec": {
            "name": spec["meta"]["name"], "version": spec["meta"]["version"],
            "path": str(spec_path),
            "canonical_sha256": ch(spec_path), "raw_sha256": rh(spec_path),
        },
        "mapping": {"version": rules.get("version"),
                    "rules": "sensor/mapping/rules.yaml",
                    "note": "no kernel events captured; the mapping layer "
                            "did not run"},
        "window_epoch_ns": replay.get("window_epoch_ns"),
        "ground_truth_counts": gt_counts,
        "effective_counts": None,   # kernel-derived; never a claim
        "replay": {"ok": replay.get("ok"),
                   "executed": replay.get("executed"),
                   "failed": replay.get("failed"),
                   "per_action": replay.get("results")},
        "served": {"available": bool(target_logs), "per_action": {}},
        "kernel": {"sensor_present": False,
                   "note": "no kernel evidence (degraded mode): R3/R4 "
                           "kernel accounting and C6 denial verification "
                           "cannot run"},
        "reconciliation": {"status": "skipped-no-sensor", "checks": [],
                           "leftovers": [],
                           "note": "R1-R5 need kernel ground truth; skipped "
                                   "in the degraded no-eBPF mode "
                                   "(DESIGN.md 9). Replay, served-layer "
                                   "availability, decision-log coverage "
                                   "(C1-C4), and outcome classification "
                                   "still computed."},
        "coverage": coverage_report,
        "outcomes": outcomes,
        "pinned": pinned,
    }
    manifest = {
        "schema": rr_mod.MANIFEST_SCHEMA,
        "run_id": run_id,
        "harness": harness,
        "design": design,
        "created": created,
        "spec_sha256": run_record["spec"]["canonical_sha256"],
        "mapping_version": pinned["mapping_version"],
        "sensor_present": False,
        "degraded": ["sensor-absent"],
        "reconciliation": "skipped-no-sensor",
        "coverage": (coverage_report or {}).get("status")
                    if design != "t0" else None,
        "versions": pinned,
        "timing": {"window_epoch_ns": replay.get("window_epoch_ns"),
                   "runrecord_created": created},
    }
    report = {
        "schema": "inspection-reconciliation/1",
        "status": "skipped-no-sensor",
        "harness": profile["harness"],
        "profile": profile["profile"],
        "note": NO_SENSOR_NOTE,
        "window_epoch_ns": replay.get("window_epoch_ns"),
        "ground_truth_counts": gt_counts,
        "effective_counts": None,
        "checks": [],
        "leftovers": [],
    }
    return run_record, manifest, report


def run_one(harness: str, run_id: str, runs_dir: Path, timeout_s: float | None = None,
            design: str = "t0", sensor: bool = True) -> dict:
    cfg = harness_cfg(harness, design)
    prefix = cfg["prefix"]
    tracee = f"{prefix}-tracee"
    out_dir = Path(runs_dir) / run_id
    if out_dir.exists():
        raise RuntimeError(f"run dir {out_dir} already exists (choose a new --run-id)")
    timeout_s = timeout_s or cfg["timeout_s"]

    check_spec_hash()
    # the mock harness reads the canonical trace directly in-container (the
    # driver compiles each action through the same pi compiler); the real
    # harnesses stage a compiled trace, so the compile/diff-check step and
    # the target-logs chown (a node/openclaw uid issue) are theirs only
    if harness == "mock-harness":
        compiled = None
    else:
        compiled = compile_harness(harness)
        chown_target_logs(cfg["prefix"])

    # T2+: gate the replay on the egress jails having applied their netns
    # policy cleanly (they are one-shot containers that exit after nft -f).
    # The mock fixture has exactly one jail (on the mock service's netns).
    egress_jails = DESIGNS[design].get("egress_jails") or []
    if harness == "mock-harness" and egress_jails:
        egress_jails = [f"{cfg['prefix']}-egress-jail"]
    for name in egress_jails:
        proc = sh(["docker", "wait", name], check=False)
        code = (proc.stdout or "").strip()
        if proc.returncode != 0 or code != "0":
            raise RuntimeError(
                f"egress jail {name} did not apply cleanly "
                f"(wait rc={proc.returncode}, container exit={code!r})")

    print(f"[{run_id}] replaying {harness} ({design}) ...", file=sys.stderr)
    result, replay_log_src = trigger_replay(harness, run_id, timeout_s, cfg)  # noqa: E501
    if not result.get("ok"):
        # design-aware: failures are only tolerated for PREVENTED actions
        # (design t2: refused by the egress policy with a refusal errno) and
        # for DENIED tool calls (checked-DENY: the enforcement point refused
        # the call — a valid terminal state for t1+ designs; a spurious
        # denial, i.e. no backed decision, fails coverage/outcomes). Any
        # other failure aborts the run before reconciliation.
        prevented = rec_mod.PREVENTED_CLASSES.get(design, set())
        spec = rec_mod.load_spec(BASELINE)
        spec_class = {a["id"]: a["class"] for a in spec["actions"]}

        def _bad(r: dict) -> bool:
            status = r.get("status")
            if status == "denied":
                # a spurious denial (design t0 has no enforcement point to
                # deny) is a failure; t1+ denials are corroborated downstream
                return design == "t0"
            if status == "ok":
                return False
            return not (spec_class.get(r.get("id")) in prevented
                        and status == "error")

        bad = [r for r in result.get("results") or [] if _bad(r)]
        if bad:
            raise RuntimeError(
                f"replay failed: {[b['id'] for b in bad]} "
                f"({', '.join(str(b.get('error')) for b in bad)})")

    out_dir.mkdir(parents=True)
    (out_dir / "replay-result.json").write_text(json.dumps(result, indent=1) + "\n")
    if Path(replay_log_src).is_file():
        shutil.copyfile(replay_log_src, out_dir / "replay-log.jsonl")
    # the adapter's dispatch records (M2a; DESIGN.md 3 collect(): dispatch-
    # record flush) land next to the replay log on the mounted volume and are
    # retained per run like every other raw artifact
    dispatch_src = Path(replay_log_src).parent / "dispatch-records.jsonl"
    if dispatch_src.is_file():
        shutil.copyfile(dispatch_src, out_dir / "dispatch-records.jsonl")
    if harness == "mock-harness":
        # the driver's own run manifest (trace/plan pins, window, digest) is
        # retained as the mock-run provenance artifact (named to avoid
        # clashing with the runner's manifest.json); the replay-log slot
        # above carries the driver's action-log.jsonl
        driver_manifest_src = Path(replay_log_src).parent / "run-manifest.json"
        if driver_manifest_src.is_file():
            shutil.copyfile(driver_manifest_src,
                            out_dir / "mock-run-manifest.json")
    if compiled is not None:
        compiled_dir = out_dir / "compiled-trace"
        compiled_dir.mkdir()
        shutil.copyfile(compiled, compiled_dir / Path(compiled).name)

    if sensor:
        print(f"[{run_id}] capturing Tracee events ...", file=sys.stderr)
        time.sleep(TRACEE_FLUSH_GRACE_S)   # Tracee flushes in batches (M6: up to ~1 s lag)
        capture_tracee(out_dir / "tracee-events.json", tracee)
        sh([sys.executable, str(MAP_EVENTS), "--rules", str(RULES),
            "--in", str(out_dir / "tracee-events.json"),
            "--out", str(out_dir / "mapped-actions.jsonl")], check=True)
    else:
        # degraded no-eBPF mode (DESIGN.md 9): the sensor container is not
        # up (compose without --profile sensor); no kernel evidence is
        # captured and nothing downstream may treat this run as verified
        print(f"[{run_id}] degraded no-sensor mode: no kernel capture "
              f"(outcomes will be self-reported claims)", file=sys.stderr)
    cid = container_id(cfg["container"])
    if sensor:
        # Defensive recapture: if the first docker-logs snapshot raced Tracee's
        # batch flush entirely (observed live 2026-09-10: a run's full window
        # missing from the captured stream), wait longer and re-capture ONCE —
        # docker logs only appends, so the re-capture is a superset.
        if in_window_mapped(out_dir / "mapped-actions.jsonl",
                            result["window_epoch_ns"], cid) == 0:
            print(f"[{run_id}] no in-window events for the harness container; "
                  f"Tracee flush lag suspected — re-capturing after "
                  f"{TRACEE_RECAPTURE_WAIT_S}s", file=sys.stderr)
            time.sleep(TRACEE_RECAPTURE_WAIT_S)
            capture_tracee(out_dir / "tracee-events.json", tracee)
            sh([sys.executable, str(MAP_EVENTS), "--rules", str(RULES),
                "--in", str(out_dir / "tracee-events.json"),
                "--out", str(out_dir / "mapped-actions.jsonl")], check=True)

        # Fast two-phase runs (openclaw t4-t6: ~1-2 s end to end) can finish
        # inside Tracee's 30-90 s batch-flush lag: the in-window stdio writes of
        # the lazily spawned MCP sessions surface only in a later batch, while
        # earlier classes and the pre-window handshakes are already present
        # (observed live 2026-10-08). If the enforcement-point record shows stdio
        # tool calls but the kernel window has none, wait out the flush lag and
        # re-capture once (docker logs appends: the re-capture is a superset).
        if design in ("t4", "t5", "t6"):
            mapped_recs = [json.loads(l) for l in open(out_dir / "mapped-actions.jsonl")]
            win = result["window_epoch_ns"]
            in_win_stdio = sum(
                1 for r in mapped_recs
                if r.get("class") == "stdio_tool_call" and r.get("ts")
                and win["start"] <= r["ts"] <= win["end"]
                and (cid is None or r.get("container") == cid))
            stdio_calls_made = 0
            dec_f = DEFAULT_RUNS_DIR / harness / "decisions.jsonl"
            if dec_f.is_file():
                for l in open(dec_f):
                    try: d = json.loads(l)
                    except Exception: continue
                    if d.get("tool_name") in ("write_file", "read_file", "list_directory"):
                        stdio_calls_made += 1
            if stdio_calls_made > 0 and in_win_stdio == 0:
                wait_s = int(TRACEE_RECAPTURE_WAIT_S) * 9   # ~90 s: the documented batch lag
                print(f"[{run_id}] in-window stdio writes missing while the "
                      f"enforcement record shows {stdio_calls_made} stdio tool "
                      f"calls; Tracee batch flush lag — re-capturing after {wait_s} s",
                      file=sys.stderr)
                time.sleep(wait_s)
                capture_tracee(out_dir / "tracee-events.json", tracee)
                sh([sys.executable, str(MAP_EVENTS), "--rules", str(RULES),
                    "--in", str(out_dir / "tracee-events.json"),
                    "--out", str(out_dir / "mapped-actions.jsonl")], check=True)

    pull_target_logs(out_dir / "target-logs", cfg)

    # enforcement-point record + coverage (t1+; T1-4 computation in runrecord)
    if DESIGNS[design].get("enforcement_record") == "harness":
        gateway_dir = pull_harness_log(out_dir, harness,
                                       DESIGNS[design].get("harness_policy"))
        if DESIGNS[design].get("seam_gateway"):
            # t5: the second enforcement point's record (seam analysis)
            pull_gateway_log(out_dir, prefix, subdir="seam-gateway")
    else:
        gateway_dir = (pull_gateway_log(out_dir, prefix)
                       if DESIGNS[design]["gateway"] else None)

    # reconcile + run record (C7/C8 libraries; run-record written even on fail)
    profile = rec_mod.load_profile(HERE / "runner" / "profiles" / f"{harness}.yaml")
    if sensor:
        run_record, manifest, report = rr_mod.assemble(
            BASELINE, profile, rec_mod.load_replay(out_dir / "replay-result.json"),
            rec_mod.load_mapped(out_dir / "mapped-actions.jsonl"),
            rec_mod.load_target_logs([str(out_dir / "target-logs")]),
            cid, rr_mod.load_versions(VERSIONS),
            harness, run_id, design=design,
            gateway_log=gateway_dir / "decisions.jsonl" if gateway_dir else None,
            gateway_policy=(gateway_dir / "policy.yaml" if (gateway_dir / "policy.yaml").is_file()
                            else gateway_dir / "policy.json" if (gateway_dir / "policy.json").is_file()
                            else None) if gateway_dir else None,
            window_tolerance_ns=int(profile.get("window_tolerance_ns", 1_000_000_000)))
    else:
        # degraded no-eBPF mode: the kernel-dependent assembly is replaced
        # by the sensorless one (R1-R5 skipped-with-note, outcomes labeled
        # self-reported; DESIGN.md 9)
        run_record, manifest, report = assemble_sensorless(
            BASELINE, profile, rec_mod.load_replay(out_dir / "replay-result.json"),
            rec_mod.load_target_logs([str(out_dir / "target-logs")]),
            cid, rr_mod.load_versions(VERSIONS),
            harness, run_id, design=design,
            gateway_log=gateway_dir / "decisions.jsonl" if gateway_dir else None,
            gateway_policy=(gateway_dir / "policy.yaml" if (gateway_dir / "policy.yaml").is_file()
                            else gateway_dir / "policy.json" if (gateway_dir / "policy.json").is_file()
                            else None) if gateway_dir else None,
            window_tolerance_ns=int(profile.get("window_tolerance_ns", 1_000_000_000)))
    artifacts = {
        "replay-result": out_dir / "replay-result.json",
        "replay-log": out_dir / "replay-log.jsonl",
    }
    if harness == "mock-harness" and (out_dir / "mock-run-manifest.json").is_file():
        artifacts["mock-run-manifest"] = out_dir / "mock-run-manifest.json"
    if sensor:
        artifacts["tracee-events"] = out_dir / "tracee-events.json"
        artifacts["mapped-actions"] = out_dir / "mapped-actions.jsonl"
    # else: the degraded run retains no kernel artifacts (they do not
    # exist); check_artifacts()/artifact_statuses() on such a manifest
    # report them skipped-no-sensor, not missing (DESIGN.md 9: a valid
    # degraded run must not fail the artifact check)
    artifacts.update(enforcement_artifacts(design, gateway_dir, out_dir))
    rr_mod.add_artifact_hashes(manifest, artifacts)
    (out_dir / "run-record.json").write_text(
        json.dumps(run_record, indent=1, sort_keys=True) + "\n")
    (out_dir / "manifest.json").write_text(
        json.dumps(manifest, indent=1, sort_keys=True) + "\n")
    (out_dir / "reconciliation.json").write_text(
        json.dumps(report, indent=1, sort_keys=True) + "\n")
    (out_dir / "outcomes.json").write_text(
        json.dumps(run_record.get("outcomes") or {}, indent=1,
                   sort_keys=True) + "\n")
    if gateway_dir is not None:
        (out_dir / "coverage.json").write_text(
            json.dumps(run_record.get("coverage") or {}, indent=1,
                       sort_keys=True) + "\n")

    cov_status = (run_record.get("coverage") or {}).get("status", "pass")
    out_status = (run_record.get("outcomes") or {}).get("status", "pass")
    print(f"[{run_id}] reconciliation: {report['status']}; coverage: {cov_status}; "
          f"outcomes: {out_status}; "
          f"effective counts: {report['effective_counts']}", file=sys.stderr)
    # the returned status is the pipeline status: a degraded run that ran
    # its (reduced, self-reported) pipeline cleanly is a completed run; the
    # run record keeps the audit distinction (reconciliation: skipped-no-
    # sensor, sensor.present: false) and the framework labels the run
    # self-reported (DESIGN.md 9)
    pipeline_status = ("pass" if cov_status == "pass" and out_status == "pass"
                      else "fail") if not sensor else report["status"]
    return {"run_id": run_id, "harness": harness, "design": design,
            "out_dir": str(out_dir),
            "status": pipeline_status, "coverage": cov_status,
            "outcomes": out_status,
            "sensor_present": sensor,
            "effective_counts": report["effective_counts"],
            "ground_truth_counts": run_record["ground_truth_counts"],
            "spec_sha256": run_record["spec"]["canonical_sha256"]}


# --- programmatic entry (execution wiring) ---------------------------------------


def run_design(harness: str, design: str, run_id: str,
               runs_dir: Path | None = None,
               timeout_s: float | None = None,
               sensor: bool = True) -> dict:
    """Minimal programmatic entry for one full run: validate the harness +
    design pairing, then delegate to run_one with the prepared defaults.
    The CLI keeps its own argument handling and calls run_one exactly as
    before (behavior-preserving); this entry exists so the execution layer
    (framework/execute.py) drives the runner through one named function
    instead of CLI-only plumbing. sensor=False drives the degraded no-eBPF
    path (DESIGN.md 9): no sensor container, no kernel evidence, every
    output self-reported."""
    if harness not in HARNESSES:
        raise ValueError(f"unknown harness {harness!r} "
                         f"(known: {sorted(HARNESSES)})")
    harness_cfg(harness, design)   # validates the design + pairing
    return run_one(harness, run_id, Path(runs_dir) if runs_dir is not None
                   else DEFAULT_RUNS_DIR, timeout_s, design, sensor=sensor)


# --- reproducibility (rerun) ------------------------------------------------------


def counts_identical(counts_by_run: dict[str, dict[str, int]]) -> bool:
    values = list(counts_by_run.values())
    return bool(values) and all(v == values[0] for v in values)


def reproducibility_verdict(summaries: list[dict]) -> dict:
    """Rerun criterion: identical effective per-class counts across >=2
    consecutive runs, each of which reconciles pass. For design t1 a run
    additionally reconciles only when the coverage section passes (T1-4),
    so the verdict requires every run's coverage to pass too (runs without
    a coverage section — t0 — are unaffected)."""
    counts = {s["run_id"]: s["effective_counts"] for s in summaries}
    all_pass = all(s["status"] == "pass" for s in summaries)
    coverage = {s["run_id"]: s.get("coverage", "pass") for s in summaries}
    all_covered = all(v == "pass" for v in coverage.values())
    identical = counts_identical(counts)
    ok = (len(summaries) >= 2 and all_pass and all_covered and identical)
    return {
        "schema": "inspection-reproducibility/1",
        "harness": summaries[0]["harness"] if summaries else None,
        "design": summaries[0].get("design", "t0") if summaries else None,
        "runs": [s["run_id"] for s in summaries],
        "reconciliation": {s["run_id"]: s["status"] for s in summaries},
        "coverage": coverage,
        "effective_counts_by_run": counts,
        "identical_counts": identical,
        "all_reconciled": all_pass,
        "all_covered": all_covered,
        "status": "pass" if ok else "fail",
    }


def run_rerun(harness: str, label: str, n: int, runs_dir: Path,
              timeout_s: float | None = None, design: str = "t0") -> dict:
    if n < 2:
        raise ValueError("rerun needs >= 2 consecutive runs")
    summaries = []
    for i in range(1, n + 1):
        run_id = f"{harness}-{label}-r{i}"
        summaries.append(run_one(harness, run_id, runs_dir, timeout_s, design))
    verdict = reproducibility_verdict(summaries)
    verdict["spec_sha256"] = summaries[0]["spec_sha256"]
    out = Path(runs_dir) / f"{harness}-{label}" / "reproducibility.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(verdict, indent=1, sort_keys=True) + "\n")
    print(json.dumps(verdict, indent=1))
    return verdict


# --- T0 report -------------------------------------------------------------------


WARMUP_PREFIX = "warmup-"


def collect_run_records(runs_dir: Path) -> list[dict]:
    """All run records under runs_dir (one level: runs/<run-id>/run-record.json)."""
    records = []
    if not Path(runs_dir).is_dir():
        return records
    for d in sorted(Path(runs_dir).iterdir()):
        f = d / "run-record.json"
        if d.is_dir() and f.is_file():
            rec = json.loads(f.read_text())
            rec["_dir"] = str(d)
            records.append(rec)
    return records


BASE_ARTIFACTS = ("tracee-events", "mapped-actions", "replay-result", "replay-log")

# Kernel-evidence artifacts: produced only when the sensor ran. In the
# degraded no-eBPF mode (DESIGN.md 9: no kernel sensor, every output
# labeled self-reported / unverified) they are expected-absent and are
# reported skipped-no-sensor, not missing.
KERNEL_ARTIFACTS = ("tracee-events", "mapped-actions")


def manifest_sensorless(manifest: dict) -> bool:
    """Whether this manifest describes a sensor-less (degraded no-eBPF)
    run: the run manifest stamps sensor_present: false and degraded:
    [sensor-absent] (assemble_sensorless), and the run record carries
    sensor.present: false. A manifest with none of these stamps is a sensor
    run — the check is never allowed to turn a sensor run's missing kernel
    artifacts into an expected absence."""
    if manifest.get("sensor_present") is False:
        return True
    if "sensor-absent" in (manifest.get("degraded") or []):
        return True
    sensor = manifest.get("sensor")
    return isinstance(sensor, dict) and sensor.get("present") is False


def _required_artifacts(design: str) -> list[str]:
    required = list(BASE_ARTIFACTS)
    if design != "t0":
        required += ["gateway-decisions"]
    if design in ("t1", "t2", "t3", "t6"):
        required += ["gateway-policy"]
    if design == "t5":
        required += ["seam-gateway-decisions", "seam-gateway-policy"]
    return required


def artifact_statuses(manifest: dict) -> dict[str, str]:
    """T0 criterion 4 (all raw artifacts retained + hashed), sensor-aware:
    required artifact name -> status. `present`: hashed in the manifest;
    `missing`: required but not retained/hashed (a defect);
    `skipped-no-sensor`: a kernel-evidence artifact of a sensor-less run
    (the degraded no-eBPF mode, DESIGN.md 9) — expected-absent, never a
    failure for a valid degraded run. Design-aware enforcement-point
    requirements: the record (decisions) for every t1+ design; the policy
    file only where the design deploys one (gateway/policy.yaml t1-t3,
    in-process policy.json t6); t5 hashes the second point's record +
    policy as the seam artifacts."""
    design = manifest.get("design") or "t0"
    sensorless = manifest_sensorless(manifest)
    statuses: dict[str, str] = {}
    for name in _required_artifacts(design):
        art = (manifest.get("artifacts") or {}).get(name) or {}
        if art.get("sha256") and art.get("bytes"):
            statuses[name] = "present"
        elif sensorless and name in KERNEL_ARTIFACTS:
            statuses[name] = "skipped-no-sensor"
        else:
            statuses[name] = "missing"
    return statuses


def check_artifacts(manifest: dict) -> list[str]:
    """The missing raw artifacts (T0 criterion 4), sensor-aware: the
    kernel-evidence artifacts of a sensor-less run are expected-absent and
    are reported by artifact_statuses() as skipped-no-sensor, not missing
    (DESIGN.md 9). Design-aware enforcement-point requirements follow the
    design stamp exactly as documented on artifact_statuses()."""
    return [name for name, status in artifact_statuses(manifest).items()
            if status == "missing"]


def load_repro_verdicts(runs_dir: Path, harness: str) -> list[dict]:
    """Rerun-mode verdicts: runs/<harness>-<label>/reproducibility.json."""
    out = []
    if not Path(runs_dir).is_dir():
        return out
    for d in sorted(Path(runs_dir).iterdir()):
        f = d / "reproducibility.json"
        if d.is_dir() and f.is_file():
            try:
                v = json.loads(f.read_text())
            except json.JSONDecodeError:
                continue
            if v.get("harness") == harness:
                out.append({"dir": d.name, "status": v.get("status"),
                            "runs": v.get("runs", []),
                            "design": v.get("design", "t0")})
    return out


def build_report(runs_dir: Path, design: str = "t0") -> dict:
    """Summary table + done-criteria checklist over the run records of one
    deployment design (records carry `design`; pre-T1-5 records default t0).
    Warmup runs (`warmup-` prefix: pre-measurement first run (warmup), window not
    clean) are excluded: their reconciliation status is meaningless for the
    done criteria and must not enter the gate, the counting, or
    `runs_recorded`. For t1, a record is a pass only when reconciliation AND
    its coverage section pass, and the design criterion additionally
    requires the observed per-class coverage to match the inspected set
    (inspected classes fully covered, non-inspected classes at 0.0)."""
    records = [r for r in collect_run_records(runs_dir)
               if r.get("design", "t0") == design
               and not r.get("run_id", "").startswith(WARMUP_PREFIX)]
    inspected = sorted(cov_mod.INSPECTED_CLASSES.get(design, set()))
    by_harness: dict[str, list[dict]] = {}
    for rec in records:
        by_harness.setdefault(rec["harness"], []).append(rec)

    rows = []
    acceptance = {}
    for harness in ("pi", "openclaw"):
        runs = by_harness.get(harness, [])
        counts = {r["run_id"]: r["effective_counts"] for r in runs}
        missing_artifacts = {}
        skipped_no_sensor = {}
        for r in runs:
            mf = Path(r["_dir"]) / "manifest.json"
            if mf.is_file():
                manifest = json.loads(mf.read_text())
                missing_artifacts[r["run_id"]] = check_artifacts(manifest)
                # sensor-less runs skip the kernel artifacts (expected-
                # absent, DESIGN.md 9): visible in the report, never a
                # failure and never silently dropped
                skips = [n for n, s in artifact_statuses(manifest).items()
                         if s == "skipped-no-sensor"]
                if skips:
                    skipped_no_sensor[r["run_id"]] = skips
        passing = [r for r in runs if r["reconciliation"]["status"] == "pass"]
        # aggregated instance-level outcome counts (checked/bypassed/
        # prevented) over the passing runs' classifications, plus the gate:
        # every passing run's classification must itself pass (no
        # indeterminate instance)
        outcome_counts: dict[str, int] = {}
        for r in passing:
            for k, v in ((r.get("outcomes") or {}).get("counts") or {}).items():
                outcome_counts[k] = outcome_counts.get(k, 0) + v
        all_outcomes_pass = bool(passing) and all(
            (r.get("outcomes") or {}).get("status", "pass") == "pass"
            for r in passing)
        # The reproducibility criterion is demonstrated by the rerun-mode
        # reproducibility verdicts (>=2 consecutive runs, identical
        # counts, each reconciling pass). The table only lists run records
        # present on disk; failed runs removed under the raw-trace retention
        # policy therefore drop out of the table, while their rerun verdict
        # (e.g. the failed openclaw-m7 pair) stays auditable in its
        # reproducibility.json. Verdicts do not by themselves decide the
        # criterion.
        verdicts = load_repro_verdicts(runs_dir, harness)
        verdicts = [v for v in verdicts if v.get("design", "t0") == design]
        repro = {
            "design": design,
            "runs_recorded": len(runs),
            "identical_counts": counts_identical(counts) if len(runs) >= 2 else None,
            "all_reconciled_pass": (len(passing) == len(runs) and bool(runs)),
            "artifacts_complete": all(not m for m in missing_artifacts.values()) if missing_artifacts else False,
            "artifacts_skipped_no_sensor": skipped_no_sensor,
            "rerun_verdicts": verdicts,
        }
        if design != "t0":
            covs = {r["run_id"]: (r.get("coverage") or {}).get("status") for r in runs}
            repro["coverage"] = covs
            repro["all_covered_pass"] = bool(runs) and all(v == "pass" for v in covs.values())
            # the measured matrix must match the design's inspected set
            repro["coverage_matches_design"] = all(
                _coverage_matches_design(r.get("coverage") or {}, inspected)
                for r in passing)
        repro["t0_criteria_met"] = bool(
            runs and repro["artifacts_complete"]
            and any(v["status"] == "pass" for v in verdicts)
            and all_outcomes_pass)
        repro["outcome_counts"] = outcome_counts
        acceptance[harness] = repro
        for r in runs:
            row = {"run_id": r["run_id"], "harness": harness,
                   "reconciliation": r["reconciliation"]["status"],
                   "coverage": (r.get("coverage") or {}).get("status", "-"),
                   "spec_sha256": r["spec"]["canonical_sha256"][:12],
                   "mapping_version": r["mapping"]["version"],
                   "counts": r["effective_counts"],
                   "ground_truth": r["ground_truth_counts"]}
            if design != "t0":
                row["coverage_per_class"] = {
                    c: v.get("coverage") for c, v in
                    (r.get("coverage") or {}).get("coverage", {}).items()}
            rows.append(row)

    spec_counts = rows[0]["ground_truth"] if rows else None

    # per-class outcome matrix (checked / prevented / bypassed), derived from
    # the MEASURED records of passing runs — the coverage section (decision
    # log) and the prevented classes the reconciliation held fixed — not from
    # the design map alone. Resolves the 0.0-ambiguity of the per-class
    # coverage fraction, which conflates bypassed with prevented.
    matrix: dict[str, dict[str, str]] = {}
    for harness in ("pi", "openclaw"):
        runs = by_harness.get(harness, [])
        passing = [r for r in runs if r["reconciliation"]["status"] == "pass"]
        if not passing:
            continue
        rec = passing[-1]
        prevented = set(rec.get("prevented_classes") or [])
        cov = (rec.get("coverage") or {}).get("coverage") or {}
        outcome = {}
        for c in rec_mod.SIX_CLASSES:
            cc = cov.get(c) or {}
            if c in prevented:
                outcome[c] = "prevented"
            elif cc.get("ground_truth") and cc.get("covered") == cc.get("ground_truth"):
                outcome[c] = "checked"
            else:
                outcome[c] = "bypassed"
        matrix[harness] = outcome

    return {
        "schema": "inspection-t0-report/1",
        "design": design,
        "inspected_classes": inspected,
        "runs_dir": str(runs_dir),
        "spec_ground_truth_counts": spec_counts,
        "runs": rows,
        "coverage_matrix": matrix,
        "acceptance": acceptance,
    }


def _coverage_matches_design(coverage: dict, inspected: list[str]) -> bool:
    """Observed per-class coverage matches the design's inspected set:
    inspected classes at 1.0, non-inspected classes at exactly 0.0 (a partial
    non-inspected coverage means actions crossed outside the inspected set)."""
    per_class = coverage.get("coverage") or {}
    if not per_class:
        return False
    for cls, v in per_class.items():
        if v.get("coverage") != (1.0 if cls in inspected else 0.0):
            return False
    return True


def render_markdown(report: dict) -> str:
    design = report.get("design", "t0")
    titles = {
        "t0": "T0 report — inspection coverage baseline (bare harness)",
        "t1": "T1 report — gateway for HTTP tools, no egress restriction",
    }
    lines = [f"# {titles.get(design, design)}", ""]
    if design != "t0":
        lines += [f"Inspected classes (cross the enforcement point): "
                  f"{', '.join(report.get('inspected_classes') or [])}", ""]
    gt = report.get("spec_ground_truth_counts")
    if gt:
        lines += ["Spec ground-truth counts: " +
                  ", ".join(f"{c}={n}" for c, n in gt.items()), ""]
    lines += ["| harness | run | recon | cov | " + " | ".join(SIX_CLASSES) + " |",
              "|" + "---|" * (4 + len(SIX_CLASSES))]
    for row in report["runs"]:
        lines.append("| " + " | ".join(
            [row["harness"], row["run_id"], row["reconciliation"],
             str(row.get("coverage", "-"))]
            + [str(row["counts"].get(c, "-")) for c in SIX_CLASSES]) + " |")
    matrix = report.get("coverage_matrix") or {}
    if matrix:
        lines += ["", "## Instance-level outcome counts (measured)", ""]
        for harness, a in report["acceptance"].items():
            oc = a.get("outcome_counts") or {}
            if oc:
                lines.append(f"- **{harness}**: " + ", ".join(
                    f"{k}={v}" for k, v in sorted(oc.items())))
        lines += ["", "## Per-class outcome matrix (measured)", ""]
        lines += ["| harness | " + " | ".join(SIX_CLASSES) + " |",
                  "|" + "---|" * (1 + len(SIX_CLASSES))]
        for harness, outcome in matrix.items():
            lines.append("| " + " | ".join(
                [harness] + [outcome.get(c, "-") for c in SIX_CLASSES]) + " |")
    lines += ["", "## Done-criteria", ""]
    for harness, a in report["acceptance"].items():
        v_pass = [v for v in a["rerun_verdicts"] if v["status"] == "pass"]
        extra = ""
        if design != "t0":
            extra = (f", coverage all pass={a.get('all_covered_pass')}, "
                     f"coverage matches design={a.get('coverage_matches_design')}")
        lines.append(f"- **{harness}**: runs={a['runs_recorded']}, "
                     f"rerun verdicts={v_pass or a['rerun_verdicts']}, "
                     f"artifacts retained={a['artifacts_complete']}{extra}, "
                     f"**met: {a['t0_criteria_met']}**")
    lines += ["", "Note: the v1 harness set is Pi + OpenClaw; OpenCode was "
              "deferred in M5 (no no-LLM tool-execute route in 1.18.30) — see "
              "implementation-plan.md M5.", ""]
    return "\n".join(lines)


# --- CLI -------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("compile", help="compile the canonical spec + diff check")
    p.add_argument("--harness", default="all", choices=["pi", "openclaw", "all"])

    p = sub.add_parser("run", help="one full run (compile -> replay -> reconcile -> record)")
    p.add_argument("--harness", required=True, choices=sorted(HARNESSES))
    p.add_argument("--design", default="t0", choices=sorted(DESIGNS))
    p.add_argument("--run-id", required=True)
    p.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS_DIR)
    p.add_argument("--timeout", type=float, default=None)
    p.add_argument("--no-sensor", action="store_true",
                   help="degraded no-eBPF mode (DESIGN.md 9): run without "
                        "the sensor (compose up WITHOUT --profile sensor); "
                        "no kernel evidence, every outcome is a "
                        "self-reported claim")

    p = sub.add_parser("rerun", help="N consecutive runs + reproducibility verdict")
    p.add_argument("--harness", required=True, choices=sorted(HARNESSES))
    p.add_argument("--design", default="t0", choices=sorted(DESIGNS))
    p.add_argument("--runs", type=int, default=2)
    p.add_argument("--label", default="rerun")
    p.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS_DIR)
    p.add_argument("--timeout", type=float, default=None)

    p = sub.add_parser("reconcile", help="re-reconcile + re-assemble from retained artifacts")
    p.add_argument("--harness", required=True, choices=sorted(HARNESSES))
    p.add_argument("--design", default="t0", choices=sorted(DESIGNS))
    p.add_argument("--run-dir", type=Path, required=True)

    p = sub.add_parser("report", help="summary table + done-criteria checklist")
    p.add_argument("--design", default="t0", choices=sorted(DESIGNS))
    p.add_argument("--runs-dir", type=Path, default=DEFAULT_RUNS_DIR)
    p.add_argument("--out", type=Path, default=None, help="write JSON report here")
    p.add_argument("--markdown", action="store_true", help="print the markdown table")

    args = ap.parse_args()

    if args.cmd == "compile":
        harnesses = sorted(HARNESSES) if args.harness == "all" else [args.harness]
        check_spec_hash()
        for h in harnesses:
            if "compile_py" not in HARNESSES[h]:
                # the mock harness reads the canonical trace directly in-
                # container (no compiled-trace step; run.py compile is the
                # real-harness compile/diff-check only)
                print(f"{h}: no compiled trace (reads the canonical spec "
                      f"directly)")
                continue
            compiled = compile_harness(h)
            print(f"{h}: compiled + diff-clean -> {compiled}")
        return 0

    if args.cmd == "run":
        summary = run_one(args.harness, args.run_id, args.runs_dir, args.timeout,
                          args.design, sensor=not args.no_sensor)
        print(json.dumps(summary, indent=1))
        cov_ok = summary["coverage"] == "pass"
        return 0 if summary["status"] == "pass" and cov_ok else 1

    if args.cmd == "rerun":
        verdict = run_rerun(args.harness, args.label, args.runs, args.runs_dir,
                            args.timeout, args.design)
        return 0 if verdict["status"] == "pass" else 1

    if args.cmd == "reconcile":
        d = args.run_dir
        profile = rec_mod.load_profile(HERE / "runner" / "profiles" / f"{args.harness}.yaml")
        versions = rr_mod.load_versions(VERSIONS)
        run_id = d.name
        gw_dir = d / "gateway"
        gateway_log = gw_dir / "decisions.jsonl" if gw_dir.is_dir() else None
        gateway_policy = gw_dir / "policy.yaml" if gw_dir.is_dir() else None
        # kernel-record scoping needs the harness container id from the live
        # run; re-reconcile reads it from the retained run record (None only
        # for records that predate its capture).
        prev_record = (json.loads((d / "run-record.json").read_text())
                       if (d / "run-record.json").is_file() else {})
        cid = prev_record.get("container_id")
        run_record, manifest, report = rr_mod.assemble(
            BASELINE, profile, rec_mod.load_replay(d / "replay-result.json"),
            rec_mod.load_mapped(d / "mapped-actions.jsonl"),
            rec_mod.load_target_logs([str(d / "target-logs")]),
            cid, versions, args.harness, run_id, design=args.design,
            gateway_log=gateway_log, gateway_policy=gateway_policy,
            window_tolerance_ns=int(profile.get("window_tolerance_ns", 1_000_000_000)))
        artifacts = {
            "tracee-events": d / "tracee-events.json",
            "mapped-actions": d / "mapped-actions.jsonl",
            "replay-result": d / "replay-result.json",
            "replay-log": d / "replay-log.jsonl",
        }
        artifacts.update(enforcement_artifacts(
            args.design, gw_dir if gateway_log is not None else None, d))
        rr_mod.add_artifact_hashes(manifest, artifacts)
        (d / "run-record.json").write_text(
            json.dumps(run_record, indent=1, sort_keys=True) + "\n")
        (d / "manifest.json").write_text(
            json.dumps(manifest, indent=1, sort_keys=True) + "\n")
        (d / "reconciliation.json").write_text(
            json.dumps(report, indent=1, sort_keys=True) + "\n")
        print(json.dumps({"run_id": run_id, "status": report["status"],
                          "effective_counts": report["effective_counts"]}, indent=1))
        return 0 if report["status"] == "pass" else 1

    if args.cmd == "report":
        report = build_report(args.runs_dir, args.design)
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
        if args.markdown:
            print(render_markdown(report))
        else:
            print(json.dumps(report, indent=1))
        return 0

    return 2


if __name__ == "__main__":
    sys.exit(main())
