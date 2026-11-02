#!/usr/bin/env python3
"""Minimal replay driver for the Pi harness (M5 slice of C9; run.py CLI lands in M7).

Runs one pi RPC process per replay inside the t0-pi container:

    docker exec -i t0-pi pi --mode rpc --no-session -e /opt/inspection/adapter/replay.ts

and drives it over the documented RPC protocol (docs/rpc.md): an extension
command (/inspection-replay <path>) executes the compiled trace in-process with
no LLM — pi's analogue of OpenClaw's POST /tools/invoke. The adapter writes
replay-log.jsonl + replay-result.json into REPLAY_LOG_DIR (= runs/pi on the
host via bind mount); this driver reads the result file and prints it.

Usage:
  python3 runner/trigger_pi.py --compile [--container t0-pi] [--out runs/pi/replay-result.json]
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
COMPILE_PY = HERE / "trace" / "compile" / "pi" / "compile.py"
BASELINE = HERE / "trace" / "traces" / "baseline.yaml"
CONTAINER_REPLAY_DIR = "/workspace/replay"
EXTENSION_PATH = "/opt/inspection/adapter/replay.ts"


def _default_out_dir() -> Path:
    # workdir-relative staging (framework/workdir): the standalone entry
    # point writes the same places the runner does, never into the repo
    from framework.workdir import staging_dir, resolve_workdir
    return staging_dir(resolve_workdir()) / "pi"


def compile_trace() -> Path:
    from framework.workdir import compile_cache, resolve_workdir
    compiled = (compile_cache(resolve_workdir()) / "pi" /
                "baseline.compiled.json")
    compiled.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run([sys.executable, str(COMPILE_PY), str(BASELINE), "--out", str(compiled)],
                   check=True)
    return compiled


def run_replay(compiled_path: Path, replay_dir: Path, container: str, timeout_s: float,
               design: str = "t0", run_id: str | None = None) -> dict:
    """Stage the compiled trace into the container's replay dir (runs/pi on the
    host, /workspace/replay in the container), exec one pi RPC process, trigger
    the extension command, and read back the result JSON from the same dir.

    T4 (design=t4, harness-native enforcement): two prompts. The extension
    command does the MCP readiness wait + the process-level actions (the
    bypass); the second prompt starts the agent run — the adapter's scripted
    provider issues the tool-call actions through pi's tool pipeline, and the
    settled handler writes replay-result.json. The driver polls for the file.

    run_id (M2a): stamped into the pi process env as INSPECTION_RUN_ID so the
    adapter's dispatch records (dispatch-record/1) carry the run identity;
    None keeps the adapter's own fallback."""
    staged = replay_dir / "compiled.json"
    replay_dir.mkdir(parents=True, exist_ok=True)  # user-owned when driver pre-creates
    # Stale artifacts are root-owned (written by the root container); clean
    # them from inside the container instead of failing on host permissions.
    # dispatch-records.jsonl (M2a) joins the cleanup list so a run never
    # reconciles the previous run's dispatch stream; delegation-records.jsonl
    # (the F2 fixture's hand-off stream) joins for the same reason.
    subprocess.run(["docker", "exec", container, "sh", "-c",
                    f"rm -f {CONTAINER_REPLAY_DIR}/replay-result.json "
                    f"{CONTAINER_REPLAY_DIR}/replay-log.jsonl "
                    f"{CONTAINER_REPLAY_DIR}/compiled.json "
                    f"{CONTAINER_REPLAY_DIR}/decisions.jsonl "
                    f"{CONTAINER_REPLAY_DIR}/dispatch-records.jsonl "
                    f"{CONTAINER_REPLAY_DIR}/delegation-records.jsonl"], check=False)
    shutil.copyfile(compiled_path, staged)

    two_phase = design in ("t4", "t5", "t6")
    model_flags = (["--provider", "inspection-replay", "--model", "replay",
                    "--session-dir", f"{CONTAINER_REPLAY_DIR}/sessions"]
                   if two_phase else [])
    # T4/T5/T6 keep a real session (--no-session yields an empty session
    # projection, so providers would see no transcript and repeat tool calls).
    no_session_flags = ([] if two_phase else ["--no-session"])
    # M2a: the run identity reaches the adapter as an env stamp (the dispatch
    # records and C5 join on it); absent run_id keeps the adapter fallback.
    run_env = (["-e", f"INSPECTION_RUN_ID={run_id}"] if run_id else [])
    proc = subprocess.Popen(
        ["docker", "exec", "-i", *run_env, container,
         "pi", "--mode", "rpc", *model_flags, *no_session_flags, "-e", EXTENSION_PATH],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def send(cmd: dict) -> None:
        proc.stdin.write(json.dumps(cmd) + "\n")
        proc.stdin.flush()

    send({"type": "prompt", "id": "replay-1",
          "message": f"/inspection-replay {CONTAINER_REPLAY_DIR}/compiled.json"})

    # Drain pi's stdout continuously: the event stream (including the large
    # system-message events) fills the pipe buffer and pi blocks on stdout
    # backpressure if nobody reads — observed live: a T4 agent run stalled
    # forever with the driver polling the result file. The reader thread
    # collects lines; the main logic consumes them from the queue.
    import queue as _queue, threading as _threading
    lines: _queue.Queue = _queue.Queue()

    def _reader(proc, q):
        for line in proc.stdout:
            q.put(line)
        q.put(None)

    _threading.Thread(target=_reader, args=(proc, lines), daemon=True).start()

    def next_line(timeout_s: float):
        try:
            return lines.get(timeout=timeout_s)
        except _queue.Empty:
            return None

    response = None
    deadline = time.time() + timeout_s
    while response is None and time.time() < deadline:
        line = next_line(1.0)
        if line is None:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "response" and event.get("id") == "replay-1":
            response = event
        elif event.get("type") == "extension_error":
            print(f"extension_error: {event.get('error')}", file=sys.stderr)

    if response is None:
        proc.kill()
        raise SystemExit("pi RPC process did not return a response for the replay command")

    if design in ("t4", "t5", "t6"):
        # Phase 2: start the agent run (scripted provider -> tool calls cross
        # pi's pipeline); the settled handler writes the result file.
        send({"type": "prompt", "id": "replay-2",
              "message": "inspection replay: execute the tool calls"})

    result_path = replay_dir / "replay-result.json"
    while time.time() < deadline and not result_path.exists():
        line = next_line(0.5)
        if line is None:
            continue
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        if event.get("type") == "extension_error":
            print(f"extension_error: {event.get('error')}", file=sys.stderr)
    proc.stdin.close()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

    if not result_path.exists():
        raise SystemExit(f"no {result_path.name} after {timeout_s}s (handler failed?)")
    result = json.loads(result_path.read_text())
    # Hand the dir back to the host user (the root container wrote the artifacts).
    subprocess.run(["docker", "exec", container, "chown", "-R",
                    f"{os.getuid()}:{os.getgid()}", CONTAINER_REPLAY_DIR], check=False)
    return result


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--compile", action="store_true",
                    help="compile the canonical spec first (trace/compile/pi/compile.py)")
    ap.add_argument("--trace", type=Path,
                    default=HERE / "trace" / "compile" / "pi" / "out" / "baseline.compiled.json")
    ap.add_argument("--container", default="t0-pi")
    ap.add_argument("--timeout", type=float, default=120)
    ap.add_argument("--out", type=Path, default=None, help="result JSON path (default runs/pi/replay-result.json)")
    args = ap.parse_args()

    out_dir = args.out.parent if args.out else _default_out_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.compile:
        compiled = compile_trace()
    else:
        compiled = args.trace
        if not compiled.exists():
            raise SystemExit(f"compiled trace {compiled} missing (use --compile)")

    result = run_replay(compiled, out_dir, args.container, args.timeout)
    dest = args.out or (out_dir / "replay-result.json")
    if dest.resolve() != (out_dir / "replay-result.json").resolve():
        dest.write_text(json.dumps(result, indent=1) + "\n")
    print(json.dumps(result, indent=1))
    print(f"result: {dest}")
    if not result.get("ok"):
        sys.exit(1)


if __name__ == "__main__":
    main()