"""The experiments workdir (framework/workdir.py): the one writable root
for run artifacts — replay staging, run outputs, the compiled-trace cache.

The repository tree is pure source; every writable artifact a run produces
must be written under the workdir, resolved as --workdir > GUARDSCOPE_WORKDIR >
cwd (so running from the repo root keeps today's layout). The compose
files mount the staging dir env-driven (${GUARDSCOPE_STAGING_DIR:-../runs})
and the runner honors the same env when it stages.

Run from the repo root:  python3 -m pytest tests/test_workdir.py -v
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "runner"))

from framework import execute as execute_mod  # noqa: E402
from framework.cli import main as cli_main  # noqa: E402
from framework.execute import execute_experiment  # noqa: E402
from framework.workdir import (  # noqa: E402
    STAGING_ENV, WORKDIR_ENV, compile_cache, resolve_workdir, runs_root,
    staging_dir,
)
import run as run_mod  # noqa: E402


@pytest.fixture(autouse=True)
def _no_workdir_env(monkeypatch):
    """Isolate every test from an operator-exported GUARDSCOPE_* env."""
    monkeypatch.delenv(WORKDIR_ENV, raising=False)
    monkeypatch.delenv(STAGING_ENV, raising=False)


# --- resolution order: flag > env > cwd -------------------------------------------


def test_resolve_workdir_defaults_to_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert resolve_workdir() == tmp_path.resolve()
    assert resolve_workdir(None) == tmp_path.resolve()


def test_resolve_workdir_env_beats_cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(WORKDIR_ENV, str(tmp_path / "wd"))
    assert resolve_workdir() == (tmp_path / "wd").resolve()


def test_resolve_workdir_flag_beats_env(tmp_path, monkeypatch):
    monkeypatch.setenv(WORKDIR_ENV, str(tmp_path / "env-wd"))
    assert resolve_workdir(tmp_path / "flag-wd") == \
        (tmp_path / "flag-wd").resolve()


def test_resolve_workdir_is_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert resolve_workdir("rel-wd").is_absolute()
    assert resolve_workdir("rel-wd") == (tmp_path / "rel-wd").resolve()


def test_derived_roots_under_workdir(tmp_path):
    wd = tmp_path / "wd"
    assert runs_root(wd) == wd / "runs"
    assert staging_dir(wd) == wd / "runs"
    assert compile_cache(wd) == wd / "cache" / "compile"


def test_runs_root_and_cache_resolve_the_workdir_themselves(tmp_path,
                                                             monkeypatch):
    monkeypatch.setenv(WORKDIR_ENV, str(tmp_path / "wd"))
    assert runs_root() == (tmp_path / "wd" / "runs").resolve()
    assert compile_cache() == (tmp_path / "wd" / "cache" / "compile").resolve()


# --- staging: GUARDSCOPE_STAGING_DIR overrides the workdir-derived root ----------


def test_staging_env_beats_workdir(tmp_path, monkeypatch):
    # compose already mounted the env value into the topology; the runner
    # must stage into the same dir, so the env wins over the workdir-derived
    # root even when the workdir was given explicitly
    monkeypatch.setenv(STAGING_ENV, str(tmp_path / "custom-staging"))
    assert staging_dir(tmp_path / "wd") == (tmp_path / "custom-staging").resolve()


def test_staging_env_relative_value_resolves_absolute(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv(STAGING_ENV, "rel-staging")
    assert staging_dir() == (tmp_path / "rel-staging").resolve()


# --- the runner derives staging + compile cache from the workdir ------------------


def test_harness_cfg_staging_from_workdir(tmp_path):
    wd = tmp_path / "wd"
    for harness, sub in (("pi", "pi"), ("openclaw", "openclaw"),
                         ("mock-harness", "mock")):
        cfg = run_mod.harness_cfg(harness, "t0", workdir=wd)
        assert cfg["replay_dir"] == wd / "runs" / sub


def test_harness_cfg_staging_env_override(tmp_path, monkeypatch):
    monkeypatch.setenv(STAGING_ENV, str(tmp_path / "brought-up-here"))
    cfg = run_mod.harness_cfg("pi", "t0", workdir=tmp_path / "wd")
    assert cfg["replay_dir"] == tmp_path / "brought-up-here" / "pi"


def test_harness_cfg_workdir_env(tmp_path, monkeypatch):
    monkeypatch.setenv(WORKDIR_ENV, str(tmp_path / "wd"))
    cfg = run_mod.harness_cfg("pi", "t0")
    assert cfg["replay_dir"] == (tmp_path / "wd" / "runs" / "pi").resolve()


def test_harness_cfg_compiled_trace_under_the_cache(tmp_path):
    wd = tmp_path / "wd"
    cfg = run_mod.harness_cfg("pi", "t0", workdir=wd)
    assert cfg["compiled"] == wd / "cache" / "compile" / "pi" / \
        "baseline.compiled.json"
    # the mock harness has no compiled-trace step (reads the spec in-
    # container); no cache path is derived for it
    assert "compiled" not in run_mod.harness_cfg("mock-harness", "t0",
                                                 workdir=wd)


def test_compile_harness_writes_under_the_cache(tmp_path):
    """The compile entry point stays (trace/compile/<harness>/compile.py);
    its output is written under <workdir>/cache/compile/<harness>/ — nothing is
    written into the source tree (trace/compile/<h>/out/ is history)."""
    wd = tmp_path / "wd"
    compiled = run_mod.compile_harness("pi", workdir=wd)
    assert compiled == wd / "cache" / "compile" / "pi" / \
        "baseline.compiled.json"
    assert compiled.is_file()
    assert not (ROOT / "trace" / "compile" / "pi" / "out").exists()


def test_pull_harness_log_reads_the_workdir_staging(tmp_path):
    """T4+: the adapter's decisions.jsonl is read from the staging dir the
    run mounted (cfg["replay_dir"], derived from the workdir), not from a
    repo-relative runs/ path."""
    wd = tmp_path / "wd"
    replay_dir = wd / "runs" / "pi"
    replay_dir.mkdir(parents=True)
    (replay_dir / "decisions.jsonl").write_text('{"tool_name": "x"}\n')
    out_dir = tmp_path / "run"
    d = run_mod.pull_harness_log(out_dir, "pi", replay_dir=replay_dir)
    assert (d / "decisions.jsonl").read_text() == '{"tool_name": "x"}\n'


# --- execute_experiment: out_root defaults to <workdir>/runs ---------------------


class MinimalFakeExecutor:
    """The (descriptor, run_id, out_root) contract; records the out_root it
    was handed (the thing the workdir must drive)."""

    def __init__(self):
        self.out_roots = []

    def __call__(self, descriptor, run_id, out_root) -> dict:
        self.out_roots.append(Path(out_root))
        out_dir = Path(out_root) / run_id
        out_dir.mkdir(parents=True, exist_ok=True)
        (out_dir / "run-record.json").write_text("{}")
        return {"run_id": run_id, "harness": descriptor.harness,
                "design": descriptor.design, "out_dir": str(out_dir),
                "run_record": str(out_dir / "run-record.json"),
                "status": "pass", "coverage": None, "window_epoch_ns": None,
                "decision_log": None, "decision_stream": {},
                "sensor_present": False, "effective_counts": {},
                "ground_truth_counts": {}, "spec_sha256": "f" * 64}


def _experiment_file(tmp_path: Path, name: str = "e.yaml") -> Path:
    p = tmp_path / name
    p.write_text(yaml.safe_dump({"schema": 1, "control": None,
                                 "designs": ["t0"]}))
    return p


def test_execute_out_root_defaults_to_workdir_runs(tmp_path, monkeypatch):
    monkeypatch.setenv(WORKDIR_ENV, str(tmp_path / "wd"))
    fake = MinimalFakeExecutor()
    result = execute_experiment(_experiment_file(tmp_path),
                                run_executor=fake)
    assert fake.out_roots == [tmp_path / "wd" / "runs"]
    assert result.manifest_path == tmp_path / "wd" / "runs" / "e" / \
        "execution.json"


def test_execute_explicit_out_root_wins(tmp_path, monkeypatch):
    monkeypatch.setenv(WORKDIR_ENV, str(tmp_path / "wd"))
    fake = MinimalFakeExecutor()
    execute_experiment(_experiment_file(tmp_path), run_executor=fake,
                       out_root=tmp_path / "elsewhere")
    assert fake.out_roots == [tmp_path / "elsewhere"]


def test_execute_out_root_defaults_to_cwd_runs(tmp_path, monkeypatch):
    # no flag, no env: the cwd is the workdir (running from the repo root
    # keeps today's ./runs behavior)
    monkeypatch.chdir(tmp_path)
    fake = MinimalFakeExecutor()
    execute_experiment(_experiment_file(tmp_path), run_executor=fake)
    assert fake.out_roots == [tmp_path / "runs"]


def test_execute_threads_workdir_into_the_default_executor(tmp_path,
                                                            monkeypatch):
    """The default executor (the runner machinery) receives the resolved
    workdir so replay staging + the compile cache are written there too."""
    seen = {}

    def fake_default(descriptor, run_id, out_root, sensor=True,
                     workdir=None):
        seen["workdir"] = workdir
        return MinimalFakeExecutor()(descriptor, run_id, out_root)

    monkeypatch.setattr(execute_mod, "default_run_executor", fake_default)
    execute_experiment(_experiment_file(tmp_path), sensor=False,
                       workdir=tmp_path / "wd")
    assert seen["workdir"] == (tmp_path / "wd").resolve()


# --- the CLI: --workdir flag and plan's resolved paths ----------------------------


def test_cli_run_workdir_flag_reaches_execute_experiment(tmp_path, capsys,
                                                         monkeypatch):
    seen = {}

    def fake_execute(experiment_path, *, out_root=None, sensor=True,
                     workdir=None):
        seen["out_root"] = out_root
        seen["workdir"] = workdir
        from framework.experiment import load_experiment, resolve
        plan = resolve(load_experiment(experiment_path))
        return execute_mod.ExecutionResult(
            experiment=plan.experiment, runs=[], manifest_path=tmp_path,
            manifest={})

    monkeypatch.setattr(execute_mod, "execute_experiment", fake_execute)
    p = _experiment_file(tmp_path)
    assert cli_main(["run", str(p), "--workdir", str(tmp_path / "wd")]) == 0
    assert seen["workdir"] == str(tmp_path / "wd")
    # out_root not given: execute_experiment derives <workdir>/runs itself
    assert seen["out_root"] is None
    assert cli_main(["run", str(p), "--out-root", str(tmp_path / "o"),
                     "--workdir", str(tmp_path / "wd")]) == 0
    assert seen["out_root"] == str(tmp_path / "o")


def test_cli_run_without_workdir_keeps_the_old_call(tmp_path, capsys,
                                                     monkeypatch):
    seen = {}

    def fake_execute(experiment_path, *, out_root=None, sensor=True,
                     workdir=None):
        seen["out_root"] = out_root
        seen["workdir"] = workdir
        from framework.experiment import load_experiment, resolve
        plan = resolve(load_experiment(experiment_path))
        return execute_mod.ExecutionResult(
            experiment=plan.experiment, runs=[], manifest_path=tmp_path,
            manifest={})

    monkeypatch.setattr(execute_mod, "execute_experiment", fake_execute)
    p = _experiment_file(tmp_path)
    assert cli_main(["run", str(p)]) == 0
    assert seen["workdir"] is None
    assert seen["out_root"] is None


def test_cli_plan_prints_resolved_paths_to_stderr(tmp_path, capsys):
    p = _experiment_file(tmp_path)
    assert cli_main(["plan", str(p), "--workdir", str(tmp_path / "wd")]) == 0
    captured = capsys.readouterr()
    runs = json.loads(captured.out)
    assert [r["design"] for r in runs] == ["t0"]
    assert f"workdir: {tmp_path / 'wd'}" in captured.err
    assert f"out root: {tmp_path / 'wd' / 'runs'}" in captured.err
    assert f"replay staging: {tmp_path / 'wd' / 'runs'}" in captured.err


def test_cli_plan_staging_line_honors_staging_env(tmp_path, capsys,
                                                   monkeypatch):
    monkeypatch.setenv(STAGING_ENV, str(tmp_path / "custom-staging"))
    p = _experiment_file(tmp_path)
    assert cli_main(["plan", str(p)]) == 0
    captured = capsys.readouterr()
    assert f"replay staging: {tmp_path / 'custom-staging'}" in captured.err


# --- compose: the staging mount is env-driven everywhere ---------------------------


def test_compose_staging_mount_uses_the_env_everywhere():
    """Every /workspace/replay mount in every compose file stages through
    ${GUARDSCOPE_STAGING_DIR:-../runs}/<harness>: unset keeps the repo-
    relative default, an operator-exported absolute path moves staging into
    the experiments workdir."""
    compose_files = sorted((ROOT / "compose").glob("*.yaml"))
    assert len(compose_files) == 14
    for f in compose_files:
        doc = yaml.safe_load(f.read_text())
        mounts = []
        for svc in (doc.get("services") or {}).values():
            for v in svc.get("volumes") or []:
                if isinstance(v, str) and v.endswith(":/workspace/replay"):
                    mounts.append(v)
        # a stack that RUNS something (a base topology, or the executor
        # host's own stack) stages a replay volume; an overlay that adds
        # only environment (the origin-side remote-delegation overlay)
        # owns no mounts — its base does
        if f.name == "t0-remote.yaml":
            assert not mounts, f"{f.name}: an env-only overlay has no mounts"
            continue
        assert mounts, f"{f.name}: no replay staging mount found"
        for m in mounts:
            assert m.startswith("${GUARDSCOPE_STAGING_DIR:-../runs}/"), \
                f"{f.name}: staging mount not env-driven: {m}"


@pytest.mark.skipif(shutil.which("docker") is None,
                    reason="docker not available locally")
def test_compose_config_resolves_the_staging_env(tmp_path):
    """docker compose config: with GUARDSCOPE_STAGING_DIR set, the bind
    sources resolve to <staging>/<harness> (the experiments-workdir
    staging); unset they resolve against the compose file's directory
    (today's repo runs/)."""
    env = dict(os.environ)
    env[STAGING_ENV] = str(tmp_path / "staging")
    proc = subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "compose" / "t0.yaml"),
         "config"], capture_output=True, text=True, env=env, timeout=60)
    assert proc.returncode == 0, proc.stderr
    text = proc.stdout
    for sub in ("pi", "openclaw"):
        assert (f"source: {tmp_path / 'staging' / sub}\n"
                f"        target: /workspace/replay") in text
    # and without the env: the repo-relative default (resolved against the
    # compose file's directory, exactly today's behavior)
    env.pop(STAGING_ENV)
    proc = subprocess.run(
        ["docker", "compose", "-f", str(ROOT / "compose" / "t0.yaml"),
         "config"], capture_output=True, text=True, env=env, timeout=60)
    assert proc.returncode == 0, proc.stderr
    assert f"source: {ROOT / 'runs' / 'pi'}" in proc.stdout
