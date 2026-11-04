"""The experiments workdir: the one writable root for run artifacts.

The repository tree is pure source (compose files, profiles, pinned
manifests, the canonical spec — read from the repo, never written). Every
writable artifact a run produces is written under ONE writable root, the
workdir:

  <workdir>/runs/            replay staging (per-harness subdirs, mounted
                             into the topology by compose at
                             /workspace/replay) AND run output dirs
                             (<workdir>/runs/<run-id>/; docs/DESIGN.md 9)
  <workdir>/cache/compile/  compiled-trace outputs (the compile entry
                             points stay; their outputs move here)

Resolution order for the workdir: the CLI --workdir flag, then the
GUARDSCOPE_WORKDIR env, then the process cwd. With no flag and no env,
running from the repo root behaves exactly as before (the repo root
becomes the workdir, so runs/ and the compile cache are written where they
always did — under the repo root).

Replay staging has one operator override: GUARDSCOPE_STAGING_DIR. The
compose files mount ${GUARDSCOPE_STAGING_DIR:-../runs}/<harness> at
/workspace/replay, so an operator who brought the topology up with a
custom staging dir must have the runner stage into the SAME dir; the env
therefore wins over the workdir-derived staging root. Export an absolute
path (a relative value is resolved against the process cwd here, but
compose resolves it against the compose file's directory — the two only
agree when the value is absolute).

No global mutable state lives here: every function takes the caller's
explicit resolution (flag or resolved workdir) as a parameter.
"""

import os
from pathlib import Path

WORKDIR_ENV = "GUARDSCOPE_WORKDIR"
STAGING_ENV = "GUARDSCOPE_STAGING_DIR"


def resolve_workdir(explicit=None) -> Path:
    """The writable root for run artifacts, resolved absolute: the
    explicit value (the CLI --workdir flag), then the GUARDSCOPE_WORKDIR
    env, then the process cwd. An explicit flag ignores the env (flag >
    env > cwd)."""
    raw = None
    if explicit is not None:
        raw = explicit
    else:
        env = os.environ.get(WORKDIR_ENV)
        if env:
            raw = env
    if raw is None:
        return Path.cwd().resolve()
    return Path(str(raw)).expanduser().resolve()


def runs_root(workdir=None) -> Path:
    """<workdir>/runs: the run-output root (and the default replay
    staging root). workdir=None resolves the workdir itself (env > cwd;
    resolve_workdir)."""
    return resolve_workdir(workdir) / "runs"


def staging_dir(workdir=None) -> Path:
    """The replay staging root: GUARDSCOPE_STAGING_DIR wins over the
    workdir-derived <workdir>/runs (compose already mounted the env value
    into the topology; the runner must stage into the same dir)."""
    env = os.environ.get(STAGING_ENV)
    if env and env.strip():
        return Path(env).expanduser().resolve()
    return runs_root(workdir)


def compile_cache(workdir=None) -> Path:
    """<workdir>/cache/compile: compiled-trace outputs (the compile entry
    points stay in trace/compile/<harness>/; their outputs live here).
    workdir=None resolves the workdir itself (env > cwd)."""
    return resolve_workdir(workdir) / "cache" / "compile"
