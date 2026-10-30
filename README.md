# guardscope

guardscope is a measurement framework for runtime controls in LLM-agent
systems: it measures how much of an agent's action surface an inspection
layer (gateway, policy engine, sandbox) actually sees and decides on, and
at what latency and fidelity cost. The design is in `docs/DESIGN.md`.

The repository currently contains the core measurement components
(`compose/`, `env/`, `gateway/`, `harnesses/`, `mock_harness/`, `runner/`,
`sensor/`, `targets/`, `tests/`, `trace/`) in their current layout.

## Running from an experiments directory

The repository tree is pure source. Every writable artifact a run produces
(replay staging, run outputs, the compiled-trace cache) lands under one
writable root, the experiments workdir, resolved as: the `--workdir` flag,
then the `GUARDSCOPE_WORKDIR` env, then the process cwd. With no flag and no
env, running from the repo root behaves as before (compiled traces now land in the workdir cache, gitignored) (the repo root is
the workdir; `runs/` and `cache/` are gitignored).

To run experiments outside the repo:

```sh
mkdir -p ~/experiments/guardscope && cd ~/experiments/guardscope
export GUARDSCOPE_WORKDIR="$PWD"
# the topology must mount the same staging dir the runner stages into:
export GUARDSCOPE_STAGING_DIR="$PWD/runs"
docker compose -f <repo>/compose/t0.yaml --profile sensor up -d
PYTHONPATH=<repo> python3 -m framework.cli run <repo>/examples/t0-pi.yaml
# or: python3 <repo>/runner/run.py run --harness pi --run-id pi-1
```

Artifacts then land in the workdir — `runs/` (replay staging per harness
plus `runs/<run-id>/` outputs) and `cache/compile/` (compiled traces) — and
the repo tree stays clean. `GUARDSCOPE_STAGING_DIR` moves the replay staging
root (the compose files mount `${GUARDSCOPE_STAGING_DIR:-../runs}/<harness>`
at `/workspace/replay`; export an absolute path so compose and the runner
resolve it identically). The repo mounts (compose files, profiles, pinned
manifests, the canonical spec) stay read-only source in both cases.
