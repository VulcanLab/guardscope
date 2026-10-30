# guardscope

guardscope is a measurement framework for runtime controls in LLM-agent
systems: it measures how much of an agent's action surface an inspection
layer (gateway, policy engine, sandbox) actually sees and decides on, and
at what latency and fidelity cost. The design is in `docs/DESIGN.md`.

## Install

You need the repo checkout plus a Python 3.12+ environment with Docker
and the compose plugin (runs execute on a Linux Docker host; the kernel
sensor additionally needs a supported kernel family, see `docs/DESIGN.md`
privilege tiers).

```sh
git clone <repo-url> && cd guardscope
pip install -e .
```

`pip install -e .` (editable, from the checkout) installs the
`guardscope` command and the `framework` package. v1 is an
editable-install-from-checkout model: the framework resolves the fixtures
repository (compose files, runner profiles, the canonical trace, plugin
manifests, the registry, the mock harness) as the directory next to the
installed package, i.e. the checkout. A plain `pip install .` does not
bundle those fixtures and cannot run experiments; a distribution-quality
package is later work. Use `pip install -e .` from the checkout.

## Quickstart

All writable artifacts land under one writable root, the experiments
workdir, resolved as: the `--workdir` flag, then the `GUARDSCOPE_WORKDIR`
env, then the process cwd. Keep the repo tree clean by working from a
separate experiments directory:

```sh
# CHECKOUT = where you cloned guardscope (adjust to your path)
CHECKOUT=~/guardscope

mkdir -p ~/experiments/guardscope && cd ~/experiments/guardscope
export GUARDSCOPE_WORKDIR="$PWD"
# the topology must mount the same staging dir the runner stages into
# (absolute path, so compose and the runner resolve it identically):
export GUARDSCOPE_STAGING_DIR="$PWD/runs"

# bring the topology up WITH the sensor (a Linux host with kernel
# privileges; the tracee container is the kernel-level ground truth):
docker compose -f $CHECKOUT/compose/t0.yaml up -d
docker compose -f $CHECKOUT/compose/t0.yaml --profile sensor up -d tracee

# validate, plan, run — the guardscope command works from any cwd:
guardscope validate $CHECKOUT/examples/t0-pi.yaml
guardscope plan $CHECKOUT/examples/t0-pi.yaml
guardscope run $CHECKOUT/examples/t0-pi.yaml
```

Without kernel privileges (or without bringing the sensor up), add
`--no-sensor` to the run: it completes in the degraded mode and every
output is labeled `self-reported` (`verified: false`).

Outputs land in the workdir: `runs/<run-id>/` (run outputs, plus the
execution manifest `runs/<experiment-id>/execution.json`) and
`cache/compile/` (compiled traces). The first run also pays one-time
warmup costs: the compose images build on first `up`, and the first run
per harness compiles the canonical trace into `cache/compile/` (reused
afterwards). The repo stays read-only source.

Add `--no-sensor` to `run` when the topology came up without the sensor
profile; the run is then labeled self-reported throughout.

## The three user types

- **Control author** (you wrote a gateway/policy/sandbox plugin): ship a
  thin shim that emits decision records per the contract
  (`framework/schemas/decision-record`), declare capabilities in a
  manifest (`plugins/<id>/manifest.json`), and run the conformance kit
  (`framework/conformance.py`) to get a registry verdict.
- **Platform team** (you run agent infrastructure): write an experiment
  file (one control, one or more designs; `examples/`), run
  `guardscope run` per control, and merge the single-control execution
  manifests with `guardscope report` into comparability-keyed grids.
- **Researcher** (you want a number you can trust): re-run a published,
  dated, hash-pinned reference snapshot and compare run manifests; the
  reference badge (M3, `docs/DESIGN.md` 12) is earned by reproducing it.

## Design

The design document `docs/DESIGN.md` is the specification: the contracts,
the C1-C6 checks, the evidence classes, the registry tiers, and the
milestone roadmap (M1-M4+).

## Repository layout

The repo is source-shaped and stays that way in v1. Read-only source:
`framework/` (the measurement core + schemas), `compose/` (fixture
topologies), `gateway/`, `harnesses/`, `mock_harness/`, `runner/`,
`sensor/`, `targets/`, `trace/`, `plugins/`, `registry/`, `examples/`,
`env/`. Writable artifacts never land in the repo; they go to the
experiments workdir (`GUARDSCOPE_WORKDIR`), described above.
