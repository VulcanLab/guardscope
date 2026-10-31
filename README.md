# guardscope

guardscope is a measurement framework for runtime controls in LLM-agent
systems: it measures how much of an agent's action surface an inspection
layer (gateway, policy engine, sandbox) actually sees and decides on, and
at what latency and fidelity cost.

## Requirements

- Python 3.12+ (a virtualenv or equivalent; see Install)
- Docker Engine 24+ with the compose plugin (every experiment runs on a
  Linux Docker host)
- Linux, kernel 5.8 or newer with BTF (`/sys/kernel/btf/vmlinux`), for the
  kernel sensor; the supported kernel families are listed in
  `docs/DESIGN.md` (privilege tiers). Without kernel privileges the
  framework still works in its degraded mode (`--no-sensor`): every
  output is labeled self-reported and unverified.
- Linux, arm64 (aarch64) or x86_64. Both families are validated
  (Graviton m7g and Intel m7i, Ubuntu 24.04, kernel 7.0.x-aws): every
  acceptance run passes on both, with identical outcome counts.
- About 50 GB of free disk: the fixture images and their build cache,
  plus the raw kernel-event captures that a sensor-backed run writes
  (a single capture can be several GB; the reconciled outputs are small).

Check a host quickly with the environment probe:

```sh
bash env/probe-server.sh
```

It reports pass/warn/fail for kernel, BTF, Docker, compose, cgroup v2,
privilege path, and disk headroom.

## Install

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

The first run of a design also pays a warmup run: warmup run IDs
(`warmup-` prefix) are pre-measurement first runs excluded from
acceptance; the first live run of a design produces leftover
bookkeeping records (harness startup writes) and fails the leftover
check by design. Run once to warm up, then run again for the accepted
measurement.

### Gateway designs: base + control overlay

Every fixture with a control slot is a placeholder **base** plus a
**control-binding overlay** (`docs/DESIGN.md` 7). The base
(`compose/t1.yaml`, ..., `t5.yaml`, and the `-mock` variants) carries the
design structure with the slot declared but the control service absent; the
bound control's service definition arrives as an overlay merged on top —
the shipped AGT binding (`plugins/agt-gateway/overlay/`) is expressed
exactly like a third party's. Bring-up merges the base FIRST (the overlay's
relative build context resolves against the first compose file's
directory), then the overlay:

```sh
# design T1 bound to the shipped gateway control:
docker compose -f $CHECKOUT/compose/t1.yaml -f $CHECKOUT/plugins/agt-gateway/overlay/t1.yaml up -d
docker compose -f $CHECKOUT/compose/t1.yaml -f $CHECKOUT/plugins/agt-gateway/overlay/t1.yaml --profile sensor up -d tracee
```

A base alone is not a validatable unit (`docker compose -f compose/t1.yaml
config` fails loudly: the harness services depend on the slot service that
only the overlay provides). t0/t4/t6 have no control slot and stay
single-file fixtures; the slot declarations are framework-side sidecar
data in `compose/slots/`, and the experiment runner validates the pairing
(the control's manifest declares the designs it supports; a supported
design without a binding overlay is a load-time error).

### Bring your own control (stub)

The overlay mechanism is the whole binding surface for a control; the
full walk-through is `docs/measure-your-control.md` (this is the
mechanics):

1. Ship a capability manifest declaring your supported designs and slot
   kinds: `plugins/<your-control>/manifest.json`.
2. Ship one binding overlay per supported design (and its mock variant
   when the mock fixture is in scope):
   `plugins/<your-control>/overlay/t1.yaml` — the gateway slot's compose
   service definition (image/build, env, policy, log wiring), moved into
   your plugin directory. The service name must be the one declared in
   `compose/slots/<design>.yaml`.
3. The on-matrix rule: the overlay defines exactly the declared slot
   service, may add auxiliary services only named `control-*` attached
   to the slot's network, and must not touch any base service. Violations
   are not errors: the run is flagged off-matrix as a custom fixture
   (`docs/DESIGN.md` 7).

The fixture fingerprint records the base and overlay hashes separately,
so your control's version changes move the fingerprint on their own.

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

## Docs

- `docs/DESIGN.md`: the specification: the contracts, the C1-C6 checks,
  the evidence classes, the registry tiers, and the milestone roadmap
  (M1-M4+).
- `docs/shim-guide.md`: translating a control's vendor log into
  `decision-record/1` records, and verifying the translation with the L1
  conformance run.
- `docs/measure-your-control.md`: the onboarding walk-through for
  bringing a control to measurement: manifest, binding overlay,
  validation, measurement, and reading your coverage column honestly.

## Repository layout

The repo is source-shaped and stays that way in v1. Read-only source:
`framework/` (the measurement core + schemas), `compose/` (fixture base
topologies + the `compose/slots/` sidecar slot declarations), `gateway/`,
`harnesses/`, `mock_harness/`, `runner/`, `sensor/`, `targets/`,
`trace/`, `plugins/` (manifests + the controls' binding overlay bundles),
`registry/`, `examples/`, `env/`. Writable artifacts never land in the
repo; they go to the experiments workdir (`GUARDSCOPE_WORKDIR`),
described above.

## License

Apache-2.0 (see `LICENSE`).
