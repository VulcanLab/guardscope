# guardscope

<p align="center">
  <img src="assets/guardscope-horizontal.svg" alt="guardscope logo" width="438">
</p>

## What guardscope does

guardscope determines which of an LLM agent's action paths a runtime control (an agent gateway, a guardrail engine, an in-process policy engine, a kernel monitor) actually checks. A control can only evaluate the actions that cross the point where it is placed, and an agent can act through far more paths than the tool-call channel: subprocesses, direct network egress, local tool servers, sub-agents, scheduled tasks. guardscope addresses the question in two stages:

1. **Static analysis.** Analyze the given realtime control's source and predict, for each of the 15 action paths, whether its placement can check it. No deployment is required. Performed by the agent skill `skills/guardscope-path-check/`.
2. **Empirical measurement.** Run a fixed workload on a controlled deployment, record what the control claims to have seen, verify the claims against what the host kernel observed, and report which actions were checked, which were bypassed, and which were prevented. The output is a coverage grid you can re-run, compare, and cite, not a vendor claim.

The static analysis produces predictions, and the empirical measurement verifies the predictions.

### Who it is for

- **You develop a runtime control** (a gateway, a policy engine, a sandbox): predict which of the 15 paths your product can check by static analysis, then measure which it actually inspects. The result is a kernel-verified coverage column you can publish as a registry verdict instead of a self-attested claim.
- **You operate agent infrastructure** (platform, security, or compliance): compare candidate controls on the same fixed workload and fixtures and see, per topology design, which paths each placement checks and which it leaves uncovered, before committing to a deployment.
- **You build an agent harness**: the harness's own permission chain is a measured component; measure what it actually covers.

### The 15 action paths

Both stages are keyed to the 15 paths an agent harness can use to produce an external effect:

| Family | Path | Description |
|---|---|---|
| In-process | P1 In-process tool execution | The harness executes a function tool inside the harness process with a purely in-memory effect that never affects the external world (e.g., SDK `@function_tool` implementations). |
| | P2 Direct-origin operations | The harness's in-process tool issues direct OS operations, file or socket (e.g., Claude Code Read/Write/Edit). |
| Spawned processes | P3 Subprocess execution | The harness launches a subprocess (shell, interpreter, or executable). |
| | P12 Background processes | A dispatched process continues running or resumes after the invocation returns (`nohup`, `setsid`, shell background jobs), without a new dispatch-time check for its later operations. |
| Network egress | P4 Direct network egress | The harness or a subprocess opens a connection that is not a tool-server call (`curl`, cloud SDK, raw socket). |
| | P5 Local-intermediary routing | Agent code contacts a local intermediary (loopback HTTP helper, Unix-socket database) that acts locally or relays onward. |
| Remote tool-server call | P6 HTTP tool-server call | The harness sends a tool request over HTTP through a gateway (e.g., Streamable-HTTP MCP). |
| Local-transport tool-server call | P7 Stdio tool-server call | The harness talks the tool protocol to a child tool server over stdin/stdout pipes (e.g., stdio MCP servers). |
| | P8 Local-IPC tool-server call | The same invocation over another local transport (Unix-domain socket, named pipe). |
| Nested tool-server call | P9 Wrapped invocation | An in-process tool's implementation itself invokes a tool server over HTTP or a local transport. |
| Delegation | P10 Agent delegation | The harness delegates to a sub-agent that shares its dispatcher or uses an independent dispatch, either locally or remotely. |
| Deferred execution | P11 Daemon/scheduler submission | The harness submits a task to a daemon, scheduler, or container runtime (crontab, systemd unit, `docker.sock`). |
| Non-dispatch channels | P13 Dispatch-free output consumption | The harness consumes model output and produces file, process, or network effects without a corresponding tool-dispatch authorization for those effects (e.g., Aider's response parsing). |
| | P14 Non-tool protocol operation | A client-initiated protocol operation other than a tool call (e.g., MCP `resources/read`, `prompts/get`) crosses a transport also used for tool calls. |
| | P15 Reverse protocol interaction | A tool server initiates a request back into the harness (server-initiated sampling, elicitation). |

## Static analysis

The static analysis investigates which paths your realtime control could check. It only needs the control's source. The repo contains an agent skill that performs it, `skills/guardscope-path-check/`, usable with any coding agent that implements the Agent Skills format (Claude Code, Codex, Gemini CLI, and others). Given the control project, the skill:

1. Classifies the control: deployment form (container gateway, attached process, embedded policy engine, kernel control, log ingest), enforce vs observe-only, record emission, the action classes it parses or hooks, and the designs it can occupy.
2. Checks each of the 15 paths against a fixed checklist: what the control must intercept to check the path, which code evidence counts, and a verdict per path — `checkable`, `not-checkable`, `conditional`, or `uncertain`.
3. Produces a per-path table with file-level evidence, cross-checked against the expected per-design dispositions (`mock_harness/manifest.yaml`), and generates the configuration set for the empirical stage: the capability manifest (`plugins/<id>/manifest.json`), the binding overlays (`plugins/<id>/overlay/`), and the experiment files, validated with `guardscope validate`.

To use it, copy or symlink `skills/guardscope-path-check/` into your agent's skill directory (`.agents/skills/` or `.claude/skills/`, project or user level) and invoke it with the path to the control project.

## Empirical measurement

Every empirical run follows the same procedure:

1. A fixed reference workload drives a real agent harness by deterministic replay injection (no LLM in the loop), exercising all 15 action paths listed above.
2. The harness runs on an environment that realizes one topology design. The repo contains fixtures for the eight designs T0-T7, from a bare harness with no control (T0), through gateways in front of the harness (T1-T3, T5), harness-native permission chains (T4) and in-process policy engines (T6), to kernel-level enforcement (T7); see `docs/DESIGN.md` for the design set.
3. Each control in the topology records every decision it makes (an arriving tool call, an allow or deny), in a common record format the framework defines.
4. An eBPF kernel sensor (Tracee) observes what actually happened on the host, regardless of what any component reports. This kernel observation is the ground truth of every run.
5. The framework compares the controls' records against the kernel observation and classifies each action instance as `checked` (the action crossed the control and was evaluated there), `bypassed` (it took effect without ever crossing the control), or `prevented` (it was blocked by a mechanism outside the control, such as a network egress filter, so it never took effect).
6. The result is a table: one row per action path (the 15 above), one column per topology design, and each cell says `checked`, `bypassed`, or `prevented`.

## Requirements (for the empirical measurement)

- Python 3.12+ (a virtualenv or equivalent; see Install)
- Docker Engine 24+ with the compose plugin (every experiment runs on a Linux Docker host)
- Linux, kernel 5.8 or newer with BTF (`/sys/kernel/btf/vmlinux`), for the kernel sensor; the supported kernel families are listed in `docs/DESIGN.md` (privilege tiers). Without kernel privileges the framework still works in its degraded mode (`--no-sensor`): every output is labeled self-reported and unverified.
- Linux, arm64 (aarch64) or x86_64. Both families are validated (Graviton m7g and Intel m7i, Ubuntu 24.04, kernel 7.0.x-aws): every acceptance run passes on both, with identical outcome counts.
- About 50 GB of free disk: the fixture images and their build cache, plus the raw kernel-event captures that a sensor-backed run writes (a single capture can be several GB; the reconciled outputs are small).

Check a host quickly with the environment probe:

```sh
bash env/check-server.sh
```

It reports pass/warn/fail for kernel, BTF, Docker, compose, cgroup v2, privilege path, and disk headroom.

## Install

```sh
git clone <repo-url> && cd guardscope
pip install -e .
```

This installs the `guardscope` command. The checkout must stay on your machine: the framework reads the compose files, traces, and plugin data from it at run time. Do not delete or move the checkout after installing.

## Quickstart

All writable artifacts are written under one writable root, the experiments workdir, resolved as: the `--workdir` flag, then the `GUARDSCOPE_WORKDIR` env, then the process cwd. Keep the repo tree clean by working from a separate experiments directory:

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

Without kernel privileges (or without bringing the sensor up), add `--no-sensor` to the run: it completes in the degraded mode and every output is labeled `self-reported` (`verified: false`).

Outputs are written in the workdir: `runs/<run-id>/` (run outputs, plus the execution manifest `runs/<experiment-id>/execution.json`) and `cache/compile/` (compiled traces). The first run also pays one-time warmup costs: the compose images build on first `up`, and the first run per harness compiles the reference trace into `cache/compile/` (reused afterwards). The repo stays read-only source.

The first run of a design also incurs a warmup run: warmup run IDs (`warmup-` prefix) are pre-measurement first runs excluded from acceptance; the first live run of a design produces leftover bookkeeping records (harness startup writes) and fails the leftover check by design. Run once to warm up, then run again for the accepted measurement.

### Gateway designs: base + control overlay

Every fixture with a control slot is a placeholder **base** plus a **control-binding overlay** (`docs/DESIGN.md` 7). The base (`compose/t1.yaml`, ..., `t5.yaml`, and the `-mock` variants) carries the design structure with the slot declared but the control service absent; the bound control's service definition arrives as an overlay merged on top — the bundled AGT binding (`plugins/agt-gateway/overlay/`) is expressed exactly like a third party's. Bring-up merges the base FIRST (the overlay's relative build context resolves against the first compose file's directory), then the overlay:

```sh
# design T1 bound to the bundled gateway control:
docker compose -f $CHECKOUT/compose/t1.yaml -f $CHECKOUT/plugins/agt-gateway/overlay/t1.yaml up -d
docker compose -f $CHECKOUT/compose/t1.yaml -f $CHECKOUT/plugins/agt-gateway/overlay/t1.yaml --profile sensor up -d tracee
```

A base alone is not a validatable unit (`docker compose -f compose/t1.yaml config` fails loudly: the harness services depend on the slot service that only the overlay provides). t0/t4/t6 have no control slot and stay single-file fixtures; the slot declarations are framework-side sidecar data in `compose/slots/`, and the experiment runner validates the pairing (the control's manifest declares the designs it supports; a supported design without a binding overlay is a load-time error).

### Bring your own control (stub)

You may test your own control by following the full walk-through in `docs/measure-your-control.md` (this is the mechanics). The `guardscope-path-check` agent skill generates this configuration set from the control's source and validates it with `guardscope validate`:

1. Provide a capability manifest declaring your supported designs and slot kinds: `plugins/<your-control>/manifest.json`.
2. Provide one binding overlay per supported design (and its mock variant when the mock fixture is in scope): `plugins/<your-control>/overlay/t1.yaml` — the gateway slot's compose service definition (image/build, env, policy, log wiring), moved into your plugin directory. The service name must be the one declared in `compose/slots/<design>.yaml`.
3. The on-matrix rule: the overlay defines exactly the declared slot service, may add auxiliary services only named `control-*` attached to the slot's network, and must not touch any base service. Violations are not errors: the run is flagged off-matrix as a custom fixture (`docs/DESIGN.md` 7).

The fixture fingerprint records the base and overlay hashes separately, so your control's version changes move the fingerprint on their own.

## The three user types

- **Control author** (you wrote a gateway/policy/sandbox plugin): write a thin shim that emits decision records per the contract (`framework/schemas/decision-record`), declare capabilities in a manifest (`plugins/<id>/manifest.json`), and run the conformance kit (`framework/conformance.py`) to get a registry verdict.
- **Platform team** (you run agent infrastructure): write an experiment file (one control, one or more designs; `examples/`), run `guardscope run` per control, and merge the single-control execution manifests with `guardscope report` into comparability-keyed grids.
- **Researcher** (you want a number you can trust): re-run a published, dated, hash-pinned reference snapshot and compare run manifests; the reference badge (M3, `docs/DESIGN.md` 12) is earned by reproducing it.

## Docs

- `docs/DESIGN.md`: the specification: the contracts, the C1-C6 checks, the evidence classes, the registry tiers, and the milestone roadmap (M1-M4+).
- `docs/shim-guide.md`: translating a control's vendor log into `decision-record/1` records, and verifying the translation with the L1 conformance run.
- `docs/measure-your-control.md`: the onboarding walk-through for bringing a control to measurement: manifest, binding overlay, validation, measurement, and reading your coverage column honestly.

## Citation

If you use guardscope, please cite the accompanying paper, [guardscope: Measuring Which Actions Runtime Controls Check in LLM Agent Systems](https://arxiv.org/abs/2611.15223), for more details:

```bibtex
@misc{guardscope,
      title={guardscope: Measuring Which Actions Runtime Controls Check in LLM Agent Systems},
      author={Kentaroh Toyoda and Alex Leung and Bhuvaneswari U},
      year={2026},
      eprint={2611.15223},
      archivePrefix={arXiv},
      primaryClass={cs.AI},
      url={https://arxiv.org/abs/2611.15223},
}
```

## License

Apache-2.0 (see `LICENSE`).
