---
name: guardscope-path-check
description: Onboard a runtime control (gateway, policy engine, monitor, sandbox) into guardscope. Statically analyze the control's source against the 15 action paths to predict which paths it can check, then generate the configuration set (plugin manifest, compose overlays, experiment files) for empirical measurement. Use when given a control project to measure with guardscope, or when asked which of the 15 action paths a control inspects.
---

# guardscope control intake

You are given a runtime control project (a gateway, policy engine, monitor, or
sandbox). Do two things, in this order:

1. Statically analyze its code against guardscope's 15 action paths and
   produce a per-path prediction: can this control check this path?
2. Generate the configuration set that lets guardscope measure the control
   empirically, and validate it.

The static analysis produces predictions, never claims. The measured
coverage column (mock harness first, then a real harness) is the only thing
that counts as a result. Keep this distinction in everything you write.

## Inputs

- `<control-project>`: path to the control's source checkout. Required. If
  not given, stop and ask.
- Guardscope checkout: the repository this skill lives in (the directory
  containing `compose/`, `plugins/`, `framework/`). If the working directory
  is not that repo, ask for the checkout path before doing anything else.

## Step 0 — read the fixed references

From the guardscope checkout, read before writing any verdict:

- `README.md` — the 15 action paths (P1-P15) and the measurement model
  (checked / bypassed / prevented).
- `docs/measure-your-control.md` — the onboarding procedure this skill
  automates; it is authoritative when this file and it disagree.
- `mock_harness/manifest.yaml` — per-design expected dispositions (which
  design checks, bypasses, or prevents each action class). Use it to sanity
  check your predictions: a prediction that contradicts the manifest for the
  reference designs must name why this control differs from the reference
  placement.
- `references/path-analysis.md` (in this skill) — the per-path checklist.
  Read it in full before Step 2.

## Step 1 — classify the control (five facts)

Read the control project's code (entrypoints, docs, deployment files, log
emission) and decide:

1. **Deployment form** → `slot_kinds`: `container` (sidecar/proxy container),
   `attached_process` (injected into or wrapped around the harness process),
   `log_ingest` (reads the control's logs after the fact),
   `embedded` (library/policy engine inside the harness process),
   `kernel` (eBPF / kernel module; requires a `kernel_interference`
   declaration in the manifest).
2. **Enforcement** → `can_enforce`: `enforce` (it can deny/abort an action)
   or `observe` (it only watches and logs; it can never produce a
   `checked-denied` cell, so do not let the manifest claim more).
3. **Record emission** → `record_source`: `native` (the control can emit
   `decision-record/1` itself) or `ingested` (a shim must translate its log;
   the control then needs a shim sketch, `docs/shim-guide.md`).
4. **Observable action classes** → which of the six classes the control can
   actually evaluate: `stdio_tool_call`, `http_tool_call`, `direct_network`,
   `process_spawn`, `file_write`, `credential_access`. Claim only classes it
   parses or hooks, not classes it "could support".
5. **Positions and designs** → which of `t0`-`t7` it can occupy. Base this
   on the deployment form: a network container fits the gateway slots of
   `t1`/`t2`/`t3`/`t5` (slot sidecars in `compose/slots/`); an embedded
   engine is a `t4`/`t6`-style concern, but note those designs have no
   control slot: they measure the harness's own chain with `control: null`
   (see `examples/t4-pi.yaml`), so an embedded control is measured through
   a harness adapter, not a plugin overlay; a kernel control fits `t7`
   (`compose/slots/t7.yaml` declares the kernel slot; `t7` has no validated
   fixture yet — say so).

Record each fact with a one-line code citation (file and symbol) so a reader
can verify it.

## Step 2 — the 15-path analysis

Work through `references/path-analysis.md` path by path (P1 to P15). For
every path, produce one row:

| Path | Action class | Verdict | Evidence (file:line or symbol) | Confirmed by design(s) |

- **Verdicts**: `checkable`, `not-checkable`, `conditional` (name the
  condition), or `uncertain` (needs the empirical run; say what the run will
  show).
- Evidence must come from the control's code, not from its README or
  marketing text. Vendor claims are never evidence.
- A `checkable` verdict additionally names the design(s) under which the
  control is placed in the path (e.g. "t3 routes stdio through the gateway"),
  consistent with `mock_harness/manifest.yaml` expectations.
- A path with no external kernel-visible effect (P1 as defined) cannot be
  kernel-verified as an effect; a control can still see its dispatch. Record
  that limitation instead of claiming coverage the kernel sensor cannot
  confirm.
- Paths the control cannot check are findings, not losses: report them
  plainly, because `bypassed` cells are the informative output.

Deliver the table to the user, and save it as
`plugins/<id>/analysis.md` in the guardscope checkout when configs are
generated in Step 3.

## Step 3 — generate the configuration set

Generate, in the guardscope checkout, under `plugins/<control-id>/`
(id: lowercase, hyphens, from the manifest schema pattern):

1. **`manifest.json`** — from `assets/manifest.template.json`. Fill it from
   the Step 1 facts. Set `correlation.echoes_meta` and
   `correlation.echoes_header` to `false` (claims are never trusted; a live
   fidelity check upgrades them, not the author). Validate against
   `framework/schemas/capabilities-manifest/1.schema.json`.
2. **`overlay/<design>.yaml`** and **`overlay/<design>-mock.yaml`** for every
   slot design in `supported_designs` — from `assets/overlay.template.yaml`.
   A supported slot design without an overlay is a load-time hard error, so
   every listed slot design needs both files. Only designs with a slot
   sidecar get overlays: today `compose/slots/` carries `t1`, `t2`, `t3`,
   `t5`, and `t7`; `t4`/`t6` carry no slot, so never generate overlays for
   them. For each design, read
   `compose/slots/<design>.yaml` first: it names the exact compose service you
   must define, the slot network, the decision-log volume, and the policy
   artifact. Obey the overlay rules printed in the template (define exactly
   the slot service; auxiliary services only named `control-*` and only on
   the slot network or its netns; never touch base services or other
   top-level structure). The merged bring-up is base file FIRST, so keep the
   base's build-context convention (see `plugins/agt-gateway/overlay/` for
   reference bindings).
3. **Experiment files** — from `assets/experiment.template.yaml`, written
   next to the other experiment YAMLs (e.g. `examples/` or the workdir, user's
   choice): one mock-harness experiment per supported design first, then real
   harness (`harness: pi` or `harness: openclaw`) variants for the designs
   that apply.
4. **If `record_source` is `ingested`**: sketch the shim (vendor log line →
   `decision-record/1` field mapping) per `docs/shim-guide.md`, but do not
   invent log fields; mark unmapped ones `"unmapped"` as the guide requires.
   If the control's log format is unclear, record this as a blocker for the
   user instead of guessing.

## Step 4 — validate

Run, from the guardscope checkout:

```sh
guardscope validate <each experiment file>
```

Fix every hard error (schema, manifest-vs-design pairing, missing overlays).
`overlay_problems` with `off_matrix: true` are warnings: the run proceeds as
a custom fixture; prefer fixing them, but do not hide them.

If `record_source` is `ingested`, the record conformance check (`docs/
shim-guide.md` section 5) is a separate later step over real recorded logs;
`guardscope validate` checks wiring, not records.

## Step 5 — report and hand off

Report to the user:

- The 15-path table from Step 2 (prediction, clearly labeled as prediction).
- The generated file list with paths.
- The exact commands to measure, mock first (substitute the design and
  control id):

```sh
docker compose -f compose/t1-mock.yaml -f plugins/<id>/overlay/t1-mock.yaml up -d
docker compose -f compose/t1-mock.yaml -f plugins/<id>/overlay/t1-mock.yaml --profile sensor up -d tracee
guardscope run <t1-mock experiment file>
```

- The reminder that the measured column is the result, that mock-run cells
  are evidence-class `mock-run`, and that no-sensor runs are self-reported.

## Honesty rules

- Never let the manifest claim more than the code shows: `observe` stays
  `observe`, correlation stays `false`, unimplemented designs stay out of
  `supported_designs`.
- Static analysis is a hypothesis about coverage; only the run decides. Do
  not report predicted `checked` paths as facts.
- `t7` has no validated fixture yet; `--no-sensor` runs are degraded and
  self-reported; do not mix them into a sensor grid.

## Installing into a harness

This skill lives inside the guardscope repo at
`skills/guardscope-path-check/`, which no harness auto-discovers. To
use it, copy or symlink the directory into the harness's skill location:

- Any harness implementing the Agent Skills standard (Codex, Gemini CLI,
  GitHub Copilot, Pi, Claude Code with spec support):
  `<guardscope-checkout>/.agents/skills/` (project) or `~/.agents/skills/`
  (user level)
- Claude Code: `<guardscope-checkout>/.claude/skills/` (project) or
  `~/.claude/skills/` (user level)
