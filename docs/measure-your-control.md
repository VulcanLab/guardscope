# Measure your control: the onboarding walk-through

Status: onboarding doc for teams bringing a runtime monitoring or control
product to be measured by guardscope.

Audience: a team with a gateway, policy engine, or monitor that wants a
path x design coverage column for its product.

## 1. Install

```sh
git clone <repo-url> && cd guardscope
pip install -e .        # editable, from the checkout; installs the guardscope command
```

Writable artifacts are never written in the repo; they go to the experiments
workdir (`GUARDSCOPE_WORKDIR`, plus `GUARDSCOPE_STAGING_DIR` for the replay
staging mount). The README quickstart carries the full sequence (topology
bring-up included); runs execute on a Linux Docker host, and the kernel
sensor additionally needs a supported kernel family.

## 2. Register your control as a plugin

Provide a capability manifest at `plugins/<your-id>/manifest.json`, validated
against `framework/schemas/capabilities-manifest/1.schema.json`. Minimum for
`kind: "control"` (the loader, `framework/contracts.py`, enforces the
per-kind fields):

```json
{
  "schema": 1,
  "id": "my-gateway",
  "version": "0.1.0",
  "kind": "control",
  "slot_kinds": ["container"],
  "positions": [{"id": "gateway", "designs": ["t1"]}],
  "record_source": "ingested",
  "observable_action_classes": ["http_tool_call"],
  "can_enforce": "enforce",
  "emitted_schema_versions": ["decision-record/1"],
  "correlation": {"echoes_meta": false, "echoes_header": false},
  "supported_designs": ["t1"]
}
```

- `slot_kinds`: `container`, `attached_process`, `log_ingest` (the vendor-log
  case), or `embedded`.
- `record_source`: `native` (your product emits decision-record/1 itself) or
  `ingested` (a shim translates your log).
- `can_enforce`: `enforce` or `observe`. An observe-only control can never
  produce `prevented`; say so here rather than overclaiming.
- `supported_designs`: checked at experiment load time; requesting a design
  outside this list is a hard error naming the conflict. A position's
  designs must stay inside it.
- Claims are never trusted. `correlation` claims
  (`echoes_meta`/`echoes_header`) stay false until a live fidelity check
  verifies them and publishes measured flags to `plugins/<id>/fidelity.json`.
  The bundled reference (`plugins/agt-gateway/manifest.json`) follows the
  same rule.

## 3. Bind it into a design: the overlay

A fixture with a control slot is a placeholder base
(`compose/<design>.yaml`, or `compose/<design>-mock.yaml` on the mock
harness) plus your control-binding overlay:
`plugins/<your-id>/overlay/<design>.yaml` (the `-mock` variant for the mock
fixture). The slot's requirements live in the framework-side sidecar
`compose/slots/<design>.yaml`: the compose service name you must define,
the slot's network, the decision-log volume, the deployed policy artifact.
The bundled overlays under `plugins/agt-gateway/overlay/` are the reference
examples.

The on-matrix validator (`framework/overlay.py`, `validate_overlay`) checks
four rules:

1. The overlay defines exactly the declared slot service (it may set or
   override that service's fields, and the service must carry `image` or
   `build`).
2. Auxiliary services are allowed only under the name `control-*` and only
   attached to the slot's network or the slot service's netns
   (`network_mode: "service:<slot>"`).
3. No base service is removed or modified (compose merge cannot remove a
   service; redeclaring one is modification).
4. No other top-level structure (networks, volumes, and the rest belong to
   the base).

Violations do not fail you: the run is flagged `off_matrix` as a custom
fixture, measured at full fidelity, with grid placement provisional. A
supported design without an overlay, on the other hand, is a load-time
hard error naming the missing file.

Merged bring-up is plain compose file merge, base FIRST (the overlay's
relative build context resolves against the first compose file's directory):

```sh
docker compose -f $CHECKOUT/compose/t1.yaml -f $CHECKOUT/plugins/my-gateway/overlay/t1.yaml up -d
docker compose -f $CHECKOUT/compose/t1.yaml -f $CHECKOUT/plugins/my-gateway/overlay/t1.yaml --profile sensor up -d tracee
```

## 4. Make its decisions legible

Two paths:

- **The shim path**: translate your product's log into
  `decision-record/1`, one record per decision. The full contract, the
  field-by-field mapping, and the L1 verification run are in
  `docs/shim-guide.md`. The bundled reference shim is the v0 AuditEntry
  reader-side mapping in `framework/records.py`.
- **Native emission**: emit `decision-record/1` directly
  (`decision-records.jsonl`) and echo the correlation carriers
  (`io.inspection/action_id` in MCP `_meta`, `x-inspection-action-id` in
  HTTP). This is the stronger path (a higher evidence ceiling and the L2
  fidelity check); see the shim guide's upgrade path section.

## 5. Validate before measuring

Write your experiment file (the only user-facing config format, DESIGN.md 6):

```yaml
schema: 1
control: my-gateway
designs: [t1]
harness: pi
workload: baseline-15
```

Then:

```sh
guardscope validate your-experiment.yaml
```

What it checks: the experiment schema and semantic pairing (your manifest
loads, its kind is `control`, the requested designs apply to your control
and to the harness's supported t-modes, each a hard error naming the
conflict on mismatch); the manifest-vs-design overlay pairing (a supported
design with no overlay file is a load-time error); and the on-matrix
validation, whose problems appear as `overlay_problems` with `off_matrix:
true` in the printed plan rather than as errors. Run the L1 conformance
check over a recorded log set as well (`docs/shim-guide.md`, section 5);
`guardscope validate` checks wiring, not your records.

## 6. Measure

Start with the mock harness (the reduced stand-in that performs the
canonical actions directly; a fixture, never a measured subject). Why
first: it needs no agent harness, it is deterministic (replay injection,
no LLM in the loop), and it is how exposure measurements (paths that exist
and escape your placement, kernel-confirmed) get their numbers. Its cells
carry the `mock-run` evidence class, reported separately from
`harness-run` cells. Use `examples/t1-mock.yaml` (or `t2-mock.yaml`,
`t3-mock.yaml`) as the template, with the mock fixtures
(`compose/t1-mock.yaml`, ...) and the pinned route plans
(`mock_harness/plans/t1.json`) crossing your slot.

Then a real harness for harness-realistic cells (the pi and OpenClaw
adapters; templates `examples/t1-pi.yaml`, `examples/t1-openclaw.yaml`):

```sh
guardscope run your-t1-mock.yaml       # mock harness, with the mock topology up
guardscope run your-t1-pi.yaml         # real harness
guardscope run your-t1-pi.yaml --no-sensor   # degraded mode, see below
```

The topology comes up with docker compose (section 3) before `run`; the run
writes its artifacts under the workdir: `runs/<run-id>/` plus
`runs/<experiment-id>/execution.json` (the merged report input). On a
machine without kernel privileges, `--no-sensor` completes the run in the
degraded mode: every output is labeled `self-reported`, and C6 (denial
effectiveness) is skipped with a note. Do not mix sensor and no-sensor runs
in one grid: they never compose (the sensor key differs, by design).

## 7. Read your column honestly

Your run produces one design column of the shared path x design matrix:
per-action-class rows over the 15 canonical actions of baseline-15, plus
outcome counts, evidence class, degraded flags, and findings. Merge
columns with `guardscope report` (see the README and DESIGN.md 10); the
merged report never upgrades an evidence class, never averages colliding
cells, and lists designs your manifest supports but no run covered as
untested.

What your cells mean (the instance-level vocabulary,
`runner/outcomes.py`):

| Cell value | Means | What you can claim |
|---|---|---|
| `checked-allowed` | The action crossed your point, was allowed, took effect. | The path is inspected by your placement. |
| `checked-denied` | Crossed, denied by policy, no effect. | Inspected and stopped by your policy. |
| `bypassed` | Took effect; no decision from you. | The path escapes your placement (this is the finding, not a loss). |
| `prevented` | No decision from you and no effect; a mechanism outside your policy stopped it (v1: forced egress in t2/t3). | Nothing about your product; the environment stopped it. |
| `indeterminate` | None of the above held cleanly (e.g. denied but took effect: the denial did not hold). | Nothing; it is always a failure to fix, not a number to report. |

Evidence classes (per cell, never upgraded at report level):

- `harness-run`: a real-harness run with the kernel sensor present.
- `mock-run`: a mock-harness run with the sensor present ("the path exists
  and escapes this topology, kernel-confirmed; no agent in the loop").
- `self-reported`: any run without kernel evidence (`--no-sensor`); claims
  only, marked unverified.
- `derived`: summary rows recomputed at report level; they take the worst
  contributing class and are labeled as derived.

Other things to read before claiming: `degraded` flags (e.g.
`sensor-absent`) on the run summary; attribution methods (the reconciler
records how each decision was joined: `id` and `target_identity` are
implemented today; `process_tree` and `time_window` are specified in
DESIGN.md 5 but not implemented in this pass); the fixture fingerprint
(base compose sha256 + your overlay sha256 + the deployed policy sha256, so
your version bumps move the fingerprint on their own, and runs under
different fingerprints are not comparable); and the vendor-overlap flag
(when your plugin id equals the harness's, the report shows it, so
selectively chosen run sets are visible).

## 8. Where to ask for help / what is not supported yet

- The kernel-position design (t7) has no validated fixture yet; its
  reference fixture is not materialized in this pass.
- The curated registry tier requires framework CI, which does not exist
  yet; recorded conformance verdicts are open-tier and self-attested.
- The distribution package is editable-install-from-checkout: `pip
  install -e .` from the repo, not a published package; a distribution
  bundle is later work.
- Attribution beyond `id`/`target_identity` (process-tree and time-window
  joins) is specified but not implemented.
- Questions and problems: open an issue against the repository; the
  decision log (DESIGN.md 11) records every contract decision.
