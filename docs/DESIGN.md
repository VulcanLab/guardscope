# guardscope design

Status: authoritative design document. Derived from the settled decisions of the plugin-architecture, interface-contracts, one-control, framework-pivot, and generic-harness councils. Where an earlier document and this one differ, this one wins.

## 1. Overview

guardscope is a measurement framework for LLM-agent runtime controls. A runtime control (a gateway, an in-process policy engine, a kernel monitor) can only evaluate actions that cross its enforcement point; a coverage claim is therefore only as good as the evidence that the action actually crossed the point. Guardscope makes this measurable: it runs a declared workload through a real agent harness via deterministic replay injection (no LLM in the loop), ingests decision records emitted by every enforcement point in the topology, reconciles those records against kernel-level ground truth observed by a Tracee eBPF sensor, and emits a path x design coverage grid in which every cell carries an evidence class. The evidence rules are fixed: decision records are claims, not facts; coverage is computed by reconciling claims against kernel observation; outcomes (`checked` / `bypassed` / `prevented`) are derived only by the reconciler and never asserted by any measured component. It is a reproducibility instrument, not a paper contribution: it exists so that a third party can re-run a pinned measurement and so that coverage can be re-measured as tool versions change.

It is for three kinds of users:

| User | Wants | Main tools |
|---|---|---|
| Control author | prove (or learn) which paths their product inspects, under a kernel-verified protocol | control contract + conformance kit |
| Platform team | compare controls against a fixed fixture and workload, per-position attribution | experiment file + `report --merge` |
| Researcher | re-run the pinned reference snapshot; study how coverage changes across versions | reference snapshot + registry pins |

## 2. Layering

The rule: **plugins are everything the framework measures or exercises; the core is everything that defines or interprets measurement.** No core code may behave differently depending on a plugin's identity.

| Layer | Contents | Admission / authority |
|---|---|---|
| Core science | designs T0-T7 + path taxonomy; fixtures (declarative data + bounded hooks); classification semantics (`checked`/`bypassed`/`prevented`); evidence classes; reconciliation engine (C1-C6); badge criteria; selection-rule protocol; conformance suites (golden fixtures); decision log | Not registrable; changed only by a major release (one that changes measurement semantics); grids citable under the design set used |
| Instrument | kernel sensor (Tracee today) behind a versioned instrument interface | Exactly one approved sensor per release line; it cannot be registered and cannot be chosen in the experiment file; a new candidate is admitted by running it alongside the current sensor on calibration workloads, plus an equivalence study, in a major release |
| Plugin: control | native controls; shims (`record_source: ingested` + mandatory `raw_ref`); eBPF-enforcing controls (mandatory kernel-interference declaration + pre/post-provision sensor checks); harness-embedded controls (separate registration, `embedded` deploy slot) | Registry, id@digest pin, L1/L2 conformance |
| Plugin: harness adapter | real harness adapters; the exerciser (reduced form, plus a parity check against a real adapter) | Same |
| Plugin: workload | baseline-15 (reference, pinned per major release); adversarial packs; LLM-generated packs (provenance + exploratory flag) | Content-addressed; distinct typed contract (see §8) |
| Plugin: renderer | report renderers consuming the standard grid export | Open registry; may not recompute coverage or define badge meanings |
| Plugin-owned data | reconciliation profiles: declarative matchers shipped with the control/shim; golden-set conformance (loose matchers cannot inflate `checked`); migrate core-resident profiles out over two release lines | Validated in conformance |
| Custom fixtures | experimenter-authored wiring; `off_matrix` flagged | Declared in experiment file; registry-tracked for recurrence; promotion via design RFC only |
| Registry | manifest index; version-keyed expiring verdicts; per-product capability facts; candidate-design queue | Two tiers: curated (CI re-verified, eligible for the main grid, small, funded) + open (self-attested, labeled) |
| Experiment file | the four user fields (§6); plugin pins; design references; embeds design-set, contract, and sensor versions | Authored by experimenter; recorded per run |

**Sensor exception.** The kernel sensor is not a plugin. It is runner-managed, exactly one per run, one clock source. There is exactly one sensor per run. The runner enforces this (the sensor starts first; it cannot be set from the experiment file) and checks it by behavior (its health report is a required run input; it is re-checked after control provisioning, because a kernel-level control can interfere with or tamper with it; a failed sensor check invalidates the run). The sensor is kept out of every plugin contract, so no plugin can change it. A new sensor (e.g. Falco) must be cross-validated against the current one on calibration workloads, plus a ground-truth equivalence study, and is added in a major release; it is never a plugin registration.

**Reference-plugin governance.** Reference plugins serve as the conformance baseline that CI runs against continuously. This is stated openly, not denied:

- A `reference` label affects interpretation only (they are the calibration set); it has no effect on evidence classes or main-grid results.
- Equal treatment is enforced: no core code depends on plugin identity, and CI checks that reference plugins use only the public contract.
- When only a reference plugin needs a contract change, the change is first made inside that plugin's adapter, flagged as contract-external and excluded from main-grid cells. It is promoted into the contract only when a second, independent plugin needs it, with a public decision-log entry naming the other plugins that benefit.
- Every contract decision is published and citable.

## 3. Contracts

### Control contract (six operations, one contract, capabilities declared per plugin)

| Operation | Meaning |
|---|---|
| `describe()` | Static manifest: slot kinds supported; `record_source: native \| ingested`; correlation capability claims (`echoes_meta`, `echoes_header`, probe-verified, never trusted); observable action classes; `can_enforce: enforce \| observe` (an observe-only control can never produce `prevented`); supported schema versions |
| `provision(slot)` | Slot-typed: `container` (image + compose service), `attached_process` (configure an existing host/process), `log_ingest` (register a vendor log source; the shim case). Returns `{handle, attach}`; the attach descriptor is per-slot and carries the runner-assigned `stream_id` plus typed env (`GATEWAY_URL`, `MCP_GATEWAY_URL`, `GATEWAY_TOOL_ROUTES`, `GATEWAY_FS`). No global singleton env |
| `configure(policy_descriptor)` | Idempotent, reversible; returns a policy fingerprint that must match `policy.policy_hash` in emitted records |
| `ready()` | Readiness must prove that enforcement works, not just that the container is running: it passes only when a runner-issued test action (one the loaded policy must deny) produces its decision record. A started container is not ready; opening the capture window too early silently produces false `bypassed` results |
| `collect()` | Flush-then-report: `{stream_locator, record_count, seq_range, flush_ack}`. One record per decision even when the control batches internally. Records arriving after the window closes with a valid `run_id` are accepted and flagged `late`; they are never dropped or counted silently |
| `teardown()` | Crash-safe, idempotent, removes volumes. A leftover `decisions.jsonl` from a previous run must be impossible; returning success means the records were durably written |

**Shims are not a separate tier.** A shim implements the same contract with `record_source: ingested` and mandatory per-record provenance (`adapter`, `adapter_version`, `raw_ref`: source + line/offset pointing back at the vendor log line). Two conformance levels:

- **L1 (translation):** schema-valid records from a recorded canonical-run log set + reconciliation to expected outcomes.
- **L2 (native):** full lifecycle + correlation probe; a `native` badge requires L2 plus at least one harness-run path.

The reconciler enforces the limit: ingested records can support `bypassed` (kernel evidence alone proves it), but a `checked` verdict based only on ingested records is `derived` evidence and is degraded unless the kernel corroborates it. The L1/L2 evidence limit must stay visible in every cell.

**eBPF-enforcing controls** must declare kernel interference and pass pre- and post-provision sensor checks; a blinded sensor invalidates the run; if the sensor cannot observe the control's enforcement, that is a reported measurement limit of the instrument, not a hidden gap.

### Harness adapter contract (six operations)

| Operation | Meaning |
|---|---|
| `describe()` | Harness version; hostable enforcement points; supported T-modes; retry policy |
| `configure(enforcement_config)` | T4/T6 permission chains per run, from the same policy-descriptor form as controls; deterministic, no leftover state from earlier runs; returns config hashes |
| `ready()` | Dispatch loop running (readiness confirmed by a signal, not by a fixed sleep delay); gateway endpoint responding; replay injection confirmed |
| `inject(trace)` | Single-pass, ordered, no retries by contract default; if the adapter cannot disable internal retries it emits one dispatch record per attempt and the run is flagged; sets correlation carriers wherever the transport allows |
| `collect()` | Dispatch-record flush |
| `teardown()` | State isolation between grid cells; permission state must not leak |

Harness-native enforcement (T4/T6) emits decision records in the main schema with the harness as the `enforcement_point`. Dispatch records use the sibling schema `dispatch-record/1` sharing the identity fields; this shared identity closes the T5 attribution gap (the two record streams previously had no shared id). **The exerciser formally implements this contract in reduced form** (`describe` / `inject` / dispatch records), so exerciser-derived cells are treated the same as harness cells and the dispatch tooling is shared. The exerciser is never called a harness: it is a path-originator fixture, an instrument on the workload side, never an evaluated component and never a row or column of the grid. It only adds provenance labels to cells.

Determinism is a set of contract clauses (replay only, no LLM, pinned loopback targets, fixed argv/paths, declared timeouts), verified by pinned hashes in the run manifest, not a separate receipt artifact.

### Emission test and declaration taxonomy

Every component that **can emit a decision-record stream** must be declared as exactly one of:

| Class | Declared by | Configured by | Selectable | Example |
|---|---|---|---|---|
| `selected` | user, experiment file | user | yes, max 1 | gateway (T1/T3/T5) |
| `harness-intrinsic` | harness `describe()` | fixture `enforcement_config` | no | T4/T6 permission chain |
| `fixture-intrinsic` | fixture declaration | fixture | no | record-emitting jail variant; composition-mounted controls |
| environment | fixture fingerprint | n/a | no | T2 forced-egress jail (silent), netns/routing |

The emission test: emitters are declared; non-emitters are environment. The silent egress jail emits nothing, so it is environment topology, hashed into the fixture fingerprint and rendered as a note on the design column (this is exactly what distinguishes T2 from T1); a hypothetical record-emitting jail is fixture-intrinsic and must be declared. Undeclared emitters are conformance failures, detected by a test action plus a kernel-truth anomaly check.

**One selected control per run.** An on-matrix run selects at most one control: one plugin product, nullable, together with the positions its manifest declares. Selection counts plugins, never positions. `control: null` with an enforcement-capable harness is the natural expression of the T4/T6 configurations. Registered is not selectable: harness-intrinsic enforcement registers through the control contract (so its records flow into grid attribution per position) but is never user-selectable. No run-level syntax may name two controls; two-selected-control deployments run only as off-matrix composition fixtures (§7), measured at full fidelity and projected to the nearest design. Every grid position carries an origin label (`selected` / `harness-intrinsic` / `fixture-intrinsic`).

**Multi-position products.** One plugin per deployed artifact; the capability manifest declares N enforcement-point positions; fixtures bind positions to slots; one provisioning. Per-slot record streams with per-slot policy identity; the grid attributes per `(path x design x position)`; product rollups are derived views with per-position decomposition preserved, never summed away; unobservable positions get an explicit marker; conformance verdicts are per-position. Harness-embedded controls (T4/T6) register separately as control plugins with an `embedded` slot; composition inside one process does not exempt it from coverage accounting; otherwise T4/T6 cells would be judged by the harness's own records alone. Self-judging is impossible regardless: C1-C6 kernel corroboration independently verifies inspection no matter who emitted the claim.

## 4. Record schemas

### `decision-record/1` (JSONL, append-only, immutable)

Required fields:

| Field | Notes |
|---|---|
| `schema` | Literal, first field. Bare `1` (see stamps below) |
| `record_id` | ULID |
| `run_id` | |
| `stream_id` | Per-slot stream |
| `seq` | Per-stream monotonic |
| `ts` | RFC3339 ms; never an ordering key |
| `enforcement_point` | `{slot_id, product, product_version}` |
| `producer` | `{plugin, plugin_version, record_source: native \| ingested}` |
| `action_class` | Six-class enum |
| `protocol` | `mcp \| http \| stdio` |
| `tool` | Plus `method`/`path` for HTTP |
| `target` | Structured; hashed where sensitive |
| `parameters_digest` | |
| `action_id` | Nullable, opaque, echoed (never learned from configuration) |
| `attempt` | Integer, default 0 |
| `correlation_transport` | `mcp_meta \| http_header \| env \| none`; required even when ids are null |
| `decision` | `allow \| deny \| transform \| observe \| error` |
| `policy` | `{policy_id, policy_version, policy_hash}`; `rule_id` where available |

Optional fields:

| Field | Notes |
|---|---|
| `decision_detail` / `rule_id` | |
| `parameters` | Redacted; contractually secret-free |
| `error` | `{failed, fail_mode: open \| closed \| unknown}`. An `allow` record coexisting with a known control error is claimed-only and cannot ground `checked` |
| `transformed_target` | Required for `transform` decisions; the reconciler matches the kernel-observed post-transform effect |
| `ids` | Vendor-native request/session ids; debugging only |
| `evidence` | `[{kind, locator}]`; mandatory when `ingested` and when `decision == deny` |
| `source_schema` | Vendor log format identifier for shims |

**MUST NOT contain:** any outcome, verdict, attribution, or confidence (reconciler-only; a `bypassed` value inside a record is a schema-validation error); credential values or secret-bearing content (digests only); prompts or model I/O; kernel data (pointers only); aggregates; expected decisions; workload knowledge beyond echoed opaque ids.

### `dispatch-record/1`

Sibling schema sharing the identity fields with `decision-record/1`: `run_id`, `action_id`, `attempt`, `dispatched_at`, `carrier_used`, `result` or `error`. One dispatch record per attempt; declared retries emit one record per attempt with a fresh `attempt` ordinal.

### Stamps and versioning

- No type names inside data files. Every data file carries a bare `schema: 1`, meaning "this file type's format, version 1"; the type is given by context (the runner knows what it opened). Version numbers are scoped per file type and unrelated across types.
- Full identity (type + namespace + version) lives only in the JSON Schema `$id` (e.g. `https://<framework-host>/schemas/decision-record/1`) and in the run manifest, which records which format versions were used for everything in the run.
- Versioning is additive-only within `/1`; unknown-field tolerance is mandatory in every consumer and is kit-tested. Breaking changes go to `/2`. Fixtures are pinned per major.
- v0 `AuditEntry` (the gateway `decisions.jsonl` format) remains a valid input via a declared reader-side mapping; existing data remains readable.
- The user-facing schema set: `experiment/1`, `decision-record/1`, `dispatch-record/1`, `capabilities-manifest/1` (a small identity/capabilities block inside the plugin package: id, version, positions, emitted schema versions). The grid-plan and composition schema families are dropped (§6, §10).

## 5. Correlation

**Keys:** `action_id` (opaque, stable per spec action, generated by the adapter from the shared trace package) plus integer `attempt` (default 0). Join key: `(run_id, stream_id, action_id, attempt)`. No second opaque id in v1; vendor ids live in the optional `ids` map. A causation/hop chain is deferred to `/2` for chained-control topologies.

**Carriers (how the ids travel), in priority order:**

1. MCP `tools/call` `params._meta` namespaced keys: `io.inspection/action_id`, `io.inspection/attempt`.
2. HTTP headers: `x-inspection-action-id`, `x-inspection-attempt` (transport-conditional; not assumed more reliable than `_meta`).
3. Target-identity join, exact, not heuristic, for the four escape classes (targets pinned by the fixture manifest).
4. Process-tree/cgroup, then time-window; labeled heuristics.

**Rules:**

- Controls are workload-blind. A control must never record an `action_id` learned from configuration; ids are echoed from the protocol carrier or emitted as null. Null means traffic from outside the workload; its volume is reported per stream, never dropped silently. A control that strips ids on inspectable traffic is a reportable defect.
- Every join records `attribution_method: id | target_identity | process_tree | time_window`. No method, including id echo, grounds `checked` without kernel corroboration.
- **Fidelity probe** (conformance kit, gating): send a marked call through the control per transport; assert the id appears in the emitted record; publish per-control, per-transport capability flags (e.g. "product X preserves `_meta`"). Capability preservation is a measured, per-control capability, never a contract assumption.

## 6. Experiment file

The only user-facing config format. Four user-facing fields; these are the experimental variables:

| Field | Status |
|---|---|
| `control` | Required, nullable. `null` means no selected control, intrinsic enforcement active |
| `designs` | Required, explicit, validated. The runner never infers designs. Each requested design is checked at load time against the control's capability manifest and the harness's supported T-modes; an inapplicable design is a load-time hard error naming the conflict, before any topology is provisioned. Multiple applicable designs: the user lists them; one run per design |
| `harness` | User-specified; default is the prepared default harness |
| `workload` | User-specified; default is the prepared default pack (baseline-15) |

Anything omitted is filled with a prepared default and written into the run manifest as a fact rather than requested as a choice. Recorded defaults, for operational details only:

- control version: latest conformant, pinned at run start;
- fixture: the reference rig matching each requested design;
- sensor: runner-managed, never a field.

An optional `fixture` block overrides the reference rig; custom and composition fixtures are declared in this block (below). Any inapplicable pairing (unsupported design for the harness, workload requiring undeclared capabilities) is a load-time hard error.

Minimal example:

```yaml
schema: 1
control: agent-governance-gateway   # or null
designs: [t1, t3]
harness: pi
workload: baseline-15
```

`control: null` with an enforcement-capable harness is shown differently from the T0 baseline (no selected control, intrinsic enforcement active).

**Composition** is a fixture variant inside the experiment file, not a separate schema family. A `composition` block declares two controls, auto-sets `off_matrix: true` (the flag need not be written explicitly), and is a gated block that may never appear alongside a non-null `control` block:

```yaml
schema: 1
control: null
designs: [t5]
harness: pi
workload: baseline-15
fixture:
  name: my-two-gateway-stack
  composition:
    - plugin: gateway-a
    - plugin: gateway-b
```

When a production stack runs two controls (gateway plus guardrail SDK), the honest default is the composition fixture: the production system's behavior is the composite, not either control alone. Two single-control runs against the same named fixture remain the path for per-product attribution.

A plan file (`guardscope batch --plan plan.yaml`) is the only file that names more than one control or design: it expands into K single-control experiment files plus a merge manifest. This makes the one-control rule easy to check: no artifact except the batch plan ever names a cross product.

## 7. Fixtures & designs

**The split.** Designs (T0-T7) are part of the core: the abstract enforcement-point placement, versioned with the major release. Fixtures are core-owned data realizing a design: a concrete, versioned, hash-pinned realization binding plugins by capability into slots. A custom topology is a documented fixture, not a contract; there is no topology DSL in v1.

Reference designs and fixtures:

| Design | Enforcement placement | Reference fixture notes |
|---|---|---|
| T0 | None (bare harness); defines the full action surface | Reference row for kernel signatures |
| T1 | Gateway for HTTP tools; transport/process escapes exposed | All egress open |
| T2 | T1 + forced network egress (default-deny at netns output) | Egress jail is environment: silent, non-emitting, hashed into the fingerprint |
| T3 | Gateway as sole enforcement point, all tools behind it; stdio transport eliminated | Kernel sees one pooled connect per tool call; shared pooled envelope in reconciliation |
| T4 | Harness-native permission chain | `control: null`; permission chain is harness-intrinsic, configured by `enforcement_config` |
| T5 | Harness permission chain + gateway (two points) | Gateway is selected; chain is harness-intrinsic; the attribution gap between the two record streams is the measurement finding |
| T6 | In-process policy engine (declarative rules at the harness tool-call hook) | Harness-embedded control registers with an `embedded` slot |
| T7 | Kernel-level enforcement | Observation row: kernel observability of all 15 paths |

**Custom fixtures** run off-matrix: full measurement fidelity (all streams, all evidence classes), but only grid placement is provisional. They carry an `off_matrix` flag, a mandatory **nearest-design projection** (which core design the fixture most resembles, plus a divergence note), and registry-tracked recurrence. The flag controls whether results enter the grid, not whether they are published: off-matrix results appear in an extension section with their own evidence class.

**Off-matrix promotion path.** Tracking repeated custom fixtures turns the off-matrix section into a path toward new designs. A design RFC must state:

1. An enforcement-point position that the current designs cannot express.
2. Kernel-ground-truth evidence from at least two real controls and at least two independent experimenters.
3. A realizable reference fixture.
4. An observability statement.
5. A re-tiering impact statement.

Design-set review happens at each major release, with response deadlines, published criteria, and decision-log rationale. Old grids remain citable under the design set they were measured with. Composition fixtures (two user-selected controls, the defense-in-depth case) get a fast-track RFC path with re-badging after promotion, so repeated compositions can become numbered designs at low cost.

Accepted limitations: merged columns are independent runs, not one run; they cannot reproduce interaction effects (one control rewriting an action so another control never sees it; the T5 finding depends on both controls running at the same time). And: two selected controls cannot be measured together in one on-matrix run until a composition design is promoted. These are documented costs, not oversights.

## 8. Workloads

Workload packs are registered and versioned like plugins, but follow their own smaller contract. The workload contract is a distinct typed contract with no enforcement points, no decision records, no readiness handshake, and no conformance verdicts. Fields:

| Field | Notes |
|---|---|
| Content digest | Content-addressed pack |
| Declared path set | Against the core taxonomy; a path outside the taxonomy is off-matrix, the same rule as fixtures |
| Injection-only metadata | No policy-facing semantics; workload-blindness constrains controls and runner wiring, enforced as a conformance test on them, not a condition on workload authorship |
| Determinism block | Class + seeds |
| Generation provenance | For generated packs: model + prompt pinned; exploratory until replay-conformance passes |
| Minimum kernel-signature requirements | What the sensor must be able to see for the pack to be reconcilable |

`baseline-15` is the default pack and the reference workload, pinned per science release. The exerciser is the reference path-originator: a hash-pinned path manifest (all 15 paths with class, operation, origin channel, expected kernel-visible signature, expected inspection points per design, attribution rules for deferred/async instances), a policy-blind originator library (one deterministic primitive per action, syscall-level for the bypass classes, plus an inspected twin per bypass path as negative control; no code shared with the inspection layer or the mapper), and a thin deterministic driver reading the canonical trace from the shared package (one definition used by both replay injection and the exerciser, so the two cannot drift apart). The driver executes the full action surface unconditionally and never knows which paths are expected to bypass; classification comes only from reconciliation.

**Exerciser placement modes** (configuration of the same code, not separate codebases):

- **Mode H (hosted, preferred):** call the originator library from inside the real harness's extension mechanism. Strongest placement: the control being escaped is the real permission chain.
- **Mode C (co-resident, default for exposure cells):** the driver runs as a second process in the harness's compose service while the real harness replays its inspected actions with the design's controls active. The originators must be policy-blind; the run must have the control present and active. No meaningless cells (a cell measured with no control running).
- **Mode R (standalone):** driver alone, for the T0 reference row and the T7 observation row; later the base for LLM path discovery.

**Evidence gates** (all mandatory before exerciser-derived bypass cells are citable):

1. Reanalysis of existing traces first; reconcile and attribution rules fixed on real-harness data before any exerciser cell is recorded.
2. T0 calibration diff: exerciser kernel signatures indistinguishable from real-harness captures for inspected paths; bypass paths validated against manifest signatures.
3. Inspected-twin check per design: the twin must classify as `checked` under that design before that design's bypass rows are recorded.
4. Capability/placement diff documented per run (exposure claims depend on the privileges of the process).
5. Tracee integrity check on the target kernel before the T7 row.

Hard properties: per-process determinism with interleaving-independent classification; digest pinning; trust-domain placement documented per run; independence (no self-reporting; Tracee is the sole ground truth); policy-blind originators; never a row or column of the grid; only per-cell provenance labels. Exposure (a path exists and escapes) is a property of the topology: any policy-blind originator inside the trust domain can prove it, if the kernel confirms the action executed. Inhabitation (real agents take the path) is a property of real agents: only real-harness runs can show it. Exerciser cells assert "the path exists and escapes this topology, kernel-confirmed; no agent in the loop." v1 exclusions: no OpenClaw host mode (the hook-API blockage must not drive the design; revisit opportunistically via a harness-spawned MCP server), and no overhead or performance claims from the instrument. Exerciser provenance (origin, placement, digests) is stored in a per-record field; the only other pipeline change is capture-window and attribution support for async paths (daemon submission, outliving processes) with ancestry-based attribution.

**Anti-overfitting rule:** primary published claims require at least one non-baseline pack; grid cells record which pack produced them; generated packs stay exploratory until replay-conformance passes; a leak check ships in conformance.

## 9. Run & reconcile

**Runner state machine:** `provision -> configure -> ready-gate -> window open -> inject -> quiesce (wait for in-flight actions) -> window close -> collect -> teardown -> reconcile`. The window opens only after every enforcement point passes its readiness check; only the runner controls the window, never a plugin.

**Tracee is runner-managed shared infrastructure:** one sensor per run, N controls, one clock source (host clock, offsets recorded at run start). Deploy, sensor check, collect, and teardown of the sensor are owned by the runner, not the control contract; the sensor is the measuring instrument and must never share the contract of the components it measures. Slot descriptors carry cgroup/namespace scope so the sensor can be scoped per slot. Sensor health (dropped-event counts) is a required run input; a run with a degraded sensor is downgraded and flagged, never trusted silently. The sensor is re-checked **after control provisioning** (a kernel-level control can interfere with or tamper with it); a failed sensor check invalidates the run. Known gaps are listed in every health report.

**Reconcile order:** partition by `stream_id`; join per point by priority `id -> target_identity -> process_tree -> time_window`, method recorded per join; per-point accounting, with cross-point joins deduped; then the versioned C1-C6 library:

| Check | Meaning |
|---|---|
| C1 | Parse: every decision record validates against `decision-record/1` |
| C2 | In-window and `run_id` match |
| C3 | Per-point 1:1 accounting (no missing, duplicated, or unmatched decisions within a stream) |
| C4 | No inspected-class leakage (unmatched kernel events in inspected classes are findings, not noise) |
| C5 | Id consistency: echoed ids match the carriers the harness dispatched; fabrication, duplication, and stripping are detected |
| C6 | Denial effectiveness: `prevented` = deny record + verified absence of the action's kernel signature; the expected per-class kernel signature is derived from exerciser baseline runs |

**Proxy-egress attribution rule:** a gateway proxying a tool call performs the `connect()` itself; kernel events from control processes must be attributed to the inspected action via slot cgroup scope, not to the direct-network escape class, or inspected designs accumulate false bypasses.

**Output.** Per action instance per enforcement point:

- `outcome: checked | prevented | bypassed | enforcement_failure | not_observed` (reconciler-only).
- `claimed[]` (decision records + attribution methods) and `verified` (kernel match) as **separate, never-merged structures**.
- `attribution_method`; `evidence class: harness-run | exerciser-run | self-reported | derived`; `degraded: [reasons]`; structured C1-C6 findings.
- Per-run leakage counters: unmatched kernel events, unmatched decisions, unmatched expected actions; organic-traffic volume per stream.

The primary reported numbers come from verified results only. Harness-run and exerciser-run cells are reported separately, never aggregated. Stated limit: `prevented` is the only fully kernel-verifiable outcome (deny record + verified absence of the action's kernel signature); `checked` confidence is limited by conformance, determinism, and record plausibility: a fabricated allow-record for an action that did occur passes both the id check and the kernel-presence check.

**Degraded no-eBPF mode** (the default path for users without kernel privileges, the main obstacle for new users): every output it produces is labeled `self-reported` / unverified. The claimed-vs-verified distinction is preserved even without the sensor.

## 10. Report & merge

A single-control run produces one **design column** of the shared path x design matrix: control fingerprint (or null), design, position set with origins. It is not a private result; the report shows the full design-column context, with untested cells marked untested, not omitted.

Grids are report-level merges of single-control run columns. There is no grid schema and no grid run mode: a grid is a batch loop over runs (`guardscope batch --plan plan.yaml` expands the plan to K experiment files; `guardscope report --merge runs/*` aggregates).

**Comparability key.** All must match for runs to compose into one grid:

- workload hash;
- fixture fingerprint, **including `enforcement_config`** (this pins the intrinsic chain policy; without it, comparisons between controls are unreliable);
- harness id + major version;
- kernel-sensor version;
- reconciliation profile id + version;
- classification-semantics version.

On mismatch, the default is separate grids; a forced single grid marks affected columns non-comparable (`--strict` hard-fails; `--allow-incomparable` is visible per cell).

**Merge guarantees:**

- Evidence classes are preserved per cell and **never upgraded at report level**; summary rows and aggregate badges take the worst contributing class; summary rows are recomputed at report level and labeled derived; untested cells are marked untested, not derived.
- Cell collisions (two run-sets covering the same control x design cell): keep both as distinct evidence rows with provenance, recency-mark one current; **never average**.
- Verdicts stay run-level and display per column; report-level badges are derived and can be earned only across comparable columns; staleness thresholds apply to badges.
- Cross-version merges (longitudinal) are annotated, allowed if the classification-semantics version matches, marked otherwise.
- All run manifests are embedded in the merged report; vendor-overlap flags (harness vendor == control vendor) are shown, so selectively chosen run sets are visible.
- Vendor-stacks caveat: when one vendor ships both harness and gateway, the intrinsic point is a product decision; the framework treats it identically either way, because the grid measures positions, not products.
- Origin labels (`selected` / `harness-intrinsic` / `fixture-intrinsic`) are shown on every grid position.
- Off-matrix columns render in an extension section with labels, nearest-design projections, and never contribute to on-matrix rollups.

Renderers are plugins that consume the canonical grid export; they may not recompute coverage or define badge meanings.

## 11. Registry & governance

Three strict layers:

| Layer | Owner | Contents |
|---|---|---|
| Plugin manifest | Plugin author | Claims, immutable per version |
| Registry | Curator | Verdicts keyed by `(plugin version, contract version, framework line, suite version, golden-fixture hash)`; per-product capability facts with provenance and expiry; candidate-design queue |
| Experiment file | Experimenter | The four user fields plus resolved pins, all stamped into the run manifest |

**Two tiers.** Curated: framework-CI re-verified per release candidate, eligible for the main grid, kept small with a fixed member limit and rotation, funded, with a stated fallback; if it cannot be maintained, the main reported claims are narrowed rather than letting stale verdicts claim to be current. Open: self-attested, labeled, appendix-only. Verdicts expire when any key changes; staleness downgrades the display (as-of version) instead of hiding it, so outdated verdicts are visible, not silent.

**Contract versioning.** Additive optional fields are a minor bump; record schema, reconciliation semantics, and evidence classes are major, with a two-release deprecation window; the runner refuses version mismatches rather than guessing.

**Sanctioned extension field.** One sanctioned non-conforming extension field on records: core-ignored, report-flagged. This keeps vendor experimentation visible and feeds RFCs instead of hidden, undocumented paths.

**Decision log.** Every contract decision is published and citable, including the analysis of which other plugins benefit (§2).

**Manifest verification (declaring is not the same as conforming).** At certification, a test replay checks that every kernel-observed decision maps to a declared position; a declared-but-silent position fails the run's readiness check; an undeclared component that acts anyway shows up as a kernel-truth anomaly. Plugin manifests are versioned and signed.

## 12. Migration from the existing testbed

Source: the internal research testbed (kept in the original research repository; imported with its recorded run data removed from this repository). The testbed is working; the extraction preserves its behavior while moving each component to its place in the framework.

| Existing component | Framework home | Notes |
|---|---|---|
| `trace/` (baseline.yaml + sha256, schema, compile) | Workloads: the baseline-15 pack; the shared trace package (one definition for replay injection and the exerciser) | The 15-action canonical trace becomes the default workload pack |
| `exerciser/` (manifest, originators, driver) | The exerciser plugin (reference path-originator fixture) + path manifest in core science | Keep the hash-pinned manifest as a core artifact |
| `runner/coverage.py` (C1-C4, coverage computation) | Core reconcile library | The AuditEntry loader becomes the v0 reader-side mapping |
| `runner/reconcile.py`, `outcomes.py`, `runrecord.py` | Core reconcile library (C1-C6 library, run-record assembly) | Design-aware rules (e.g. `PREVENTED_CLASSES`, the T3 shared pooled envelope) become fixture-declared reconciliation parameters |
| `runner/run.py` | Runner, re-driven by the experiment file | `--design` flags and manually started Compose stacks are replaced by load-time validated `designs` |
| `runner/profiles/` (pi, openclaw, agentgateway, claude-sandbox, docker-mcp-gw, nemo) | Plugin-owned reconciliation profiles (shipped with each control/shim) | Migrate core-resident profiles out over two release lines |
| `sensor/` (Tracee container, args, smoke) + `sensor/mapping/` (rules.yaml, map_events.py) | Instrument layer | Mapping version (`MAPPING_VERSION=6`) becomes part of the instrument interface version |
| `harnesses/pi`, `harnesses/openclaw` | Reference harness adapter plugins | Determinism clauses move from adapter code into the contract |
| `gateway/` (AGT MCP Security Gateway) + `targets/` + `compose/` (t0-t6.yaml) | Fixtures: the reference rigs realizing T0-T6 (no T7 compose rig exists; the ActPlane kernel-verifier incident is retained as the T7 record); the gateway becomes the first reference control plugin | The T5 attribution-gap finding drives the correlation carriers design |
| REMOVED-ROW
| `env/versions.env` | Run manifest + registry pins | Version pins become recorded facts, not environment files |
| The paper's 12 verified configurations | The reference snapshot: a published, dated, hash-pinned set of run manifests under guardscope | Grids remain citable under the design set used; the snapshot is evidence, not a demonstration |

**Renames.** The testbed and the paper use "mediation" (mediation-coverage, `MEDIATED_CLASSES`, `/mediation-replay`); the framework uses "inspection" everywhere (inspection coverage, inspection boundary, inspected/bypassed, `io.inspection/action_id`). The paper keeps its own submitted terminology. Renaming mediation -> inspection in code identifiers is an M1 refactor decision at extraction time: mechanical, done once, with the v0 `AuditEntry` reader mapping preserving data compatibility. This document records the decision; it does not perform the rename.

## 13. Roadmap

| Milestone | Contents |
|---|---|
| M1 | Extraction and the code-identifier rename (mediation -> inspection, mechanical, once); the two contracts (`control`, `harness`); both record schemas (`decision-record/1`, `dispatch-record/1`); the experiment-file runner with load-time validation; the C1-C4 reconcile library; the exerciser and the AGT gateway as the first two control-side plugins (the pi and OpenClaw adapters are equally in scope as the reference harness plugins); the v0 AuditEntry reader mapping |
| M2 | Fidelity probe; C5/C6 (id consistency, denial effectiveness via exerciser-derived kernel signatures); `report --merge` with the comparability key; the registry (two tiers, expiring verdicts); the conformance kit (L1/L2); the degraded no-eBPF mode, labeled self-reported |
| M3 | First third-party control admitted through the conformance kit; success criterion: that third party reproduces the reference tables unaided; the reference badge |
| M4+ | Scenario packs; LLM-driven path discovery on the exerciser substrate (Mode R); decay-tracking mode (re-running pinned snapshots across control versions, the measurement the framework exists to enable) |

**Privilege tiers** (what a user needs to install): Tier 0 harness-native (no privileges), Tier 1 gateway designs (plain Docker), Tier 2 kernel/eBPF (privileged, opt-in, restricted kernel families). The degraded no-eBPF mode is the default path and is labeled self-reported/unverified. Multiple harnesses per run-set are allowed (switching the harness does not complicate attribution).

**CI scope (v1).** Determinism test (same trace twice, identical decision stream), schema conformance, and exerciser smoke on one pinned kernel; a manually maintained kernel capability matrix documents the rest, including the two known-failing families. No promise of hosted multi-kernel CI.

**Release gates (before any public release).** Adapter licensing check; responsible-release review of the exerciser (it is a deterministic bypass-path suite); the framework name stays neutral and distinct from any paper title.

**Framework conditionality.** The replication kit (M1/M2) is unconditional; the plugin-contract layer beyond it is justified by the longitudinal decay study commitment. If that commitment stops, fall back to the kit rather than maintaining contract features nobody uses.

Scope rule from the framework-direction decision: v1 ships only what has an existing consumer among the two harnesses and the controls in scope. Out of v1: GUI, hosted service, auto-discovery, non-Linux sensors, multi-node, LLM-driven workloads, a topology DSL, arbitrary third-party profile parsing. Deferred, documented, non-blocking: causation/hop chains and a second correlation id, `preflight` as a separate operation (folded into configure validation plus ready), streaming/drain APIs beyond collect-with-flush-ack, capability negotiation (the runner statically compares `describe()` output), health-check operations, multi-slot plugins, monotonic-clock fields, standalone determinism receipts (pinned hashes live in the run manifest), migration tooling beyond v0 reading, a second workload, richer decision values (`ask`, `throttle`, `not_evaluated`).

## Open questions

- **Open:** the JSON Schema `$id` host and distribution form (stable framework host vs. a relative-$id convention plus run-manifest-local type records) must be fixed before the first public release; the run-manifest recording mechanism is settled either way.
- **Open:** whether a `focus`-style field is needed to mark deployment-authoritative runs (platform-team stacks pinning a named fixture) beyond what the optional `fixture` override plus `control: null` already expresses; current reading is that no such field is needed, but the platform-team comparison workflow (two single-control runs against the same named fixture) has not been exercised end to end.
- **Open:** the exerciser's Mode H (hosted) placement lands with the exerciser plugin in M1 only if the extension-mechanism timebox succeeds; otherwise M1 ships Modes C and R and Mode H follows, per the generic-harness sequencing.
