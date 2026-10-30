# The shim guide: translating a control's log into decision records

Status: onboarding doc for control authors whose product emits its own log format.

Audience: an engineer whose control product (gateway, monitor, policy engine) writes a vendor log and wants its decisions measured by guardscope.

## 1. What a shim is and what it is for

Your control emits decisions in its own format. A shim is a small translator you write: it turns each vendor log line into one `decision-record/1` record (`framework/schemas/decision-record/1.schema.json`). The framework never trusts the translation: it validates every record against the schema (the L1 run, `framework/conformance.py`) and reconciles them against kernel-level ground truth at measurement time. The shipped reference example is the v0 AuditEntry reader-side mapping in `framework/records.py` (`audit_entry_to_decision_record`): it parses the gateway's `decisions.jsonl` into standard records, marks them `record_source: "ingested"`, and carries provenance back to the original line.

## 2. The record you must produce

One worked example runs through this section. The vendor line (line 128 of `sentinel-events.jsonl`, a made-up gateway monitor):

```json
{"ts":"2026-10-28T09:42:17.512Z","event":"tool_call","method":"POST","path":"/hook","tool":"post_hook","target_url":"http://mcp-http:8091/mcp","policy_name":"default-v3","policy_rev":3,"decision":"allowed","req_id":"req-8842","params":{"body":"tool-call payload"}}
```

Its translated record:

```json
{"schema": 1, "record_id": "01M65YCACGJ1SGJRHMSM484AQM",
 "run_id": "acme-t1-run-1", "stream_id": "acme-t1-run-1:gateway", "seq": 0,
 "ts": "2026-10-28T09:42:17.512Z",
 "enforcement_point": {"slot_id": "gateway", "product": "acme-sentinel", "product_version": "2.4.1"},
 "producer": {"plugin": "acme-sentinel", "plugin_version": "0.1.0", "record_source": "ingested"},
 "action_class": "http_tool_call", "protocol": "http", "tool": "post_hook", "method": "POST", "path": "/hook",
 "target": {"kind": "http_url", "value": "http://mcp-http:8091/mcp"},
 "parameters_digest": "b05db7694cad08a26985896fca61ff21dec07ae79cf0b2903d2ba38fbd11d728",
 "action_id": null, "attempt": 0, "correlation_transport": "none", "decision": "allow",
 "policy": {"policy_id": "default-v3", "policy_version": "3", "policy_hash": "<sha256 of your deployed policy file>"},
 "parameters": {"body": "tool-call payload"}, "ids": {"req_id": "req-8842"},
 "evidence": [{"kind": "vendor-line", "locator": {"source": "sentinel-events.jsonl", "line": 128}}],
 "source_schema": "acme-sentinel-event/0"}
```

Required fields, and where they typically come from in a vendor log:

| Field | Meaning / source |
|---|---|
| `schema` | The bare literal `1`, stamped first; no type names inside data files. |
| `record_id` | A ULID (26 chars); `framework.records.new_ulid()` generates one. |
| `run_id` | The run, from the run manifest (assigned by the runner). |
| `stream_id` | The per-slot stream, typically `<run_id>:<slot_id>`. |
| `seq` | Per-stream monotonic integer: the ordering key. Assign 0, 1, 2, ... in log order. |
| `ts` | RFC3339 with milliseconds; never an ordering key. The run manifest's measurement window decides which records count (C2): it scopes out lines from a previous run that leaked into the log volume. Map the vendor timestamp faithfully. |
| `enforcement_point` | `{slot_id, product, product_version}`: your product's name/version and the slot it occupies. |
| `producer` | `{plugin, plugin_version, record_source}`; a shim emits `record_source: "ingested"`. |
| `action_class` | One of the six classes: `stdio_tool_call`, `http_tool_call`, `direct_network`, `process_spawn`, `file_write`, `credential_access`. Classify by what actually happened. The schema has no null here: when your product does not distinguish classes, derive the class from the tool/protocol the way the shipped v0 mapping does (a routing table plus a declared default). A wrong class puts decisions in the wrong grid row; derive it, do not guess. |
| `protocol`, `tool` | `mcp` / `http` / `stdio`; the tool name. For HTTP, also the optional `method` and `path` when known (the v0 mapping fills them from the gateway routing table). |
| `target` | Structured `{kind, value, digest?, note?}`; hashed where sensitive (the convention: `kind: "digest"` with the digest in `value`). |
| `parameters_digest` | sha256 over canonical JSON of the redacted parameters; `framework.records.parameters_digest()` computes it. |
| `action_id` | Nullable; echoed from the protocol carrier (`io.inspection/action_id` in MCP `_meta`, or `x-inspection-action-id`), else null. Never learned from configuration. |
| `attempt` | Integer, default 0; echoed with the id (`io.inspection/attempt`, `x-inspection-attempt`). |
| `correlation_transport` | `mcp_meta`, `http_header`, `env`, or `none`. Required even when ids are null: `none` says the ids had no carrier on this traffic. Null `action_id` means traffic from outside the workload; its volume is reported per stream, never dropped silently. |
| `decision` | `allow`, `deny`, `transform`, `observe`, or `error`. A monitor-only product emits `observe`. |
| `policy` | `{policy_id, policy_version, policy_hash}` (+ optional `rule_id`). Take the deployed policy descriptor from the runner; the v0 mapping marks unknown policy fields `"unmapped"` rather than guessing. Without this identity two runs under different policies are incomparable: the fixture fingerprint pins the deployed policy, and the hash must match what your product loaded. |

Optional fields you will often want: `decision_detail` and `rule_id` (free-form detail / the matched rule); `parameters` (redacted, contractually secret-free, debugging only); `error` (`{failed, fail_mode: open | closed | unknown}`; an `allow` record coexisting with a known control error is a claim only and cannot ground `checked`); `ids` (vendor-native ids, debugging only, never a join key); `source_schema` (your vendor format identifier); `transformed_target` (required for `transform` decisions); `evidence` (`[{kind, locator}]`, mandatory when `record_source` is `ingested` and when `decision` is `deny`: the locator points back at the vendor log line, the `raw_ref` provenance).

## 3. The must-nots

- **No outcome, verdict, attribution, or confidence fields.** The reconciler derives them. `framework/records.py` rejects these keys at any nesting depth with a specific error: `outcome`, `verdict`, `bypassed`, `checked`, `prevented`, `attribution`, `attribution_method`, `evidence_class`, `confidence`, `degraded`, `expected_decision`. Unknown-field tolerance (mandatory for any other unknown key) is never granted to these. A vendor line may use the word "verdict"; map it to `decision`, never copy the key.
- **No secrets.** Digests only: `parameters_digest`, hashed targets; `parameters` redacted and secret-free.
- **No ids learned from configuration.** `action_id` is echoed from the protocol carriers or null. A control is workload-blind; an id from config would fabricate correlation. A control that strips ids on inspectable traffic is a reportable defect (detected by the C5 check).
- **Never edit the vendor line.** The `evidence` locator (`source` + `line`/`offset`) points back at it unchanged; that back-reference is what makes the translation checkable.

## 4. What an ingested record can and cannot prove

The evidence ceiling for translated records (DESIGN.md 3, 9):

- **bypassed: yes.** Kernel evidence alone proves a bypass.
- **checked: degraded.** A `checked` verdict resting only on translated logs is derived evidence; it counts when the kernel corroborates that the action actually crossed your enforcement point.
- **prevented: reachable through a shim.** A deny record in a translated
  log, plus the C6 check's kernel-verified absence of the action's effect,
  grounds `prevented`; a deny without action ids is attributed to its spec
  action by target identity (the same ladder the shipped v0 mapping uses).
  What native emission adds is id-based attribution (the correlation
  carriers) and the fidelity evidence, not `prevented` itself.

A monitor-only product (`can_enforce: "observe"`, `decision: "observe"`)
never issues its own denials, but its column is not limited to `checked`
and `bypassed`: under designs with an environment-level blocker (the t2/t3
forced egress), a `prevented` cell means the ENVIRONMENT stopped the action
(fixture-attributed, nothing about your product), and `indeterminate` is
always possible in principle. Read the cell's origin and attribution, not
just the word.

## 5. Verifying your shim (L1)

Record one real run of your control (its vendor log plus the run manifest's `run_id`, `design`, and measurement window), translate the log, and run L1:

```python
from framework.conformance import run_l1

golden = {                       # the golden set: one recorded run
    "format": "auto",
    "lines": records,            # your translated decision-record/1 dicts
    "run_id": "acme-t1-run-1",
    "design": "t1",              # required: the C1-C4 topology input
    "window": {"start": 1793171837286000000, "end": 1793171837564000000},
    "window_slack_ns": 1_000_000_000,
    "source": "decision-records.jsonl",
}
expected = {                     # the run's recorded per-class outcomes
    "http_tool_call": "checked-allowed", "stdio_tool_call": "bypassed",
    "direct_network": "bypassed", "process_spawn": "bypassed",
    "file_write": "bypassed", "credential_access": "bypassed",
}
verdict = run_l1(golden, expected,
                 plugin_id="acme-sentinel",
                 plugin_version="0.1.0",
                 suite_version="1")
```

`run_l1` also accepts a JSONL file path, or a recorded run directory (that form needs `plugin_id` and reads the first present of `decisions.jsonl`, `gateway/decisions.jsonl`, `decision-records.jsonl`, `gateway/decision-records.jsonl`, plus a `manifest.json` carrying `run_id`, `design`, and `timing.window_epoch_ns`):

```python
verdict = run_l1("runs/acme-t1-run-1", expected,
                 plugin_id="acme-sentinel", plugin_version="0.1.0",
                 suite_version="1")
```

The golden set's lines must be one format: the v0 AuditEntry shape or decision-record/1. A raw vendor log is neither; that is why the shim runs first. What the checks mean when they fail:

| Check id | Fails when |
|---|---|
| `L1-parse` | A golden line is not JSON (a malformed line is a problem, never a silent drop). |
| `L1-format` | Lines match neither accepted shape, or mix both in one set. |
| `L1-schema` | A record fails decision-record/1 or the outcome reject list; the failure names the line. |
| `L1-producer` | A record declares a producer other than the plugin under test. |
| `C1-parse` | A log line does not parse. |
| `L1-reconcile` | The record set does not reconcile: a decision has no v0-equivalent mapping, the golden set carries no design, or the coverage computation errors. |
| `C2-accounted` | An in-window decision maps to no inspected spec action: an unknown tool, a decision in a class the design does not inspect, or more decisions than spec actions. Out-of-window records are counted as `out_of_window`, never a failure. |
| `C3-evaluated` | A ground-truth action of an inspected class has no decision. |
| `C4-inspected-only` | A decision maps to a class the design does not inspect. |
| `L1-outcomes` | The derived per-class outcomes differ from the expected outcomes. |

A `pass` verdict is deterministic: the same inputs produce a byte-identical verdict. It carries its own registry key components (DESIGN.md 11): `plugin_id`, `plugin_version`, `contract_version`, `framework_line`, `suite_version`, and `golden_fixture_hash`; a change to any of them expires the verdict. Honesty note: with no framework CI yet, a recorded verdict is open-tier and self-attested (the shipped example, `registry/open/agt-gateway.json`, records the same limitation).

## 6. The upgrade path (native emission)

The stronger path: emit `decision-record/1` directly from your product (`record_source: "native"`, no translation step) and echo the correlation carriers: `io.inspection/action_id` and `io.inspection/attempt` in the MCP `tools/call` `_meta`, or the `x-inspection-action-id` / `x-inspection-attempt` HTTP headers. The shipped gateway does both (a native `decision-records.jsonl` stream alongside its v0 log).

Native emission unlocks:

- **The L2 run** (`run_l2`, `framework/conformance.py`): the full control lifecycle plus the correlation fidelity check, which sends one marked call per transport and verifies your id echo. It publishes measured per-transport capability flags (`preserves_meta`, `preserves_header`) to `plugins/<id>/fidelity.json`; manifest claims are never trusted.
- **Stronger attribution and fidelity evidence**: `checked` no longer rests on a translation, ids attribute by the carriers rather than target identity, and the fidelity check (does the control preserve `io.inspection` carriers) becomes available and records per-transport capability flags.
