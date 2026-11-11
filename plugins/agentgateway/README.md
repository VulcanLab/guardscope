# agentgateway control binding (plugins/agentgateway)

The guardscope binding for the CNCF **agentgateway** (agentgateway.dev):
an HTTP gateway placed at design T1 in front of the harness, restoring
the pre-guardscope probe's standalone-configuration measurement
(the old probe lives read-only at
`realtime-control-coverage/code/probes/agentgateway-t1/`; its lost
evidence is what this binding re-establishes under the framework).

## What is here

| File | What it is |
|---|---|
| `manifest.json` | capability manifest (kind `control`, position `gateway` at `t1`, `record_source: ingested`) |
| `overlay/t1.yaml`, `overlay/t1-mock.yaml` | the t1 control-binding overlays (real + mock fixtures), image pinned by digest |
| `config/t1-allow-all.json` | the deployed agentgateway config (the binding's enforcement_config artifact) |
| `collect.yaml` | the binding's runner recipe (phase 2a): the ingested record collection + the deployed-policy artifact + the readiness gate + the pi harness client module |
| `collector/capture.py`, `collector/Dockerfile` | the `control-agentgateway-trace` collector service: follows the admin `/debug/trace` SSE and persists the vendor decision rows to the slot's decision-log volume |
| `shim/translate.py` | the shim: vendor rows -> `decision-record/1` (record_source `ingested`, raw_ref provenance) |
| `versions.env` | every pinned identity (image digests, config digest, collector base) and its verification state |

Experiments: `examples/t1-pi-agentgateway.yaml`, `examples/t1-mock-agentgateway.yaml`.

## Image pin

CNCF agentgateway **v1.5.0** — the version the pre-guardscope probe pinned
and the version whose config/dtrace semantics this binding was verified
against (source rev `fe67324`, re-confirmed at runtime by the gateway's
own version banner during the 2026-11-10 local smoke). Pinned by the
**linux/arm64 manifest digest** `sha256:f64c27c8…` (platform pinned with
it; no cross-arch emulation). The v1.5.0 index digest and the amd64
manifest digest are recorded in `versions.env`; all three were re-verified
against ghcr.io on 2026-11-10 (the index digest matches the old probe's
record byte-for-byte). Current stable release is v1.7.0 (2026-10-27);
v1.5.0 is kept deliberately so the binding reproduces the probe's
configuration. To move to a newer version: pull the tag, verify the
digests, re-verify the config/dtrace semantics against that version's
source, and bump the pins here.

## The deployed config (config/t1-allow-all.json)

Verified against the v1.5.0 source:

- `config.adminAddr: 0.0.0.0:15000` — the admin listener (`/debug/trace`
  lives here); `0.0.0.0` so the collector service on the slot's network
  can follow the trace.
- `mcp.port: 8090` — the streamable-HTTP MCP frontend the harness
  services reach at `GATEWAY_URL=http://gateway:8090`
  (compose/slots/t1.yaml `harness_env`).
- `mcp.targets[0]` — the fixture's tool endpoint
  `http://mcp-http:8091/mcp`. ONE target with `prefixMode` at its
  default (conditional) means tool names pass through UNPREFIXED and
  every tools/call routes to this target
  (`mcp/upstream/mod.rs` `UpstreamGroup::default_target_name`); confirmed
  live (bare `post_hook`/`get_health`/`put_state` calls route through).
- `mcp.policies.authorization.rules`: `[{"require": true}, {"require":
  "json(request.body).method != \"tools/call\" ||
  json(request.body).params.name != \"__readiness_check__\""}]` — the
  CEL rule set evaluated per MCP request (the second rule is the
  readiness exception, see below; the body form is the old probe's
  live-verified shape — the resource-level `mcp.tool.name` form was
  tried and found to deny the initialize handshake itself, found live
  2026-11-10: the CEL reference errors for non-tool requests and a
  failed `require` is fail-closed). Two verified facts drive this:
  1. With rules present, EVERY tools/call produces exactly one
     `authorizationResult` dtrace event (allow/deny + per-rule matches)
     (`http/authorization.rs` `RuleSets::validate`).
  2. With NO rules the check short-circuits and NO decision event is
     emitted (`mcp/rbac.rs` `McpAuthorizationSet::validate`) — the
     explicit rule exists so the decision stream exists at all.

  The first rule is trivially true — the honest expression of the T1
  design's reference policy (`gateway/policy.yaml` `t1-allow-all`:
  `allowed_tools` post_hook/get_health/put_state, `denied_tools: []`):
  every request is CHECKED (one decision per tools/call) and ALLOWED;
  deny rules are deliberately absent over the measured surface, exactly
  like the reference binding. The second rule denies only the reserved
  readiness tool (no workload trace calls it), so the measured surface
  stays allow-all and T1 measures topology coverage (what crosses the
  gateway), not policy content. `can_enforce: enforce` is the
  capability, not this file's setting: the same rule-set mechanism
  denies requests (`ProxyError::AuthorizationFailed`), and the
  pre-guardscope capture retains a live deny (HTTP 403) under a
  body-checking rule.

## The decision path (record_source: ingested)

agentgateway writes no decision log; its decisions are visible only on
the admin `/debug/trace` SSE (per-request `authorizationResult` dtrace
events with the request state). The binding therefore has three parts:

1. **Collector** (`control-agentgateway-trace`, an auxiliary `control-*`
   service on the slot's network, overlay rule b): follows
   `POST /debug/trace?follow=Ns` (admin cap 1h per window; the collector
   loops) and appends every event to the slot's decision-log volume as
   one JSONL row `{"received_epoch_ns": …, "raw": <verbatim event>}`.
   The capture clock is the wall-clock anchor (the dtrace events carry
   only relative µs times); a `.ready` sidecar marks each window's
   start.
2. **Shim** (`shim/translate.py`, the plugin-owned reader-side mapping,
   the same pattern as `plugins/actplane/shim/`): one record per
   tools/call decision, grouped by `requestId` exactly like the old
   probe's `normalize.py` — ingress `requestState` body preferred over
   the final-request `bodySnapshot` (the gateway may add its own `_meta`
   upstream; response bodies never used), exactly one allow/deny
   `authorizationResult` required (ambiguous/missing authorization is a
   problem, never a guess), `io.inspection/*` carriers echoed from
   `params._meta` when present (else null + `correlation_transport:
   none`; the JSON-RPC id is a vendor-native id in `ids`, never a join
   key), raw_ref evidence pointing back at the vendor lines, policy
   marked unmapped unless the caller passes the deployed config
   (`--policy-file` stamps its sha256 as `policy_hash`).
3. **Runner integration** (phase 2a, implemented): the binding's recipe
   `collect.yaml` declares the ingested collection per control — the
   runner (`runner/run.py pull_ingested_log`) cats the vendor rows from
   the binding's collector container (the agentgateway image is
   distroless: there is no shell in the gateway container to exec), scopes
   them to the run (the slot volume accumulates rows across runs; the
   scope floor is the readiness probe's issuance time, the exclusions are
   counted, never silent), runs this shim into
   `runs/<id>/gateway/decision-records.jsonl` + `shim-problems.txt`, and
   writes the workload records as `decisions.jsonl` — the C1-C4 coverage
   input in the same decision-record/1-in-decisions.jsonl shape the t7
   kernel control uses. The deployed config is copied as the run's
   `gateway/policy.json` and hashed into the fixture fingerprint's
   `enforcement_config` component (framework/execute.py resolves the
   config per control from the recipe — the design's default
   `gateway/policy.yaml` is the no-recipe fallback, so the v0 AGT path is
   unchanged). A decisions log whose lines are decision-record/1 passes
   through the framework's mapping VERBATIM (shape-driven, never
   plugin-identity-driven), so the records keep this binding's own
   producer/product identity, action_id and policy fields.

## The readiness gate (the framework-side convention)

`ready()` needs a deny-able action, but a T1 config is allow-all by
DESIGN. The convention (decided once, framework-side; the AGT binding
faces the same question and can adopt the same rule in a later pass):

- The reserved tool name is the framework's `READINESS_TOOL`
  (`__readiness_check__`, `framework/contracts.py`) — the same name the
  in-process reference policy always denies.
- A binding deploying an allow-all config carries a DEDICATED deny rule
  for the reserved tool (here: the second `require` rule in
  `config/t1-allow-all.json`), isolated from the measurement — no
  workload trace calls it.
- The runner issues exactly ONE readiness tools/call through the
  topology BEFORE the measurement window opens (`runner/run.py
  gateway_readiness_probe`; the mock fixture via `mock_harness/
  gateway_probe.py`, the pi container via `harnesses/pi/adapter/
  readiness-probe.mjs`), and the run is gated on both halves:
  the gateway must refuse the call (the probe report is retained as
  `gateway/readiness-probe.json`) AND the collected stream must contain
  its deny decision record (else the run fails loudly — a started
  container is not a ready one, and opening the capture window before
  enforcement works silently produces false `bypassed` results).
- The readiness probe carries NO correlation ids (runner plumbing, not
  workload traffic): its record is retained in the native stream, and
  excluded from the C1-C4 coverage input with the exclusion counted and
  printed (C5 skips its null action_id; C6 cannot attribute it — the
  reserved tool matches no spec action — and records a note, never a
  finding).

## Harness-side integration (closed in phase 2a)

agentgateway v1.5.0's streamable-HTTP MCP frontend enforces two
MCP-spec requirements the fixture's harness clients did not meet
(both confirmed live 2026-11-10):

- `Accept: application/json, text/event-stream` is REQUIRED on every
  POST (`mcp/streamablehttp.rs` `handle_post`); a POST without it gets
  406.
- The MCP backend is STATEFUL by default: a non-initialize request
  without an `Mcp-Session-Id` header is rejected ("session header is
  required"). A client must initialize once and carry the session id.
- Responses arrive SSE-framed (`text/event-stream` `data:` frames) or as
  plain JSON — decoded by Content-Type.

Both harness clients now speak the protocol (ported from the old
probe's `transport.mjs`, which drove v1.5.0 live; the shapes are
backward-compatible with the v0 AGT gateway, which ignores the extra
headers and answers plain JSON):

- mock harness: one `GatewaySession` per run
  (`mock_harness/originators.py`), started lazily on the first
  gateway-routed action; `syscalls.http_request_full` exposes the
  response headers (the session id) and returns non-2xx as data (a
  denial is a decision, never a transport error).
- pi harness: the `GATEWAY_CLIENT_MODULE` hook
  (`harnesses/pi/adapter/streamable-mcp-client.mjs`, baked into the pi
  image with the adapter and injected per run by `runner/trigger_pi.py`
  from this binding's recipe) — the client carries the io.inspection
  `_meta` carriers on every tools/call, so its dispatches record
  carrier `mcp_meta` exactly like the adapter's built-in route.

## Validation (phase 1: 2026-11-10; phase 2a end-to-end below)

- `guardscope validate` on both example experiments: pass, on-matrix
  (`off_matrix: false`, no overlay problems).
- Overlay validator (`framework.overlay.validate_overlay`): ok for both
  overlays against the t1 slot declaration.
- `tests/test_agentgateway_shim.py`: 14 tests over verbatim live
  captures (the old probe's retained v1.5.0 capture of 2026-10-08,
  including the live deny) — pass.
- Full suite (phase 1): 773 passed (759 pre-existing + 14 new).
- Local smoke (arm64 Fedora Docker host, degraded no-sensor scope):
  merged t1-mock topology up; the pinned image's runtime banner confirms
  v1.5.0/fe67324; tool calls route through to the fixture's endpoint
  with bare names; the collector captured the `authorizationResult`
  events; the shim translated them into schema-valid decision-record/1
  with the `a011` carrier echoed live (`action_id=a011`,
  `correlation_transport=mcp_meta`) and `policy_hash` equal to the
  deployed config's sha256. Manifest correlation claims stay false
  until the formal fidelity check (claims are never trusted).

## End-to-end degraded runs (phase 2a, 2026-11-10)

`guardscope run … --no-sensor` through the full pipeline (readiness gate
-> replay -> ingested collection -> shim -> C1-C4 -> C5 -> outcomes ->
execution manifest), both harnesses, local arm64 Docker host:

- `examples/t1-mock-agentgateway.yaml`: status pass, coverage pass,
  C1-C4 pass, C5 pass, coverage_consistent true, no findings; 4
  decision records (a011-a014, `checked-allowed`) + 11 bypassed —
  exactly the T1-mock reference counts under the AGT binding. The
  readiness gate fired live: the gateway refused the reserved tool
  (HTTP 403) and the collected stream carried its deny record
  (`gateway/decision-records.jsonl`; excluded from the coverage input,
  `gateway/readiness-probe.json` retained). The vendor rows of the
  earlier phase-1 smoke on the same volume were scoped out (15 rows,
  counted) — the run-scoping is exercised live.
- `examples/t1-pi-agentgateway.yaml` (pi image rebuilt with the
  streamable client + probe; build 29 s): status pass, coverage pass,
  C5 pass, no findings, same 4 checked + 11 bypassed. The pi client's
  `_meta` carriers echo through agentgateway live (a011-a014 action ids
  on the decision records; found live on the first attempt: a probe
  that minted a carrier id surfaced as a C5 fabrication finding and was
  fixed to carry none — the convention's own check working).
- v0 regression (live): `examples/t1-mock.yaml` (agt-gateway) through
  the SAME new session client — pass, coverage pass, C5 pass, no
  findings: the streamable-HTTP shapes are backward-compatible with
  the v0 gateway (it forwards `initialize` untouched, ignores the
  session header, answers plain JSON).
- Full suite (phase 2a): 789 passed; `guardscope validate` passes on
  all 16 example experiments.

## Operational notes (running the examples)

- Bring the topology up out of band BEFORE `guardscope run`: the runner
  does not start the stack. `docker compose -f compose/t1-mock.yaml -f
  plugins/agentgateway/overlay/t1-mock.yaml up -d` (add `--profile sensor
  up -d tracee` for the sensor-backed scope; `compose/t1.yaml` +
  `overlay/t1.yaml` for the pi fixture).
- Keep the experiments workdir (and `--out-root`) under the checkout
  tree: the mock driver fails with "did not write its run manifest"
  when its staging path is outside the repo-visible tree. Same rule as
  the v0 examples (GUARDSCOPE_WORKDIR + GUARDSCOPE_STAGING_DIR per the
  README quickstart).
- The vendor-log volume accumulates rows across runs on a long-lived
  topology; the runner scopes rows to the current run by the readiness
  probe's issuance time and prints the excluded count. Tear the stack
  down (`down -v`) between campaigns to reset the volume.
