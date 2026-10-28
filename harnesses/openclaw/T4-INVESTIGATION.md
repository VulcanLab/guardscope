# OpenClaw T4–T6 capability investigation

**Status: C1, C3, and the MCP tool-id naming are CONFIRMED from the official
docs (docs2.openclaw.ai + the docs shipped in the pinned image,
`ghcr.io/openclaw/openclaw@sha256:6cb72e1…`, extracted locally — `/app/docs`).
C2 is strongly indicated; ONE live check remains (does `/tools/invoke` fire
`before_tool_call`?), with the probe procedure below.**

Image docs used: `docs/gateway/tools-invoke-http-api.md`,
`docs/gateway/config-tools.md`, `docs/tools/mcp.md`, `docs/plugins/hooks.md`,
`docs/plugins/hooks/tool-policy` (online), `docs/gateway/audit.md`.

## C1 — pre-dispatch interception: CONFIRMED (docs)

Typed plugin hook `before_tool_call` (Modify/gate, 15 s default timeout,
fail-closed on error/timeout):

- Event: `event.toolName`, `event.params` (the arguments), optional
  `event.toolCallId`, `event.derivedPaths` (host-derived target-path hints),
  ctx: `ctx.agentId`, `ctx.sessionKey`, `ctx.runId`, ...
- Return contract: `{ params? (rewrite), block?: boolean, blockReason?: string,
  requireApproval?: {...} }`; `block: true` is terminal.
- Host-level tier: `api.registerTrustedToolPolicy(...)` runs BEFORE ordinary
  `before_tool_call` hooks (workspace-policy placement; matcher on canonical
  tool ids).
- `after_tool_call` (Observe): "Observe tool results, errors, and duration" —
  the completion boundary for the per-call latency evidence.

Mapping to the designs:
- **T4**: `before_tool_call` allow-all + decision record (AuditEntry shape) =
  the harness permission chain. The fail-closed default matches the paper's
  T6 semantics.
- **T6**: the in-process policy engine (`t6Evaluate`, ported verbatim from
  `harnesses/pi/adapter/replay.ts`) evaluated in the hook; deny →
  `{ block: true, blockReason }`; the decision record carries the matched rule
  and the inspected arguments.
- The deny probe (a014) needs `block` — confirmed available.
- Argument visibility for the inspectable-features claim: `event.params` —
  confirmed.

## C2 — deterministic no-LLM dispatch: STRONGLY INDICATED, one live check

From `docs/gateway/tools-invoke-http-api.md` (in the pinned image):

- `POST /tools/invoke` invokes a single tool directly — "always enabled and
  uses Gateway auth plus tool policy".
- **"Tool availability is filtered through the same policy chain used by
  Gateway agents"** — the invoke path reuses the agent tool pipeline.
- **`idempotencyKey` (optional) is "used to derive a stable tool-call id for
  the invocation"** — the driver can pin the canonical action id into the call,
  and (to verify live) the hook's `event.toolCallId` then carries it: clean
  decision-record attribution without argument matching.
- Request body: `{ tool, args, sessionKey, agentId, idempotencyKey, dryRun }`.
- **Hard deny list** on this endpoint (exec, spawn, shell, fs_write, ...) —
  our canonical MCP tool calls (toy-mcp-fs/toy-mcp-http) are not on it; note
  the endpoint is unusable for shell-tool-inspected spawns (the `spawn`/`shell`
  tools are denied there).
- Policy-denied tools return **404**; blocked-by-hook calls return ... (live
  check: the exact blocked response shape).
- `docs/gateway/audit.md`: "A `before_tool_call` hook records its own allow or
  block as an enforced plugin gate; fail-closed hook errors are denials."

The single remaining check: does the invoke path fire the plugin
`before_tool_call`/`after_tool_call` hooks (the online hooks doc says
"explicitly invoked tool hooks remain active"; the pinned-image docs do not
carry that exact line — verify live per the probe procedure below).

## C3 — MCP client config: CONFIRMED (docs)

"Connect MCP servers to OpenClaw ... Server definitions live under `mcp`."
Plus the naming fact (from `docs/gateway/config-tools.md`):

- Configured MCP servers are exposed as plugin-owned tools under the
  `bundle-mcp` plugin id, through the same policy chain.
- **MCP tool ids are `<provider-safe-server-prefix>__<tool>`** — e.g.
  `toy-mcp-fs__write_file`; non-`[A-Za-z0-9_-]` characters in the server key
  become `-`, non-letter-initial keys get an `mcp-` prefix. The T6 policy
  engine strips the `<server>__` prefix (same as pi's `mcp__<server>__`).
- Sandbox gates: `tools.sandbox.tools` must include `bundle-mcp` when sandbox
  mode is enabled (not relevant to the v1 permissions-only configuration).

## Open design points (decide after the runtime check)

1. **Phase orchestration**: process-level actions (spawn/file/credential/direct
   net) execute inside the plugin's own `replay_trace` tool invocation (as in
   T0–T3 — harness children, kernel-attributed to the container). The wrapper
   call crosses the hook; the T4/T6 hook must therefore skip its own
   `replay_trace` tool (allow + do not count it as a canonical decision).
   Canonical tool calls are then issued by the DRIVER as one `/tools/invoke`
   per action; the hook records each decision. A final `/tools/invoke`
   (`finalize`) assembles the replay result from the recorded per-call results.
2. **Decision-record scoping**: `ctx.runId`/`ctx.toolCallId` (optional) — if the
   caller-supplied call id survives to the hook, use it as the canonical action
   id; else fall back to argument matching (same attribution as coverage.py).
3. **What the deny surfaces as** in the replay result: a blocked call's
   `/tools/invoke` response shape decides whether the driver records status
   `denied` (expected) or `error`.

## LIVE PROBE RESULT (2026-10-07): ALL CHECKS PASS — C2 CONFIRMED

Run against the t4-openclaw gateway (T6_MODE=1, the t6-policy variant):

- `before_tool_call` FIRES for `/tools/invoke` calls (the decisive C2 check).
- `idempotencyKey` propagates into the hook's `event.toolCallId` as
  `http-direct-operator-<idempotencyKey>` — exact per-instance attribution
  (`http-direct-operator-a001` / `-a014` in the decision record).
- Allow canary (`write_file`, path in `/workspace/out`): decision allowed
  (rule-0), executed through the harness dispatch via the plugin tool's MCP
  session — `{"ok":true,"result":{"text":"wrote 5 bytes to ..."}}`.
- Deny canary (path outside the workspace prefix): decision denied, no
  execution, caller receives
  `{"ok":false,"error":{"type":"tool_call_blocked","message":"no rule allows
  write_file with the given arguments"}}` — the driver detects denials by the
  `tool_call_blocked` error type.
- Two implementation facts learned en route:
  1. plugin tools MUST be declared in `openclaw.plugin.json`
     `contracts.tools` — undeclared tools are silently dropped at
     registration;
  2. the `/tools/invoke` endpoint resolves only registry tools — config-
     registered MCP tools are materialized per agent RUN
     (`materializeBundleMcpToolsForRun`) and are NOT available turn-less, so
     the canonical tool calls are registered AS plugin tools (they cross the
     same before/after_tool_call pipeline) whose execute() performs the MCP
     call. This is the openclaw realization of T4's "tool_call permission
     chain evaluates every tool call issued through its pipeline"; the
     transport substitution (plugin MCP session vs harness MCP client) is
     disclosed alongside the paper's other transport substitutions.

## Where each check runs

`investigate.sh` (static extraction from the pinned image) is superseded: the
image docs were extracted locally (same digest) and the findings are above.
What remains is ONE LIVE PROBE against a running gateway:

1. Bring up `compose/t4.yaml` with the openclaw T4 adapter (`adapter/t4.js`)
   and an openclaw config registering the two toy MCP servers under
   `mcp.servers` (`toy-mcp-fs`, `toy-mcp-http`).
2. From the harness container (or the driver), with the gateway token:

   ```bash
   # canary: does the hook fire for an explicitly invoked tool?
   curl -s -X POST http://localhost:28789/tools/invoke \
     -H 'Authorization: Bearer <gateway-token>' \
     -d '{"tool":"toy-mcp-fs__write_file","args":{"path":"/workspace/out/probe.txt","data":"probe"},"idempotencyKey":"a001"}'
   # then inspect /workspace/replay/decisions.jsonl for an entry with
   # tool_name=toy-mcp-fs__write_file and tool_call_id derived from a001.

   # denial: T6-policy deny (or a temporary canary block) — record the exact
   # response shape the caller sees (status code + body).
   ```

3. Record: hook fired? `toolCallId` derivation from `idempotencyKey`?
   `after_tool_call` for the denied call? Blocked response shape?

If all hold: port the driver (`runner/trigger_openclaw.py` — one
`/tools/invoke` per canonical tool call with `idempotencyKey=<action id>`),
then warmup + pairs for openclaw T4–T6.