// OpenClaw T4/T6 adapter (harness-native / in-process enforcement).
//
// Skeleton — see T4-INVESTIGATION.md for the docs findings and the pending
// runtime verifications. Design mirrors harnesses/pi/adapter/replay.ts:
//
//   T4_MODE=1  the `before_tool_call` hook is the enforcement point
//              (allow-all permission chain); it records every canonical
//              tool call as an AuditEntry-shaped decision.
//   T6_MODE=1  the same position, but the in-process policy engine decides
//              (declarative rules over tool names + argument values;
//              fail-closed; deny -> block). The decision record carries the
//              matched rule and the inspected arguments.
//
// Replay flow (two phases; the driver issues one POST /tools/invoke per call):
//   phase "process"   the plugin executes the process-level actions directly
//                     (spawn/file/credential/direct net) — agent-side code
//                     OUTSIDE the tool pipeline: the bypass T4 measures.
//                     [RUNTIME CHECK: the wrapper tool call crosses the hook;
//                     the hook must skip its own replay tool — see below.]
//   canonical calls   the driver invokes each MCP tool of the config-
//                     registered servers (toy-mcp-fs / toy-mcp-http) via
//                     /tools/invoke; every call crosses the hook.
//   phase "finalize"  the plugin assembles replay-result.json from the
//                     recorded per-call results (incl. denials).
//
// RUNTIME VERIFICATION POINTS (marked VERIFY below):
//   V1  RESOLVED: MCP tool ids are <server-prefix>__<tool> (config-tools.md)
//   V2  the hook's event shape actually delivered for /tools/invoke calls
//   V3  what a blocked call returns to the /tools/invoke caller (denied vs
//       error) and whether after_tool_call still fires for it

import { Type } from "typebox";
import { spawn, execFile } from "node:child_process";
import { promises as fs, createWriteStream, appendFileSync, readFileSync } from "node:fs";
import { dirname } from "node:path";
import net from "node:net";
import dgram from "node:dgram";

const REPLAY_LOG_DIR = process.env.REPLAY_LOG_DIR || "/workspace/replay";
const T4_MODE = process.env.T4_MODE === "1";
const T6_MODE = process.env.T6_MODE === "1";
const T6_POLICY_PATH = process.env.T6_POLICY_PATH || "/opt/inspection/t6-policy.json";
const ACTION_TIMEOUT_MS = 20000;
// The plugin's own wrapper tool (process phase + finalize); the hook must not
// record it as a canonical decision.
const REPLAY_TOOL = "replay_trace_t4";

const ns = () => Number(process.hrtime.bigint());
const epochNs = () => Number(BigInt(Date.now()) * 1000000n);

// --- correlation carriers + dispatch records (M2a; DESIGN.md 3, 4, 5) -------
//
// The T4/T6 tool calls are dispatched through the harness's own
// /tools/invoke surface, which has no _meta carrier; the id rides the
// toolCallId, so the dispatch records say carrier_used "none" (C5 skips
// carrier-less dispatches). Run identity: the driver stages run-id on the
// mounted replay volume (the long-lived gateway process cannot receive
// per-run env); process env INSPECTION_RUN_ID is the fallback.

// Re-read per dispatch (no process-lifetime cache): the openclaw process is
// long-lived across runs while the driver re-stages run-id per run, so a
// cached value would stamp later runs with the first run's id.
function dispatchRunId() {
  try {
    const staged = readFileSync(`${REPLAY_LOG_DIR}/run-id`, "utf8").trim();
    if (staged) return staged;
  } catch { /* no staged run id: fall through to the env default */ }
  return process.env.INSPECTION_RUN_ID || "unattributed";
}

// One dispatch-record/1 line per attempt (DESIGN.md 4): bare schema:1 stamp,
// run_id, action_id, attempt 0, dispatched_at, carrier_used, result | error.
// The /tools/invoke endpoint derives the hook's toolCallId as
// "<prefix>-<idempotencyKey>" and the driver keys the canonical calls by the
// action id, so the bare action id is the toolCallId's final segment (same
// normalization as finalize). Emission must never fail the replay.
function writeDispatchRecord(actionId, carrierUsed, result, error) {
  try {
    appendFileSync(`${REPLAY_LOG_DIR}/dispatch-records.jsonl`, JSON.stringify({
      schema: 1,
      run_id: dispatchRunId(),
      action_id: actionId,
      attempt: 0,
      dispatched_at: new Date().toISOString(),
      carrier_used: carrierUsed,
      ...(error !== null
        ? { error: { message: error } }
        : { result: result ?? {} }),
    }) + "\n");
  } catch { /* never fail a replay on record emission */ }
}

// --- T6 policy engine (ported verbatim from harnesses/pi/adapter/replay.ts) --

let t6Policy = null;
function t6Evaluate(toolName, input) {
  // V1 RESOLVED (docs/gateway/config-tools.md): config-registered MCP tools
  // are named <provider-safe-server-prefix>__<tool> (e.g. toy-mcp-fs__write_file).
  const bare = toolName.split("__").slice(-1)[0];
  if (!t6Policy) t6Policy = JSON.parse(readFileSync(T6_POLICY_PATH, "utf8"));
  for (let i = 0; i < t6Policy.rules.length; i++) {
    const rule = t6Policy.rules[i];
    if (rule.tools && !rule.tools.includes(bare)) continue;
    let ok = true;
    for (const [arg, prefix] of Object.entries(rule.constraints ?? {})) {
      const v = input?.[arg];
      if (typeof v !== "string" || !v.startsWith(prefix)) { ok = false; break; }
    }
    if (ok) return { allowed: true, reason: rule.reason ?? `rule ${i}`, matched_rule: `rule-${i}` };
  }
  return t6Policy.default === "allow"
    ? { allowed: true, reason: "default allow", matched_rule: null }
    : { allowed: false, reason: `no rule allows ${bare} with the given arguments`, matched_rule: null };
}

// --- MCP stdio session (same as the T0-T3 adapter) --------------------------
class McpSession {
  #cmd; #proc; #buf = ""; #pending = new Map(); #nextId = 0; #diagnostics = [];
  constructor(cmd) { this.#cmd = cmd; }
  async start() {
    this.#proc = spawn(this.#cmd[0], this.#cmd.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
    this.#proc.on("error", (e) => this.#diagnostics.push(`spawn error: ${e}`));
    this.#proc.stderr.setEncoding("utf8");
    this.#proc.stderr.on("data", (d) => this.#diagnostics.push(`stderr: ${String(d).trim().slice(0, 300)}`));
    this.#proc.stdout.setEncoding("utf8");
    this.#proc.stdout.on("data", (chunk) => {
      this.#buf += chunk;
      let i;
      while ((i = this.#buf.indexOf("\n")) >= 0) {
        const line = this.#buf.slice(0, i).trim(); this.#buf = this.#buf.slice(i + 1);
        if (!line) continue;
        let msg; try { msg = JSON.parse(line); } catch { continue; }
        const resolve = this.#pending.get(msg.id);
        if (resolve) { this.#pending.delete(msg.id); resolve(msg); }
      }
    });
    const init = await this.#request("initialize", {
      protocolVersion: "2025-06-18", capabilities: {},
      clientInfo: { name: "inspection-replay", version: "0.2.0" },
    });
    if (!init.result) throw new Error(`MCP initialize failed: ${JSON.stringify(init)}`);
    this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    return init.result;
  }
  #request(method, params) {
    const id = ++this.#nextId;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => { this.#pending.delete(id); reject(new Error(`MCP ${method} timeout`)); }, 20000);
      this.#pending.set(id, (msg) => { clearTimeout(t); resolve(msg); });
      this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }
  call(tool, args) { return this.#request("tools/call", { name: tool, arguments: args }); }
}

// --- enforcement-point record + per-call results -----------------------------

function writeDecision(entry) {
  try {
    appendFileSync(`${REPLAY_LOG_DIR}/decisions.jsonl`, JSON.stringify(entry) + "\n");
  } catch { /* logging must never break enforcement */ }
}

// per-call results, keyed by toolCallId (canonical action id)
const callStart = new Map();
const results = new Map();
const processResults = [];
let replayWindowStart = null;   // phase-1 mark; finalize closes the window

// Registered from index.js (single plugin entry; the manifest stays the
// validated M4 one). Loaded only when T4_MODE/T6_MODE is set.
export function registerT4Enforcement(api) {

    // --- the enforcement point ------------------------------------------
    api.on("before_tool_call", (event, ctx) => {
      if (event.toolName === REPLAY_TOOL) return {};   // skip the wrapper
      const start = { started_ns: ns(), started_epoch_ns: epochNs() };
      callStart.set(event.toolCallId ?? `anon-${start.started_ns}`, start);
      let allowed = true, reason, matchedRule = null;
      if (T6_MODE) {
        const verdict = t6Evaluate(event.toolName, event.params ?? {});
        allowed = verdict.allowed; reason = verdict.reason; matchedRule = verdict.matched_rule;
      } else {
        reason = "harness permission mode (allow-all)";
      }
      writeDecision({
        timestamp: Date.now() / 1000,
        agent_id: T6_MODE ? "t6-in-process" : "t4-harness",
        tool_name: event.toolName,
        tool_call_id: event.toolCallId ?? null,     // V2: confirm the field survives /tools/invoke
        allowed,
        reason,
        matched_rule: matchedRule,
        parameters: event.params ?? {},
      });
      // dispatch-record/1 per attempt (M2a; DESIGN.md 3 inject, 4): the call
      // crossed the enforcement point; no protocol carrier on this surface.
      if (event.toolCallId) {
        writeDispatchRecord(String(event.toolCallId).split("-").pop(), "none",
          { status: allowed ? "ok" : "denied" }, null);
      }
      if (!allowed) {
        // record the terminal result here: a blocked call may not produce an
        // after_tool_call event (V3 — mirrors the pi behavior)
        results.set(event.toolCallId ?? `anon-${start.started_ns}`, {
          status: "denied", error: null,
          started_ns: start.started_ns, ended_ns: ns(),
          started_epoch_ns: start.started_epoch_ns,
        });
        return { block: true, blockReason: reason };
      }
      return {};
    });
    api.on("after_tool_call", (event) => {
      // V3: confirm blocked calls do (not) reach here; dedupe against the
      // deny-recorded result if they do.
      const id = event.toolCallId ?? "";
      if (results.has(id)) return {};
      const start = callStart.get(id);
      results.set(id, {
        status: event.isError ? "error" : "ok",
        error: event.isError ? "tool execution failed" : null,
        started_ns: start?.started_ns, ended_ns: ns(),
        started_epoch_ns: start?.started_epoch_ns,
      });
      return {};
    });

    // --- canonical tool calls as plugin tools ----------------------------
    // The /tools/invoke endpoint resolves only registry tools (MCP tools are
    // materialized per agent RUN — materializeBundleMcpToolsForRun — and the
    // invoke is turn-less), so the canonical tool calls are registered as
    // plugin tools: they cross the same before_tool_call/after_tool_call
    // pipeline, and execute() performs the MCP call (the fs/http toy servers).
    // This is the openclaw realization of "the harness permission chain
    // evaluates every tool call issued through its pipeline" (pi realizes it
    // via its MCP client; see the transport-disclosure note in the paper).
    let fsSession = null, httpSession = null;
    const ensureSession = async (kind) => {
      const key = kind === "http" ? "http" : "fs";
      const store = kind === "http" ? "httpSession" : "fsSession";
      if ((kind === "http" ? httpSession : fsSession)) return kind === "http" ? httpSession : fsSession;
      const cmd = kind === "http"
        ? (JSON.parse(process.env.MCP_HTTP_SERVER_CMD || '["python3","-u","/opt/inspection/mcp-http-stdio/server.py"]'))
        : JSON.parse(process.env.MCP_SERVER_CMD || '["python3","-u","/opt/inspection/mcp-fs/server.py"]');
      const session = new McpSession(cmd);
      await session.start();
      if (kind === "http") httpSession = session; else fsSession = session;
      return session;
    };
    const CANONICAL_TOOLS = [
      { name: "write_file", kind: "fs" }, { name: "read_file", kind: "fs" },
      { name: "list_directory", kind: "fs" }, { name: "post_hook", kind: "http" },
      { name: "get_health", kind: "http" }, { name: "put_state", kind: "http" },
    ];
    for (const ct of CANONICAL_TOOLS) {
      api.registerTool({
        name: ct.name,
        description: `canonical inspection trace tool (${ct.kind})`,
        parameters: Type.Object({}, { additionalProperties: true }),
        async execute(toolCallId, params) {
          // the hook records the decision; execute performs the MCP call
          const session = await ensureSession(ct.kind);
          const resp = await session.call(ct.name, params ?? {});
          if (resp.error) throw new Error(`mcp ${ct.name}: ${JSON.stringify(resp.error)}`);
          const rec = results.get(toolCallId) ?? {};
          rec.status = "ok"; rec.detail = { server: ct.kind, tool: ct.name };
          results.set(toolCallId, rec);
          return { text: resp.result?.content?.[0]?.text ?? "" };
        },
      });
    }

    // --- process phase + finalize (the plugin's own wrapper tool) --------
    api.registerTool({
      name: REPLAY_TOOL,
      description: "inspection replay: process-level phase + result assembly (T4/T6)",
      parameters: Type.Object({
        phase: Type.Union([Type.Literal("process"), Type.Literal("finalize")]),
        trace: Type.Optional(Type.String()),
      }),
      async execute(_tool, args) {
        const trace = typeof args.trace === "string"
          ? JSON.parse(await fs.readFile(args.trace, "utf8"))
          : args.trace;
        if (args.phase === "process") {
          await fs.mkdir(REPLAY_LOG_DIR, { recursive: true });
          const log = createWriteStream(`${REPLAY_LOG_DIR}/replay-log.jsonl`, { flags: "w" });
          const line = (o) => new Promise((res) => log.write(JSON.stringify(o) + "\n", res));
          const startedNs = ns(), startedEpoch = epochNs();
          replayWindowStart = startedEpoch;   // finalize closes the window
          await line({ event: "mark-start", ts_ns: startedNs, epoch_ns: startedEpoch,
                       spec_sha256: trace.meta?.spec_sha256, harness: "openclaw", design: T6_MODE ? "t6" : "t4" });
          for (const action of trace.actions) {
            if (action.class === "stdio_tool_call" || action.class === "http_tool_call") continue;
            const t0 = ns();
            let status = "ok", detail = null, error = null;
            try { detail = await execProcessAction(action); }
            catch (exc) { status = "error"; error = String(exc?.message ?? exc); }
            const rec = { id: action.id, class: action.class, op: action.op,
                          started_ns: t0, ended_ns: ns(), started_epoch_ns: epochNs(),
                          status, detail, error };
            processResults.push(rec);
            await line(rec);
          }
          await new Promise((res) => log.end(res));
          return { phase: "process", executed: processResults.length };
        }
        // finalize: assemble the replay result from phase-1 + the recorded
        // tool-call results (the driver posts this after the canonical calls).
        // The invoke endpoint derives the hook's toolCallId as
        // "<prefix>-<idempotencyKey>"; normalize by the idempotencyKey suffix.
        const norm = new Map();
        for (const [id, rec] of results) norm.set(String(id).split("-").pop(), rec);
        for (const rec of processResults) norm.set(rec.id, rec);
        for (const [aid, obs] of Object.entries(args.observations ?? {})) {
          if (!norm.has(aid)) {
            norm.set(aid, { id: aid, status: obs.status, error: obs.error ?? null });
          }
        }
        const ordered = trace.actions.map((a) => Object.assign(
          { id: a.id, class: a.class, op: a.op },
          norm.get(a.id) ?? { status: "error", error: "no result recorded (tool call never executed?)" },
          { id: a.id }));
        const failed = ordered.filter((r) => r.status === "error");
        const denied = ordered.filter((r) => r.status === "denied");
        const result = {
          ok: failed.length === 0, executed: ordered.length, failed: failed.length,
          denied: denied.length,
          window_ns: { start: 0, end: 0 },
          window_epoch_ns: { start: replayWindowStart ?? 0, end: epochNs() },
          replay_log: `${REPLAY_LOG_DIR}/replay-log.jsonl`,
          results: ordered,
        };
        await fs.writeFile(`${REPLAY_LOG_DIR}/replay-result.json`,
                           JSON.stringify(result, null, 1) + "\n");
        return { phase: "finalize", ok: result.ok, denied: denied.length };
      },
    });
}

// process-level executors (identical to the T0-T3 adapter; agent-side code
// outside the tool pipeline)
async function execProcessAction(action) {
  switch (action.kind) {
    case "tcp_connect":
      return await withTimeout(new Promise((resolve, reject) => {
        const sock = net.connect({ host: action.host, port: action.port }, () => {
          sock.end(action.payload ?? "");
        });
        sock.on("data", () => { sock.destroy(); });
        sock.on("error", reject);
        sock.on("close", () => resolve({ host: action.host, port: action.port }));
      }), ACTION_TIMEOUT_MS, "tcp_connect");
    case "udp_send":
      return await new Promise((resolve, reject) => {
        const sock = dgram.createSocket("udp4");
        sock.send(Buffer.from(action.payload ?? ""), action.port, action.host, (err) => {
          if (err) { sock.close(); reject(err); return; }
          resolve({ host: action.host, port: action.port });
          setTimeout(() => { try { sock.close(); } catch { /* already closed */ } }, 50);
        });
      });
    case "spawn":
      return await withTimeout(new Promise((resolve, reject) => {
        execFile(action.cmd[0], action.cmd.slice(1), { timeout: ACTION_TIMEOUT_MS }, (err) => {
          if (err) reject(err); else resolve({ cmd: action.cmd });
        });
      }), ACTION_TIMEOUT_MS + 1000, "spawn");
    case "file_write": {
      await fs.mkdir(dirname(action.path), { recursive: true });
      if (action.append) await fs.appendFile(action.path, action.data);
      else await fs.writeFile(action.path, action.data);
      return { path: action.path, bytes: Buffer.byteLength(action.data) };
    }
    case "credential_read": {
      const data = await fs.readFile(action.path);
      return { path: action.path, bytes: data.length };
    }
    default:
      throw new Error(`unknown kind ${action.kind}`);
  }
}

const withTimeout = (p, ms, what) =>
  Promise.race([p, new Promise((_, rej) =>
    setTimeout(() => rej(new Error(`${what} timeout`)), ms))]);