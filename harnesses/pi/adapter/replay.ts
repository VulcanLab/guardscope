// Pi replay adapter (C3, M5): injects the compiled canonical trace inside the
// pi agent process — no LLM anywhere.
//
// Injection point (documented extension surface): the driver runs
//   pi --mode rpc --no-session -e /opt/inspection/adapter/replay.ts
// and sends the RPC command  {"type":"prompt","message":"/inspection-replay <path>",
// "id":"replay-1"}. Extension commands execute immediately via RPC without an
// agent run (see pi docs/rpc.md), so the whole trace executes in the pi
// process (harness context); children (MCP server, /bin/sh, /bin/echo) are
// harness children and Tracee attributes them to container t0-pi.
//
// The compiled trace path is passed as the command argument. The driver
// mounts runs/pi at /workspace/replay and reads replay-result.json after the
// RPC response arrives.
//
// Execution plan per class (compiled by trace/compile/pi/compile.py — same
// shape as the OpenClaw one):
//   mcp              -> spawn the toy MCP stdio server as a pi child; one
//                       session per replay, NDJSON JSON-RPC roundtrip
//   http             -> fetch() from the pi process; with GATEWAY_URL set
//                       (T1): MCP tools/call over HTTP via the gateway
//   tcp_connect      -> node:net socket to the net-peer target
//   udp_send         -> node:dgram datagram to the net-peer target
//   spawn            -> node:child_process execFile (the traced process tree)
//   file_write       -> node:fs write/append (direct, no tool transport)
//   credential_read  -> node:fs read of the seeded secret file
//
// Env knobs (pi-process env, set by the harness container):
//   REPLAY_LOG_DIR  replay JSONL log + result (default /workspace/replay)
//   MCP_SERVER_CMD  JSON argv array; the MCP stdio server command
//                   (default ["python3","-u","/opt/inspection/mcp-fs/server.py"])

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai/compat";
import { spawn, execFile } from "node:child_process";
import { promises as fs, createWriteStream, readFileSync, appendFileSync } from "node:fs";
import { dirname } from "node:path";
import net from "node:net";
import dgram from "node:dgram";

const REPLAY_LOG_DIR = process.env.REPLAY_LOG_DIR || "/workspace/replay";
const MCP_CMD = JSON.parse(process.env.MCP_SERVER_CMD ||
  '["python3","-u","/opt/inspection/mcp-fs/server.py"]');
const MCP_TIMEOUT_MS = 20000;
const ACTION_TIMEOUT_MS = 20000;
// Opt-in Stage 9b observation only; unset preserves every existing replay shape.
const CSB_EVIDENCE_DIR = process.env.CSB_EVIDENCE_DIR || "";
async function csbSnapshot(trace: any) {
  if (!CSB_EVIDENCE_DIR) return;
  const snapshot: any = { observed_epoch_ns: epochNs(), process_pid: process.pid,
    argv: process.argv, sandbox: process.env.IS_SANDBOX || null,
    agent: process.env.IS_SANDBOX_AGENT || null };
  for (const name of ["status", "mountinfo", "cgroup", "net/route"]) {
    try { snapshot[name] = await fs.readFile(`/proc/self/${name}`, "utf8"); }
    catch (e) { snapshot[name] = { error: String(e) }; }
  }
  snapshot.namespaces = {};
  for (const name of ["net", "pid", "mnt", "user"]) {
    try { snapshot.namespaces[name] = await fs.readlink(`/proc/self/ns/${name}`); }
    catch (e) { snapshot.namespaces[name] = { error: String(e) }; }
  }
  const procIdentity = async (pid: string, role: string) => {
    const base = `/proc/${pid}`;
    const stat = await fs.readFile(`${base}/stat`, "utf8");
    const fields = stat.slice(stat.lastIndexOf(")") + 2).trim().split(/\s+/);
    return { proc_pid: Number(stat.slice(0, stat.indexOf(" "))), proc_ppid: Number(fields[1]),
      start_ticks: Number(fields[19]), role,
      argv: (await fs.readFile(`${base}/cmdline`, "utf8")).replace(/\0$/, "").split("\0") };
  };
  // This procfs is mounted from the outer PID namespace; process.pid alone
  // is the innermost ID. Record both and corroborate against host /proc.
  const self = await procIdentity("self", "pi");
  snapshot.start_ticks = self.start_ticks;
  snapshot.startup_processes = [self];
  let parent = self.proc_ppid;
  const seen = new Set([self.proc_pid]);
  while (parent > 0 && !seen.has(parent) && seen.size < 32) {
    seen.add(parent);
    try {
      const entry = await procIdentity(String(parent), "setup-only");
      snapshot.startup_processes.push(entry);
      parent = entry.proc_ppid;
    } catch (e) { snapshot.ancestry_error = String(e); break; }
  }
  for (const pid of await fs.readdir("/proc")) {
    if (!/^\d+$/.test(pid)) continue;
    try {
      const entry = await procIdentity(pid, "relay-only");
      if (entry.argv[0]?.split("/").pop() === "pasta" && seen.has(Number(entry.argv.at(-1)))) {
        snapshot.startup_processes.push(entry);
      }
    } catch { /* exited or unreadable; never invent helper identity */ }
  }
  snapshot.public_routes = {};
  for (const action of trace.actions || []) {
    if (action.id !== "csb-public-001") continue;
    snapshot.public_routes[action.host] = await new Promise((resolve) => execFile("ip", ["-j", "-4", "route", "get", action.host],
      { timeout: 5000 }, (err, stdout, stderr) => resolve({ stdout, stderr, error: err?.message || null })));
  }
  // /proc/net/route omits blackhole routes. Capture the full table BEFORE
  // mark-start; retain failures, do not invent the product's routing table.
  snapshot.routes = await new Promise((resolve) => execFile("ip", ["-4", "route", "show", "table", "all"],
    { timeout: 5000 }, (err, stdout, stderr) => resolve({ stdout, stderr, error: err?.message || null })));
  await fs.writeFile(`${CSB_EVIDENCE_DIR}/jail-snapshot.json`, JSON.stringify(snapshot, null, 1) + "\n");
  // Host transport must acknowledge translated Pi/pasta/bwrap identities
  // BEFORE replay mark-start. This opt-in handshake changes no legacy run.
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    try {
      const tree = JSON.parse(await fs.readFile(`${CSB_EVIDENCE_DIR}/host-tree.json`, "utf8"));
      if (tree.status === "pass" && tree.root?.start_ticks === self.start_ticks) return;
    } catch { /* wait for a complete host writer */ }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("CSB host /proc startup attribution handshake missing");
}
// T1 gateway routing (compose/t1.yaml sets GATEWAY_URL for the deployment-
// design T1 topology; unset = T0 bare-harness mode with raw fetch). When set,
// http_tool_call actions execute as MCP tools/call over HTTP against the
// gateway — the T1 enforcement point — instead of raw fetch to the target.
const GATEWAY_URL = process.env.GATEWAY_URL || "";
// method+path -> gateway tool name (targets/mcp-http TOOL_ROUTES, 1:1 with
// canonical http_tool_call actions a011-a013).
const GATEWAY_TOOL_ROUTES: Record<string, string> = {
  "POST /hook": "post_hook",
  "GET /health": "get_health",
  "PUT /state": "put_state",
};
let gatewayRpcId = 0;

// T3 (compose/t3.yaml sets GATEWAY_FS=1): the stdio tool calls are proxied
// through the gateway as MCP tools/call over HTTP (the gateway is the sole
// enforcement point). No MCP server child is spawned; the tool name is the
// fs tool name itself (write_file/read_file/list_directory).
const GATEWAY_FS = process.env.GATEWAY_FS === "1";

// T4 (compose/t4.yaml sets T4_MODE=1): harness-native enforcement. The
// tool-call actions (stdio + http) are issued as MCP tools of the harness
// (mcp__<server>__<tool>) through a REAL agent run driven by a scripted
// provider, so they cross pi's tool pipeline — the `tool_call` extension
// hook (the harness permission layer, the T4 enforcement point) evaluates
// every call and writes the enforcement-point record (decisions.jsonl). The
// process-level actions (direct network, spawn, file, credential) execute in
// the extension-command phase directly — agent code OUTSIDE the tool
// pipeline, the process-level bypass T4 measures. No gateway, no egress.
const T4_MODE = process.env.T4_MODE === "1";

// T6 (compose/t6.yaml sets T6_MODE=1): IN-PROCESS enforcement — the same
// placement (the hook inside the harness process) but a policy ENGINE
// decides: declarative rules over tool names and argument values
// (Progent-style symbolic semantics). Denials block the call (fail-closed);
// the decisions record
// carries the matched rule and the argument features it inspected.
const T6_MODE = process.env.T6_MODE === "1";
const T6_POLICY_PATH = process.env.T6_POLICY_PATH || "/opt/inspection/t6-policy.json";
// MCP tool names as pi registers them: mcp__<server>__<tool> with every
// character other than letters/digits/_ replaced by _ (docs/mcp.md) — the
// server keys toy-mcp-fs / toy-mcp-http become toy_mcp_fs / toy_mcp_http.
const T4_FS_SERVER = "toy_mcp_fs";
const T4_HTTP_SERVER = "toy_mcp_http";
const T4_MCP_READY_TIMEOUT_MS = 30000;

async function gatewayFsToolCall(action: any): Promise<unknown> {
  if (probeGatewayClient) return await probeGatewayClient.call(action.tool, action.arguments ?? {}, action.id);
  const msg = { jsonrpc: "2.0", id: ++gatewayRpcId, method: "tools/call",
                params: { name: action.tool, arguments: action.arguments ?? {} } };
  const resp = await withTimeout(fetch(`${GATEWAY_URL.replace(/\/$/, "")}/mcp`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg),
  }), ACTION_TIMEOUT_MS, `gateway ${action.tool}`) as Response;
  const data: any = await resp.json();
  if (data.error) throw new Error(`gateway denied ${action.tool}: ${JSON.stringify(data.error)}`);
  return { text: data.result?.content?.[0]?.text, via: "gateway", tool: action.tool };
}

let probeGatewayClient: any = null;
async function initProbeGateway() {
  if (process.env.GATEWAY_CLIENT_MODULE && !probeGatewayClient) {
    const { GatewayClient } = await import(process.env.GATEWAY_CLIENT_MODULE);
    probeGatewayClient = new GatewayClient(GATEWAY_URL);
    await probeGatewayClient.start();
  }
}

async function mcpHttpToolCall(action: any): Promise<unknown> {
  const u = new URL(action.url);
  const tool = GATEWAY_TOOL_ROUTES[`${action.method} ${u.pathname}`];
  if (!tool) throw new Error(`no gateway tool route for ${action.method} ${u.pathname}`);
  const toolArgs: Record<string, string> = {};
  if (action.body !== undefined) toolArgs.body = action.body;
  if (probeGatewayClient) return await probeGatewayClient.call(tool, toolArgs, action.id);
  const msg = { jsonrpc: "2.0", id: ++gatewayRpcId, method: "tools/call",
                params: { name: tool, arguments: toolArgs } };
  const resp = await withTimeout(fetch(`${GATEWAY_URL.replace(/\/$/, "")}/mcp`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg),
  }), ACTION_TIMEOUT_MS, `gateway ${tool}`) as Response;
  const data: any = await resp.json();
  if (data.error) throw new Error(`gateway denied ${tool}: ${JSON.stringify(data.error)}`);
  const result = JSON.parse(data.result.content[0].text);
  return { ...result, via: "gateway", tool };
}

const ns = () => Number(process.hrtime.bigint());           // monotonic (durations)
const epochNs = () => Number(BigInt(Date.now()) * 1000000n); // wall clock (Tracee-comparable)
const withTimeout = (p: Promise<unknown>, ms: number, what: string) =>
  Promise.race([p, new Promise((_, rej) =>
    setTimeout(() => rej(new Error(`${what} timeout`)), ms))]);

// --- MCP stdio session (same wire protocol as the harness MCP client) ------

class McpSession {
  #proc;
  #buf = "";
  #pending = new Map<number, (msg: any) => void>();
  #nextId = 0;
  #diagnostics: string[] = [];

  async start() {
    this.#proc = spawn(MCP_CMD[0], MCP_CMD.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
    this.#proc.on("error", (e) => this.#diagnostics.push(`spawn error: ${e}`));
    this.#proc.stderr!.setEncoding("utf8");
    this.#proc.stderr!.on("data", (d) => this.#diagnostics.push(`stderr: ${String(d).trim().slice(0, 300)}`));
    this.#proc.on("exit", (code) => this.#diagnostics.push(`exit: ${code}`));
    this.#proc.stdout!.setEncoding("utf8");
    this.#proc.stdout!.on("data", (chunk) => {
      this.#buf += chunk;
      let i;
      while ((i = this.#buf.indexOf("\n")) >= 0) {
        const line = this.#buf.slice(0, i).trim();
        this.#buf = this.#buf.slice(i + 1);
        if (!line) continue;
        let msg;
        try { msg = JSON.parse(line); } catch { continue; }
        const resolve = this.#pending.get(msg.id);
        if (resolve) { this.#pending.delete(msg.id); resolve(msg); }
      }
    });
    const init = await this.#request("initialize", {
      protocolVersion: "2025-06-18",
      capabilities: {},
      clientInfo: { name: "inspection-replay", version: "0.2.0" },
    });
    if (!init.result) throw new Error(`MCP initialize failed: ${JSON.stringify(init)}`);
    this.#proc.stdin!.write(
      JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    return init.result;
  }

  #request(method: string, params: unknown) {
    const id = ++this.#nextId;
    return new Promise<any>((resolve, reject) => {
      const t = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`MCP ${method} timeout`));
      }, MCP_TIMEOUT_MS);
      this.#pending.set(id, (msg) => { clearTimeout(t); resolve(msg); });
      this.#proc.stdin!.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  call(tool: string, args: unknown) { return this.#request("tools/call", { name: tool, arguments: args }); }

  get diagnostics() { return this.#diagnostics.slice(-10); }

  close() {
    try { this.#proc.stdin!.end(); } catch { /* already gone */ }
    this.#proc.kill("SIGKILL");
  }
}

// --- per-class executors -----------------------------------------------------

async function execAction(action: any): Promise<unknown> {
  switch (action.kind) {
    case "mcp": {
      if (GATEWAY_FS && !probeGatewayClient?.disabled) return await gatewayFsToolCall(action);
      const resp = await withTimeout(mcpSession!.call(action.tool, action.arguments),
                                     MCP_TIMEOUT_MS, `mcp ${action.tool}`);
      if (resp.error) throw new Error(`mcp ${action.tool}: ${JSON.stringify(resp.error)}`);
      return { server: action.server, tool: action.tool };
    }
    case "http": {
      if (GATEWAY_URL && !probeGatewayClient?.disabled) return await mcpHttpToolCall(action);
      const init: RequestInit = { method: action.method };
      if (action.body !== undefined) init.body = action.body;
      const resp = await withTimeout(fetch(action.url, init), ACTION_TIMEOUT_MS, action.url);
      await resp.arrayBuffer(); // drain so the connection returns to the pool
      return { status: resp.status };
    }
    case "tcp_connect":
      return await withTimeout(new Promise((resolve, reject) => {
        let connected = false;
        const sock = net.connect({ host: action.host, port: action.port }, () => {
          connected = true;
          if (CSB_EVIDENCE_DIR && action.id === "csb-public-001" && action.connect_only === true) {
            sock.destroy(); // explicitly partial external connect-only case; no served claim
          } else {
            sock.end(action.payload ?? "");
          }
        });
        let received = "";
        // Bound the CSB blackhole attempt without leaving a live socket after
        // a recorded timeout. Existing profiles retain their executor path.
        const timer = CSB_EVIDENCE_DIR ? setTimeout(() => {
          const err = Object.assign(new Error("tcp_connect timeout"), { code: "ETIMEDOUT" });
          sock.destroy(err);
        }, ACTION_TIMEOUT_MS) : null;
        sock.on("data", (data) => { received += data.toString(); sock.destroy(); });
        sock.on("error", (err) => { if (timer) clearTimeout(timer); reject(err); });
        sock.on("close", () => {
          if (timer) clearTimeout(timer);
          resolve({ host: action.host, port: action.port, ...(CSB_EVIDENCE_DIR ? { received, connected } : {}) });
        });
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
        execFile(action.cmd[0], action.cmd.slice(1), { timeout: ACTION_TIMEOUT_MS }, (err, stdout, stderr) => {
          if (err) reject(err); else resolve({ cmd: action.cmd, ...(CSB_EVIDENCE_DIR ? { stdout, stderr } : {}) });
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

// --- replay session state (one MCP session per replay, opened lazily) ------
let mcpSession: McpSession | null = null;

async function ensureMcpSession() {
  if (!mcpSession) {
    mcpSession = new McpSession();
    await mcpSession.start();
  }
}

async function runReplay(trace: any) {
  await fs.mkdir(REPLAY_LOG_DIR, { recursive: true });
  await csbSnapshot(trace); // BEFORE the measurement window, and off by default
  await initProbeGateway(); // initialize/session/tool discovery outside measurement window
  const logPath = `${REPLAY_LOG_DIR}/replay-log.jsonl`;
  const log = createWriteStream(logPath, { flags: "w" });
  const startedNs = ns();
  const startedEpoch = epochNs();
  const line = (obj: unknown) => new Promise<void>((res) => log.write(JSON.stringify(obj) + "\n", res));

  const results: any[] = [];
  try {
    await line({ event: "mark-start", ts_ns: startedNs, epoch_ns: startedEpoch,
                 spec_sha256: trace.meta?.spec_sha256, harness: "pi" });
    for (const action of trace.actions) {
      const t0 = ns();
      const attemptEpoch = CSB_EVIDENCE_DIR ? epochNs() : null;
      let errorDetail: any = null;
      let status = "ok", detail: unknown = null, error: string | null = null;
      try {
        // Only the additive all-tool probe client suppresses the local child;
        // preserve legacy executor paths, and restore stdio in its baseline.
        if (action.kind === "mcp" && (!GATEWAY_FS || !probeGatewayClient || probeGatewayClient.disabled)) await ensureMcpSession();
        detail = await execAction(action);
      } catch (exc) {
        status = "error";
        error = String((exc && (exc as Error).message) || exc);
        if (CSB_EVIDENCE_DIR) {
          const e: any = exc;
          errorDetail = { code: e?.code || e?.cause?.code || null, errno: e?.errno ?? e?.cause?.errno ?? null,
            syscall: e?.syscall || e?.cause?.syscall || null, path: e?.path || null,
            timeout: /timeout/i.test(error), message: error };
        }
        if (mcpSession?.diagnostics.length) error += ` | ${mcpSession.diagnostics.join(" | ")}`;
      }
      const rec = { id: action.id, class: action.class, op: action.op,
                    started_ns: t0, ended_ns: ns(),
                    started_epoch_ns: epochNs(), status, detail, error,
                    ...(CSB_EVIDENCE_DIR ? { attempt_epoch_ns: attemptEpoch, error_detail: errorDetail } : {}) };
      results.push(rec);
      await line(rec);
    }
  } finally {
    if (mcpSession) { mcpSession.close(); mcpSession = null; }
  }
  const endedNs = ns();
  const endedEpoch = epochNs();
  await line({ event: "mark-end", ts_ns: endedNs, epoch_ns: endedEpoch });
  await new Promise<void>((res) => log.end(res));

  const failed = results.filter((r) => r.status !== "ok");
  const result = {
    ok: failed.length === 0,
    executed: results.length,
    failed: failed.length,
    window_ns: { start: startedNs, end: endedNs },
    window_epoch_ns: { start: startedEpoch, end: endedEpoch },
    replay_log: logPath,
    results,
  };
  await fs.writeFile(`${REPLAY_LOG_DIR}/replay-result.json`,
                     JSON.stringify(result, null, 1) + "\n");
  return result;
}

// --- T4: harness-native enforcement -----------------------------------------

// The tool-call actions as pi MCP tool calls: (actionId, mcp tool name, args).
// The compiled plan is kind-shaped (kind mcp/http with url/method fields —
// see trace/compile/pi/compile.py), not spec-shaped.
function t4ToolCalls(trace: any): { id: string; tool: string; args: Record<string, unknown> }[] {
  const calls: { id: string; tool: string; args: Record<string, unknown> }[] = [];
  for (const action of trace.actions) {
    if (action.class === "stdio_tool_call") {
      calls.push({ id: action.id, tool: `mcp__${T4_FS_SERVER}__${action.tool}`,
                   args: action.arguments ?? {} });
    } else if (action.class === "http_tool_call") {
      const u = new URL(action.url);
      const tool = GATEWAY_TOOL_ROUTES[`${action.method} ${u.pathname}`];
      if (!tool) throw new Error(`no MCP tool for ${action.method} ${u.pathname}`);
      const args: Record<string, unknown> = {};
      if (action.body !== undefined) args.body = action.body;
      calls.push({ id: action.id, tool: `mcp__${T4_HTTP_SERVER}__${tool}`, args });
    }
  }
  return calls;
}

function t4WriteDecision(entry: Record<string, unknown>) {
  try {
    appendFileSync(`${REPLAY_LOG_DIR}/decisions.jsonl`,
                   JSON.stringify(entry) + "\n");
  } catch { /* logging must never break enforcement */ }
}

// Per-call latency evidence (T4-T6): the tool_call hook is the dispatch
// boundary — it fires when the call crosses the enforcement point, before
// execution; tool_result fires when the call completes. The pair gives the
// per-call dispatch latency RQ4 measures (same boundary semantics as the
// T0-T3 adapter-side started_ns/ended_ns).
const t4CallStart = new Map<string, { started_ns: number; started_epoch_ns: number }>();
// Deny-path (T6): tool calls the enforcement point denied. A BLOCKED call
// never executes and pi never fires tool_result for it — the hook records
// the terminal result itself (status "denied", duration = the hook's
// evaluation time). tool_result handles only the executed calls.
const t4DeniedIds = new Set<string>();
const t4RecordedIds = new Set<string>();

function t4RecordResult(rec: Record<string, unknown>) {
  t4ToolResults.push(rec);
  t4RecordedIds.add(String(rec.id));
}

// T4 phase state: the command phase writes it, the agent-settled handler
// consumes it (single replay per pi process, matching the T0 design).
let t4State: {
  trace: any;
  startedNs: number; startedEpoch: number;
  log: ReturnType<typeof createWriteStream>;
  processResults: any[];
} | null = null;
const t4ToolResults: any[] = [];

async function t4CommandPhase(trace: any, ctx: any): Promise<void> {
  await fs.mkdir(REPLAY_LOG_DIR, { recursive: true });
  // MCP readiness: pi connects the config servers in the background at
  // startup; the agent run waits for direct tools, but the COMMAND phase
  // must not start the measurement window before the servers' handshake
  // traffic is done — wait for the tools to be registered first.
  const wanted = new Set(t4ToolCalls(trace).map((c) => c.tool));
  const deadline = Date.now() + T4_MCP_READY_TIMEOUT_MS;
  for (;;) {
    const have = new Set((piRef!.getAllTools() as { name: string }[]).map((t) => t.name));
    if ([...wanted].every((t) => have.has(t))) break;
    if (Date.now() > deadline) {
      // Non-fatal: MCP tools may only register when the agent run starts (pi
      // waits for direct tools at the first prompt). If they are genuinely
      // absent, phase 2 fails visibly per action.
      ctx.ui.notify(`inspection-replay (t4): MCP tools not visible to getAllTools ` +
                    `after ${T4_MCP_READY_TIMEOUT_MS}ms; continuing (phase 2 waits)`, "warning");
      break;
    }
    await new Promise((r) => setTimeout(r, 250));
  }

  const startedNs = ns();
  const startedEpoch = epochNs();
  const logPath = `${REPLAY_LOG_DIR}/replay-log.jsonl`;
  const log = createWriteStream(logPath, { flags: "w" });
  const line = (obj: unknown) => new Promise<void>((res) => log.write(JSON.stringify(obj) + "\n", res));
  t4State = { trace, startedNs, startedEpoch, log, processResults: [] };
  await line({ event: "mark-start", ts_ns: startedNs, epoch_ns: startedEpoch,
               spec_sha256: trace.meta?.spec_sha256, harness: "pi", design: "t4" });

  // Process-level actions: agent code OUTSIDE the tool pipeline (bypass).
  for (const action of trace.actions) {
    if (action.class === "stdio_tool_call" || action.class === "http_tool_call") continue;
    const t0 = ns();
    let status = "ok", detail: unknown = null, error: string | null = null;
    try {
      detail = await execAction(action);
    } catch (exc) {
      status = "error";
      error = String((exc && (exc as Error).message) || exc);
    }
    const rec = { id: action.id, class: action.class, op: action.op,
                  started_ns: t0, ended_ns: ns(), started_epoch_ns: epochNs(),
                  status, detail, error };
    t4State.processResults.push(rec);
    await line(rec);
  }
  await new Promise<void>((res) => log.end(res));   // close phase-1 log; reassembled at settle
}

async function t4SettledPhase(): Promise<void> {
  if (!t4State) return;   // no replay in flight
  const { trace, startedNs, startedEpoch, processResults } = t4State;
  const endedNs = ns();
  const endedEpoch = epochNs();

  const byId = new Map(processResults.map((r) => [r.id, r]));
  for (const tr of t4ToolResults) {
    const a = trace.actions.find((x: any) => x.id === tr.id);
    byId.set(tr.id, { ...tr, class: a?.class, op: a?.op });
  }
  const results = trace.actions.map((a: any) => {
    const rec = byId.get(a.id);
    if (rec) return rec;
    return { id: a.id, class: a.class, op: a.op, status: "error",
             error: "no result recorded (tool call never executed?)" };
  });

  const logPath = `${REPLAY_LOG_DIR}/replay-log.jsonl`;
  const log = createWriteStream(logPath, { flags: "w" });
  const line = (obj: unknown) => new Promise<void>((res) => log.write(JSON.stringify(obj) + "\n", res));
  await line({ event: "mark-start", ts_ns: startedNs, epoch_ns: startedEpoch,
               spec_sha256: trace.meta?.spec_sha256, harness: "pi", design: "t4" });
  for (const rec of results) await line(rec);
  await line({ event: "mark-end", ts_ns: endedNs, epoch_ns: endedEpoch });
  await new Promise<void>((res) => log.end(res));

  const failed = results.filter((r: any) => r.status === "error");
  const denied = results.filter((r: any) => r.status === "denied");
  const result = {
    ok: failed.length === 0,
    executed: results.length,
    failed: failed.length,
    denied: denied.length,
    window_ns: { start: startedNs, end: endedNs },
    window_epoch_ns: { start: startedEpoch, end: endedEpoch },
    replay_log: logPath,
    results,
  };
  await fs.writeFile(`${REPLAY_LOG_DIR}/replay-result.json`,
                     JSON.stringify(result, null, 1) + "\n");
  t4State = null;
}

// --- T6: in-process policy engine -------------------------------------------

interface T6Rule {
  tools?: string[];
  /** arg name -> required value prefix (argument-level constraints) */
  constraints?: Record<string, string>;
  reason?: string;
}

interface T6Policy {
  name: string;
  default: "allow" | "deny";
  rules: T6Rule[];
}

let t6Policy: T6Policy | null = null;

function t6LoadPolicy(): T6Policy {
  if (!t6Policy) {
    t6Policy = JSON.parse(readFileSync(T6_POLICY_PATH, "utf8"));
  }
  return t6Policy;
}

function t6Evaluate(toolName: string, input: Record<string, unknown>):
    { allowed: boolean; reason: string; matched_rule: string | null } {
  const bare = toolName.startsWith("mcp__") ? toolName.split("__").slice(-1)[0] : toolName;
  const policy = t6LoadPolicy();
  for (let i = 0; i < policy.rules.length; i++) {
    const rule = policy.rules[i];
    if (rule.tools && !rule.tools.includes(bare)) continue;
    let ok = true;
    for (const [arg, prefix] of Object.entries(rule.constraints ?? {})) {
      const v = input?.[arg];
      if (typeof v !== "string" || !v.startsWith(prefix)) { ok = false; break; }
    }
    if (ok) {
      return { allowed: true, reason: rule.reason ?? `rule ${i}`, matched_rule: `rule-${i}` };
    }
  }
  if (policy.default === "allow") {
    return { allowed: true, reason: "default allow", matched_rule: null };
  }
  return { allowed: false, reason: `no rule allows ${bare} with the given arguments`, matched_rule: null };
}

// --- T4 scripted provider: the replay trace as a deterministic agent turn ---
// The provider issues the tool-call actions the way a model would (assistant
// message with tool calls), so pi's tool pipeline — argument validation, the
// tool_call permission handlers, MCP execution — runs exactly as in
// production. Phase 1: issue the tool calls; phase 2 (after the tool
// results): end the turn.
function t4RegisterProvider(pi: ExtensionAPI) {
  const zeroUsage = { input: 0, output: 0, cacheRead: 0, cacheWrite: 0,
                      cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 } };
  const msg = (content: any[], stopReason: string) => ({
    role: "assistant", content, api: "replay", provider: "inspection-replay",
    model: "replay", usage: zeroUsage, stopReason, timestamp: Date.now(),
  });

  pi.registerProvider("inspection-replay", {
    // never contacted (the stream is fully scripted); the legacy provider
    // config requires a baseUrl when defining custom models
    baseUrl: "http://127.0.0.1:9",
    apiKey: "unused-scripted-provider",
    api: "replay",
    models: [{ type: "chat", id: "replay", name: "Inspection Replay (scripted)",
               input: ["text"], cost: zeroUsage.cost,
               contextWindow: 128000, maxTokens: 8192 }],
    streamSimple: (_model: any, context: any) => {
      const stream = createAssistantMessageEventStream();
      console.error(`[inspection-replay] streamSimple called; messages=${(context.messages ?? []).length}`);
      (async () => {
        try {
          console.error(`[inspection-replay] phase entry`);
          const tracePath = `${REPLAY_LOG_DIR}/compiled.json`;
          const trace = JSON.parse(readFileSync(tracePath, "utf8"));
          console.error(`[inspection-replay] trace loaded (${trace.actions.length} actions)`);
          console.error(`[inspection-replay] trace loaded (${trace.actions.length} actions)`);
          const hasToolResults = (context.messages ?? []).some(
            (m: any) => m.role === "toolResult");
          if (hasToolResults) {
            console.error(`[inspection-replay] phase 2 (tool results present)`);
            const text = "inspection replay complete";
            stream.push({ type: "start", partial: msg([], "stop") });
            stream.push({ type: "text_start", contentIndex: 0, partial: msg([], "stop") });
            stream.push({ type: "text_delta", contentIndex: 0, delta: text, partial: msg([], "stop") });
            stream.push({ type: "text_end", contentIndex: 0, content: text, partial: msg([], "stop") });
            stream.push({ type: "done", reason: "stop", message: msg([{ type: "text", text }], "stop") });
          } else {
            console.error(`[inspection-replay] phase 1 (issuing ${t4ToolCalls(trace).length} tool calls)`);
            const calls = t4ToolCalls(trace);
            const content = calls.map((c) => ({ type: "toolCall", id: c.id, name: c.tool, arguments: c.args }));
            stream.push({ type: "start", partial: msg(content, "toolUse") });
            for (let i = 0; i < calls.length; i++) {
              stream.push({ type: "toolcall_start", contentIndex: i, partial: msg(content, "toolUse") });
              stream.push({ type: "toolcall_end", contentIndex: i,
                            toolCall: { type: "toolCall", id: calls[i].id, name: calls[i].tool, arguments: calls[i].args },
                            partial: msg(content, "toolUse") });
            }
            stream.push({ type: "done", reason: "toolUse", message: msg(content, "toolUse") });
          }
          stream.end();
          console.error(`[inspection-replay] stream ended`);
        } catch (error) {
          console.error(`[inspection-replay] stream error: ${String((error as Error)?.message ?? error)}`);
          stream.push({ type: "error", reason: "error",
                        error: { ...msg([], "error"), stopReason: "error",
                                 errorMessage: String((error as Error)?.message ?? error) } });
          stream.end();
        }
      })();
      return stream;
    },
  });
}

// --- extension entry -----------------------------------------------------------

// Captured for the T4 command phase (MCP readiness polling).
let piRef: ExtensionAPI | null = null;

// Optional probe evaluator: enforcement remains at this real dispatch hook.
// NeMo's Python runtime is a local child; no loopback policy service or LLM.
let externalEvaluator: any = null;
async function getExternalEvaluator() {
  if (!externalEvaluator && process.env.T6_EVALUATOR_MODULE) {
    const { EvaluatorBridge } = await import(process.env.T6_EVALUATOR_MODULE);
    externalEvaluator = new EvaluatorBridge(JSON.parse(process.env.T6_EVALUATOR_CMD!));
    await externalEvaluator.start();
  }
  return externalEvaluator;
}

export default function (pi: ExtensionAPI) {
  piRef = pi;
  if (T4_MODE || T6_MODE) {
    // The enforcement point: the tool_call hook. T4: the harness permission
    // layer (allow-all v1). T6: the in-process policy engine (declarative
    // rules over tool names + argument values; denials block, fail-closed).
    // Both write the enforcement-point record (AuditEntry-shaped, same
    // loader as the gateway's decisions.jsonl).
    pi.on("tool_call", async (event) => {
      let allowed = true, reason: string, matchedRule: string | null = null;
      let productVerdict: any = null;
      t4CallStart.set(event.toolCallId, { started_ns: ns(), started_epoch_ns: epochNs() });
      if (T6_MODE) {
        try {
          const evaluator = await getExternalEvaluator();
          const verdict = evaluator
            ? await evaluator.evaluate(event.toolName, event.input ?? {}, event.toolCallId)
            : t6Evaluate(event.toolName, event.input ?? {});
          allowed = verdict.allowed;
          reason = verdict.reason;
          matchedRule = verdict.matched_rule;
          productVerdict = evaluator ? verdict : null;
        } catch (error) {
          // Fail closed, but evaluator failure is NOT an observed policy denial.
          const st = t4CallStart.get(event.toolCallId)!;
          reason = `policy evaluator failure: ${String(error)}`;
          t4RecordResult({ id: event.toolCallId, status: "error", error: reason,
                           started_ns: st.started_ns, ended_ns: ns(),
                           started_epoch_ns: st.started_epoch_ns });
          appendFileSync(`${REPLAY_LOG_DIR}/evaluator-errors.jsonl`,
                         JSON.stringify({ tool_call_id: event.toolCallId, reason, timestamp: epochNs() }) + "\n");
          return { block: true, reason };
        }
      } else {
        reason = "harness permission mode (allow-all)";
      }
      if (!allowed) {
        // blocked: no execution, no tool_result event — record the terminal
        // result here (the denial IS the outcome; effect must be absent)
        t4DeniedIds.add(event.toolCallId);
        const st = t4CallStart.get(event.toolCallId)!;
        t4RecordResult({
          id: event.toolCallId, status: "denied", error: null,
          started_ns: st.started_ns, ended_ns: ns(),
          started_epoch_ns: st.started_epoch_ns,
        });
      }
      t4WriteDecision({
        timestamp: Date.now() / 1000,
        agent_id: T6_MODE ? "t6-in-process" : "t4-harness",
        tool_name: event.toolName,
        tool_call_id: event.toolCallId,
        allowed,
        reason,
        matched_rule: matchedRule,
        product_verdict: productVerdict,
        parameters: event.input ?? {},
      });
      return allowed ? {} : { block: true, reason };
    });
    pi.on("tool_result", (event) => {
      if (t4RecordedIds.has(event.toolCallId)) return {};  // denied: recorded at the hook
      const start = t4CallStart.get(event.toolCallId);
      t4RecordResult({
        id: event.toolCallId,
        status: event.isError ? "error" : "ok",
        error: event.isError ? "tool execution failed" : null,
        started_ns: start?.started_ns,
        ended_ns: ns(),
        started_epoch_ns: start?.started_epoch_ns,
      });
      return {};
    });
    pi.on("agent_settled", async () => { await t4SettledPhase(); externalEvaluator?.close(); });
    pi.on("session_shutdown", () => { externalEvaluator?.close(); });
    t4RegisterProvider(pi);
  }
  pi.registerCommand("inspection-replay", {
    description: "T0 replay adapter: execute a compiled canonical trace in-process (no LLM)",
    handler: async (args, ctx) => {
      const path = String(args || "").trim() || `${REPLAY_LOG_DIR}/compiled.json`;
      let trace: any;
      try {
        trace = JSON.parse(await fs.readFile(path, "utf8"));
      } catch (exc) {
        await fs.writeFile(`${REPLAY_LOG_DIR}/replay-result.json`,
          JSON.stringify({ ok: false, error: `cannot read trace: ${(exc as Error).message}` }) + "\n");
        ctx.ui.notify(`inspection-replay: bad trace (${(exc as Error).message})`, "error");
        return;
      }
      if (!trace?.actions?.length) {
        await fs.writeFile(`${REPLAY_LOG_DIR}/replay-result.json`,
          JSON.stringify({ ok: false, error: "missing trace.actions" }) + "\n");
        return;
      }
      if (T4_MODE || T6_MODE) {
        // T4 command phase: MCP readiness + the process-level actions. The
        // driver then sends the second prompt, which starts the agent run
        // (scripted provider -> the tool calls cross pi's pipeline); the
        // settled handler assembles the full replay result.
        if (T6_MODE) await getExternalEvaluator(); // warm before measurement marks
        await t4CommandPhase(trace, ctx);
        ctx.ui.notify(`inspection-replay (${T6_MODE ? "t6" : "t4"}): process phase done; send the tool-call prompt`, "info");
        return;
      }
      const result = await runReplay(trace);
      ctx.ui.notify(`inspection-replay: ${result.executed} actions, ${result.failed} failed`, 
                    result.ok ? "info" : "error");
    },
  });
}