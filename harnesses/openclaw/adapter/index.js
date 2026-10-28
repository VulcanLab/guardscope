// OpenClaw replay adapter (C3): injects the compiled canonical trace at the
// harness tool level. No LLM anywhere: the driver triggers one tool call,
// `replay_trace`, via POST /tools/invoke; this plugin executes every action
// sequentially inside the OpenClaw gateway process (harness context), so all
// child processes (MCP server, /bin/sh, /bin/echo) are harness children and
// Tracee attributes them correctly.
//
// Execution plan per class (compiled by trace/compile/openclaw/compile.py):
//   mcp              -> spawn the toy MCP stdio server as a gateway child;
//                       one session per replay, NDJSON JSON-RPC roundtrip
//   http             -> fetch() from the gateway process; with GATEWAY_URL
//                       set (T1): MCP tools/call over HTTP via the gateway
//   tcp_connect      -> node:net socket to the net-peer target
//   udp_send         -> node:dgram datagram to the net-peer target
//   spawn            -> child_process.execFile (the traced process tree)
//   file_write       -> node:fs write/append (direct, no tool transport)
//   credential_read  -> node:fs read of the seeded secret file
//
// Env knobs (gateway-process env, set by the harness container):
//   REPLAY_LOG_DIR  replay JSONL log + marks (default /workspace/replay)
//   MCP_SERVER_CMD  JSON array; the MCP stdio server command
//                   (default ["python3","-u","/opt/inspection/mcp-fs/server.py"])

import { definePluginEntry } from "openclaw/plugin-sdk/plugin-entry";
import { registerT4Enforcement } from "./t4.js";

// T4/T6 (harness-native / in-process enforcement): registered by the same
// plugin entry when T4_MODE/T6_MODE is set (see adapter/t4.js). Static import
// + synchronous registration so the hooks exist before the gateway serves.
const T4_OR_T6 = process.env.T4_MODE === "1" || process.env.T6_MODE === "1";
import { Type } from "typebox";
import { spawn, execFile } from "node:child_process";
import { promises as fs, createWriteStream } from "node:fs";
import { dirname } from "node:path";
import net from "node:net";
import dgram from "node:dgram";

const REPLAY_LOG_DIR = process.env.REPLAY_LOG_DIR || "/workspace/replay";
const MCP_CMD = JSON.parse(process.env.MCP_SERVER_CMD ||
  '["python3","-u","/opt/inspection/mcp-fs/server.py"]');
const MCP_TIMEOUT_MS = 20000;
const ACTION_TIMEOUT_MS = 20000;
// T1 gateway routing (compose/t1.yaml sets GATEWAY_URL for the deployment-
// design T1 topology; unset = T0 bare-harness mode with raw fetch). When set,
// http_tool_call actions execute as MCP tools/call over HTTP against the
// gateway — the T1 enforcement point — instead of raw fetch to the target.
const GATEWAY_URL = process.env.GATEWAY_URL || "";
// method+path -> gateway tool name (targets/mcp-http TOOL_ROUTES, 1:1 with
// canonical http_tool_call actions a011-a013).
const GATEWAY_TOOL_ROUTES = {
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

async function gatewayFsToolCall(action) {
  const msg = { jsonrpc: "2.0", id: ++gatewayRpcId, method: "tools/call",
                params: { name: action.tool, arguments: action.arguments ?? {} } };
  const resp = await withTimeout(fetch(`${GATEWAY_URL.replace(/\/$/, "")}/mcp`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg),
  }), ACTION_TIMEOUT_MS, `gateway ${action.tool}`);
  const data = await resp.json();
  if (data.error) throw new Error(`gateway denied ${action.tool}: ${JSON.stringify(data.error)}`);
  return { text: data.result?.content?.[0]?.text, via: "gateway", tool: action.tool };
}

async function mcpHttpToolCall(action) {
  const u = new URL(action.url);
  const tool = GATEWAY_TOOL_ROUTES[`${action.method} ${u.pathname}`];
  if (!tool) throw new Error(`no gateway tool route for ${action.method} ${u.pathname}`);
  const toolArgs = {};
  if (action.body !== undefined) toolArgs.body = action.body;
  const msg = { jsonrpc: "2.0", id: ++gatewayRpcId, method: "tools/call",
                params: { name: tool, arguments: toolArgs } };
  const resp = await withTimeout(fetch(`${GATEWAY_URL.replace(/\/$/, "")}/mcp`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg),
  }), ACTION_TIMEOUT_MS, `gateway ${tool}`);
  const data = await resp.json();
  if (data.error) throw new Error(`gateway denied ${tool}: ${JSON.stringify(data.error)}`);
  const result = JSON.parse(data.result.content[0].text);
  return { ...result, via: "gateway", tool };
}

const ns = () => Number(process.hrtime.bigint());           // monotonic (durations)
const epochNs = () => Number(BigInt(Date.now()) * 1000000n); // wall clock (Tracee-comparable)
const withTimeout = (p, ms, what) =>
  Promise.race([p, new Promise((_, rej) =>
    setTimeout(() => rej(new Error(`${what} timeout`)), ms))]);

// --- MCP stdio session (same wire protocol as the harness MCP client) ------

class McpSession {
  #proc;
  #buf = "";
  #pending = new Map();
  #nextId = 0;
  #diagnostics = [];

  async start() {
    this.#proc = spawn(MCP_CMD[0], MCP_CMD.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
    this.#proc.on("error", (e) => this.#diagnostics.push(`spawn error: ${e}`));
    this.#proc.stderr.setEncoding("utf8");
    this.#proc.stderr.on("data", (d) => this.#diagnostics.push(`stderr: ${d.trim().slice(0, 300)}`));
    this.#proc.on("exit", (code) => this.#diagnostics.push(`exit: ${code}`));
    this.#proc.stdout.setEncoding("utf8");
    this.#proc.stdout.on("data", (chunk) => {
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
    this.#proc.stdin.write(
      JSON.stringify({ jsonrpc: "2.0", method: "notifications/initialized" }) + "\n");
    return init.result;
  }

  #request(method, params) {
    const id = ++this.#nextId;
    return new Promise((resolve, reject) => {
      const t = setTimeout(() => {
        this.#pending.delete(id);
        reject(new Error(`MCP ${method} timeout`));
      }, MCP_TIMEOUT_MS);
      this.#pending.set(id, (msg) => { clearTimeout(t); resolve(msg); });
      this.#proc.stdin.write(JSON.stringify({ jsonrpc: "2.0", id, method, params }) + "\n");
    });
  }

  call(tool, args) { return this.#request("tools/call", { name: tool, arguments: args }); }

  get diagnostics() { return this.#diagnostics.slice(-10); }

  close() {
    try { this.#proc.stdin.end(); } catch { /* already gone */ }
    this.#proc.kill("SIGKILL");
  }
}

// --- per-class executors -----------------------------------------------------

async function execAction(action) {
  switch (action.kind) {
    case "mcp": {
      if (GATEWAY_FS) return await gatewayFsToolCall(action);
      const resp = await withTimeout(mcpSession.call(action.tool, action.arguments),
                                     MCP_TIMEOUT_MS, `mcp ${action.tool}`);
      if (resp.error) throw new Error(`mcp ${action.tool}: ${JSON.stringify(resp.error)}`);
      return { server: action.server, tool: action.tool };
    }
    case "http": {
      if (GATEWAY_URL) return await mcpHttpToolCall(action);
      const init = { method: action.method };
      if (action.body !== undefined) init.body = action.body;
      const resp = await withTimeout(fetch(action.url, init), ACTION_TIMEOUT_MS, action.url);
      await resp.arrayBuffer(); // drain so the connection returns to the pool
      return { status: resp.status };
    }
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

// --- replay session state (one MCP session per replay, opened lazily) ------
let mcpSession = null;

async function ensureMcpSession() {
  if (!mcpSession) {
    mcpSession = new McpSession();
    await mcpSession.start();
  }
}

// --- plugin entry ------------------------------------------------------------

export default definePluginEntry({
  id: "inspection-replay",
  name: "Inspection Replay",
  description: "T0 replay adapter: injects the canonical trace (no LLM)",
  register(api) {
    if (T4_OR_T6) {
      registerT4Enforcement(api);
      return;
    }
    api.registerTool({
      name: "replay_trace",
      description: "Execute a compiled canonical trace inside the gateway (harness context)",
      parameters: Type.Object({
        trace: Type.Object({}, { additionalProperties: true }),
      }),
      async execute(first, second) {
        // api.registerTool passes the core runtime signature
        // (toolCallId, params, ...); accept both shapes defensively.
        const params = typeof first === "string" ? second : first;
        const trace = params?.trace;
        if (!trace?.actions?.length) {
          return { ok: false, error: "missing trace.actions" };
        }
        return runReplay(trace);
      },
    });
  },
});

async function runReplay(trace) {
  await fs.mkdir(REPLAY_LOG_DIR, { recursive: true });
  const logPath = `${REPLAY_LOG_DIR}/replay-log.jsonl`;
  const log = createWriteStream(logPath, { flags: "w" });
  const startedNs = ns();
  const startedEpoch = epochNs();
  const line = (obj) => new Promise((res) => log.write(JSON.stringify(obj) + "\n", res));

  const results = [];
  try {
    await line({ event: "mark-start", ts_ns: startedNs, epoch_ns: startedEpoch,
                 spec_sha256: trace.meta?.spec_sha256, harness: "openclaw" });
    for (const action of trace.actions) {
      const t0 = ns();
      let status = "ok", detail = null, error = null;
      try {
        if (action.kind === "mcp") await ensureMcpSession();
        detail = await execAction(action);
      } catch (exc) {
        status = "error";
        error = String((exc && exc.message) || exc);
        if (mcpSession?.diagnostics.length) error += ` | ${mcpSession.diagnostics.join(" | ")}`;
      }
      const rec = { id: action.id, class: action.class, op: action.op,
                    started_ns: t0, ended_ns: ns(),
                    started_epoch_ns: epochNs(), status, detail, error };
      results.push(rec);
      await line(rec);
    }
  } finally {
    if (mcpSession) { mcpSession.close(); mcpSession = null; }
  }
  const endedNs = ns();
  const endedEpoch = epochNs();
  await line({ event: "mark-end", ts_ns: endedNs, epoch_ns: endedEpoch });
  await new Promise((res) => log.end(res));

  const failed = results.filter((r) => r.status !== "ok");
  return {
    ok: failed.length === 0,
    executed: results.length,
    failed: failed.length,
    window_ns: { start: startedNs, end: endedNs },
    window_epoch_ns: { start: startedEpoch, end: endedEpoch },
    replay_log: logPath,
    results,
  };
}