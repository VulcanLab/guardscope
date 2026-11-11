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
//   INSPECTION_RUN_ID  run id the runner stamps into the pi process env
//                   (runner/trigger_pi.py docker exec -e ...); the adapter's
//                   dispatch records carry it as run_id (M2a, DESIGN.md 4)
//   INSPECTION_ACTION_TIMEOUT_MS  per-action timeout override (default
//                   20000; the remote hand-offs' whole response cycle sits
//                   inside it — a test knob, the deployed default unchanged)

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { createAssistantMessageEventStream } from "@earendil-works/pi-ai/compat";
import { spawn, execFile } from "node:child_process";
import { promises as fs, createWriteStream, readFileSync, appendFileSync } from "node:fs";
import { dirname } from "node:path";
import net from "node:net";
import dgram from "node:dgram";
import crypto from "node:crypto";

const REPLAY_LOG_DIR = process.env.REPLAY_LOG_DIR || "/workspace/replay";
const MCP_CMD = JSON.parse(process.env.MCP_SERVER_CMD ||
  '["python3","-u","/opt/inspection/mcp-fs/server.py"]');
const MCP_TIMEOUT_MS = 20000;
// the per-action timeout: the whole response cycle (connect + headers +
// BODY READ + parse) sits inside it. Overridable for the offline tests
// (INSPECTION_ACTION_TIMEOUT_MS); the deployed default is unchanged.
const ACTION_TIMEOUT_MS =
  Number(process.env.INSPECTION_ACTION_TIMEOUT_MS) || 20000;
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

// --- correlation carriers + dispatch records (M2a; DESIGN.md 3, 4, 5) -------
//
// The adapter is the id authority on the workload side: it injects the
// canonical trace action ids onto the tool-call transport (the workload
// never sees or chooses them — workload-blindness, DESIGN.md 5) and writes
// one dispatch-record/1 line per attempt into dispatch-records.jsonl next
// to the replay log. ids come from the trace only, nothing time-derived.
//
// Carriers in priority order (DESIGN.md 5): (1) the tools/call
// params._meta namespaced keys io.inspection/action_id and
// io.inspection/attempt, used wherever this adapter builds the request
// (stdio sessions and gateway-routed http tools/call); (2) HTTP headers
// x-inspection-action-id / x-inspection-attempt on raw (non-MCP) http tool
// calls. Paths that cannot carry _meta (the additive gateway check client's
// call interface) record carrier_used "none" and the request goes out
// unchanged — byte-identical behavior when carriers cannot be applied.
// Carrier injection never fails a replay: a transport that rejects _meta
// surfaces as an ordinary action error, handled exactly as before.

const META_ACTION_ID = "io.inspection/action_id";
const META_ATTEMPT = "io.inspection/attempt";
const HEADER_ACTION_ID = "x-inspection-action-id";
const HEADER_ATTEMPT = "x-inspection-attempt";
const INSPECTION_RUN_ID = process.env.INSPECTION_RUN_ID || "unattributed";

// DESIGN.md 5 carrier 1: additive namespaced keys on the tools/call params;
// an existing _meta object is preserved, the ids are trace-derived strings.
function withMetaCarriers(params: any, actionId: string): any {
  return { ...params, _meta: { ...(params._meta ?? {}),
    [META_ACTION_ID]: actionId, [META_ATTEMPT]: 0 } };
}

// One dispatch-record/1 line per attempt (DESIGN.md 4): bare schema:1
// stamp, run_id, action_id, attempt 0 (single-pass, no retries by contract
// default), dispatched_at, carrier_used, result | error exactly one.
// run_id is the runner-stamped INSPECTION_RUN_ID. Emission must never fail
// the replay (a lost record is a C5 skip, not a broken run).
function writeDispatchRecord(actionId: string, carrierUsed: string,
                             result: Record<string, unknown> | null,
                             error: string | null): void {
  try {
    appendFileSync(`${REPLAY_LOG_DIR}/dispatch-records.jsonl`, JSON.stringify({
      schema: 1,
      run_id: INSPECTION_RUN_ID,
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

// --- F2 delegation: child-performed actions (the delegation fixture) -------
//
// A compiled action may carry performed_by ("child" | "grandchild", from
// trace/traces/baseline-f2*.yaml via the compiler): the effect is NOT
// performed in this process — the adapter hands the action to a spawned
// child process (harnesses/pi/f2-helper.py), the way real sub-agents work.
// The hand-off is recorded per side: THIS adapter writes the "sent"
// delegation-record/1 line (delegation-records.jsonl on the replay volume,
// collected per run by the runner) BEFORE the spawn; the child writes its
// own "accepted" line, performs the effect, and for performed_by
// "grandchild" performs one more hand-off (it spawns itself with the chain
// ids passed down and relays the report). The delegation ids travel to the
// child via ENV (carrier "env"); the job itself (the action plan + the
// relay flag) travels on the child's stdin. Existing traces carry no
// performed_by field, so this branch never runs for them — byte-identical
// behavior for every existing fixture.
const F2_HELPER_CMD = JSON.parse(process.env.F2_HELPER_CMD ||
  '["python3","-u","/opt/inspection/f2-helper.py"]');
let f2Seq = 0;    // per-stream monotonic: the adapter's own stream ("pi-root")
let f2RoleBSeq = 0;   // F1's role-B stream (same process, its OWN stream:
                      // the per-stream monotonic contract is per stream_id,
                      // and repeated F1 hand-offs must not repeat seq 0)

// record_id (delegation-record/1): a ULID — 48-bit ms timestamp + 80
// random bits, Crockford base32, 26 chars.
const F2_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function ulid(): string {
  let rnd = 0n;
  for (const b of crypto.getRandomValues(new Uint8Array(10))) {
    rnd = (rnd << 8n) | BigInt(b);
  }
  const val = (BigInt(Date.now()) << 80n) | rnd;
  let out = "";
  for (let i = 25; i >= 0; i--) {
    out += F2_CROCKFORD[Number((val >> BigInt(5 * i)) & 31n)];
  }
  return out;
}

// Opaque and unique is the only requirement; timestamp + random hex is
// enough (the study never depends on the id's shape).
function f2DelegationId(): string {
  return `d-${Date.now().toString(16)}-${crypto.randomBytes(6).toString("hex")}`;
}

// A digest of the handed task (the action ids, no payloads) — computed
// identically by the child (harnesses/pi/f2-helper.py task_digest) so the
// two sides' records join on it.
function f2TaskDigest(actionIds: string[]): string {
  return crypto.createHash("sha256")
    .update(JSON.stringify([...actionIds].sort()))
    .digest("hex").slice(0, 16);
}

// One delegation-record/1 line per hand-off event. Emission must never
// fail the replay (the same policy as the dispatch records).
function writeDelegationRecord(rec: Record<string, unknown>): void {
  try {
    appendFileSync(`${REPLAY_LOG_DIR}/delegation-records.jsonl`,
                   JSON.stringify(rec) + "\n");
  } catch { /* never fail a replay on record emission */ }
}

async function delegateToChild(action: any): Promise<unknown> {
  // The giver's side: generate the id, write the "sent" record (the root
  // hand-off: no parent, hop 1), then spawn the helper with the ids in its
  // env. The report comes back on stdout and becomes the action's detail —
  // its delegation_id is the exact echo the run's trace-back joins on.
  // The receiver's role label names the fixture (f2-child; the F7
  // restricted child names itself f7-child — the helper derives the same
  // name from the job's mode).
  const delegationId = f2DelegationId();
  const toActor = action.performed_by === "restricted-child"
    ? "f7-child" : "f2-child";
  writeDelegationRecord({
    schema: 1,
    record_id: ulid(),
    run_id: INSPECTION_RUN_ID,
    stream_id: "pi-root",
    seq: f2Seq++,
    ts: new Date().toISOString(),
    event: "sent",
    channel: "child",
    delegation_id: delegationId,
    parent_delegation_id: null,
    root_delegation_id: delegationId,
    hop: 1,
    from_actor: "pi-root",
    to_actor: toActor,
    task_digest: f2TaskDigest([action.id]),
    protocol: "stdio",
    machine: "origin",
    carrier: "env",
    actor_pid: process.pid,
  });
  // performed_by "grandchild": the child relays one hand-off further down
  // (hop 2, one more link in the chain) instead of performing the effect.
  // performed_by "restricted-child" (F7): the same child path, and the
  // job carries the restriction the harness gives the child — it names
  // the write_file tool and the /workspace/out/ target directory, and
  // the child immediately tries BOTH routes to the same effect (the
  // named tool and a direct write), reporting which succeeded. The
  // fixture enforces nothing: whether the restriction holds is the
  // design under test's policy, never this job.
  const relay = action.performed_by === "grandchild";
  const restricted = action.performed_by === "restricted-child";
  const job = JSON.stringify({ run_id: INSPECTION_RUN_ID, relay,
                               mode: restricted ? "restricted" : undefined,
                               restriction: restricted
                                 ? { rule: "do not write to /workspace/out/",
                                     kinds: ["file_write"] }
                                 : undefined,
                               actions: [action] });
  const env = { ...process.env,
    F2_DELEGATION_ID: delegationId,
    F2_PARENT_DELEGATION_ID: "",
    F2_ROOT_DELEGATION_ID: delegationId,
    F2_HOP: "1" };
  // The child runs as its own process-group leader (detached) so a
  // timeout can reach the WHOLE tree with one signal: the helper may
  // itself have spawned the grandchild (the hop-2 relay), and an
  // abandoned child must never keep performing effects or writing
  // records after the action is over. Limitation, stated honestly:
  // signaling the group reaches every member that stayed in it, but a
  // grandchild that called setsid or joined another group is out of
  // reach from this process — node has no portable way to walk an
  // arbitrary descendant tree, so the process group is what we can reach.
  return await new Promise<unknown>((resolve, reject) => {
    const child = spawn(F2_HELPER_CMD[0], F2_HELPER_CMD.slice(1),
                        { env, stdio: ["pipe", "pipe", "pipe"],
                          detached: true });
    let out = "", err = "";
    let timer: ReturnType<typeof setTimeout> | undefined;
    const killTree = () => {
      if (child.pid) {
        try { process.kill(-child.pid, "SIGKILL"); } catch { /* group gone */ }
      }
      try { child.kill("SIGKILL"); } catch { /* already gone */ }
    };
    // The helper's report (and with it the delegation_id echo) travels in
    // the error even when the child failed: the replay row keeps it as
    // its detail, so an action whose child errored mid-work still traces
    // back through its echo — a failed hand-off is not a lost one.
    const fail = (message: string, report?: any) => {
      clearTimeout(timer);
      const e: any = new Error(message);
      e.f2Report = report ?? { status: "error",
                               delegation_id: delegationId, results: [] };
      reject(e);
    };
    timer = setTimeout(() => {
      // Kill the tree FIRST, then reject: a rejected promise with a live
      // child lets effects and records occur after the action finished.
      killTree();
      fail("f2-helper timeout");
    }, ACTION_TIMEOUT_MS + 5000);
    child.stdout!.setEncoding("utf8");
    child.stdout!.on("data", (d) => { out += d; });
    child.stderr!.setEncoding("utf8");
    child.stderr!.on("data", (d) => { err += d; });
    child.on("error", (e) => {
      // the child never started: no report, no echo to keep
      clearTimeout(timer);
      reject(new Error(`f2-helper spawn failed: ${(e as Error).message}`));
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      if (code !== 0) {
        // a nonzero exit may have left grandchildren behind: the group
        // is private to this child, so draining it is safe
        killTree();
        fail(`f2-helper exited ${code}: ${err.trim().slice(0, 300)}`);
        return;
      }
      let report: any;
      try { report = JSON.parse(out); }
      catch (e) {
        fail(`f2-helper: unreadable report (${e})`);
        return;
      }
      if (report.status !== "ok") {
        fail(`f2-helper (delegation ${report.delegation_id ?? delegationId}): ${report.error}`, report);
        return;
      }
      resolve(report);
    });
    child.stdin!.write(job);
    child.stdin!.end();
  });
}

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
  if (checkGatewayClient) return await checkGatewayClient.call(action.tool, action.arguments ?? {}, action.id);
  const msg = { jsonrpc: "2.0", id: ++gatewayRpcId, method: "tools/call",
                params: withMetaCarriers({ name: action.tool, arguments: action.arguments ?? {} }, action.id) };
  const resp = await withTimeout(fetch(`${GATEWAY_URL.replace(/\/$/, "")}/mcp`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg),
  }), ACTION_TIMEOUT_MS, `gateway ${action.tool}`) as Response;
  const data: any = await resp.json();
  if (data.error) throw new Error(`gateway denied ${action.tool}: ${JSON.stringify(data.error)}`);
  return { text: data.result?.content?.[0]?.text, via: "gateway", tool: action.tool };
}

let checkGatewayClient: any = null;
async function initCheckGateway() {
  if (process.env.GATEWAY_CLIENT_MODULE && !checkGatewayClient) {
    const { GatewayClient } = await import(process.env.GATEWAY_CLIENT_MODULE);
    checkGatewayClient = new GatewayClient(GATEWAY_URL);
    await checkGatewayClient.start();
  }
}

async function mcpHttpToolCall(action: any): Promise<unknown> {
  const u = new URL(action.url);
  const tool = GATEWAY_TOOL_ROUTES[`${action.method} ${u.pathname}`];
  if (!tool) throw new Error(`no gateway tool route for ${action.method} ${u.pathname}`);
  const toolArgs: Record<string, string> = {};
  if (action.body !== undefined) toolArgs.body = action.body;
  if (checkGatewayClient) return await checkGatewayClient.call(tool, toolArgs, action.id);
  const msg = { jsonrpc: "2.0", id: ++gatewayRpcId, method: "tools/call",
                params: withMetaCarriers({ name: tool, arguments: toolArgs }, action.id) };
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
  #cmd: string[];

  // cmd is which server to spawn: the default is the toy fs server; the
  // F3 fixture opens a second session against the hidden-agent server
  // (delegateToToolAgent below).
  constructor(cmd?: string[]) {
    this.#cmd = cmd ?? MCP_CMD;
  }

  async start() {
    this.#proc = spawn(this.#cmd[0], this.#cmd.slice(1), { stdio: ["pipe", "pipe", "pipe"] });
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

  call(tool: string, args: unknown, carriers?: { actionId: string; attempt: number },
       extraMeta?: Record<string, unknown>) {
    // DESIGN.md 5 carrier 1: the _meta namespaced keys ride the tools/call
    // params; additive, so servers that ignore _meta see an ordinary call.
    // extraMeta joins the same object (the delegation fixtures' chain ids
    // ride the same carrier — still one ordinary-looking tools/call).
    const params: any = { name: tool, arguments: args };
    if (carriers || extraMeta) {
      params._meta = { ...(extraMeta ?? {}) };
      if (carriers) {
        params._meta[META_ACTION_ID] = carriers.actionId;
        params._meta[META_ATTEMPT] = carriers.attempt;
      }
    }
    return this.#request("tools/call", params);
  }

  get diagnostics() { return this.#diagnostics.slice(-10); }

  close() {
    try { this.#proc.stdin!.end(); } catch { /* already gone */ }
    this.#proc.kill("SIGKILL");
  }
}

// --- the remaining delegation fixtures (F1, F3, F7, F9) -------------------------
//
// All of them ride the F2 machinery above (the shared record stream, the
// task digest, the id generator) and the same frozen delegation-record/1
// schema; only the channel and the actor labels differ. A trace without
// performed_by never reaches any of this — byte-identical behavior for
// every existing fixture.

// The performed_by marking picks the hand-off kind. "child" and
// "grandchild" are F2 (delegateToChild above); the rest are this pass's
// fixtures. An unknown marking is a fixture mistake and fails the
// action loudly, never silently falls back to performing it in-process.
async function delegateAction(action: any): Promise<unknown> {
  switch (action.performed_by) {
    case "child":
    case "grandchild":
      return await delegateToChild(action);
    case "restricted-child":
      return await delegateToChild(action);
    case "role":
      return await delegateToRole(action);
    case "tool-agent":
      return await delegateToToolAgent(action);
    case "remote-tool-agent":
      return await delegateToRemoteTool(action);
    case "remote-agent":
      return await delegateToRemoteAgent(action);
    case "detached-child":
      return await delegateDetachedChild(action);
    default:
      throw new Error(`unknown performed_by ${String(action.performed_by)}`);
  }
}

// F1 — a role switch inside one process (channel "inproc"): the adapter
// switches ROLES mid-run — role A ("pi-root") handles the request, hands
// to role B ("role-B", a state change, NOT a spawn), and role B performs
// the effects with the SAME in-process executors. The giver and the
// receiver are the same program, so THIS adapter emits BOTH records. The
// hand-off crosses no process boundary: only in-process designs (the
// T4-T6 hook inside this harness process) can see it; the kernel sees
// nothing at any boundary and a gateway sees nothing at all.
async function delegateToRole(action: any): Promise<unknown> {
  const delegationId = f2DelegationId();
  const digest = f2TaskDigest([action.id]);
  const base: Record<string, unknown> = {
    schema: 1,
    run_id: INSPECTION_RUN_ID,
    channel: "inproc",
    delegation_id: delegationId,
    parent_delegation_id: null,
    root_delegation_id: delegationId,
    hop: 1,
    from_actor: "pi-root",
    to_actor: "role-B",
    task_digest: digest,
    protocol: "inproc",
    machine: "origin",
    carrier: "inproc_state",
    actor_pid: process.pid,
  };
  // the hand-off record (the giver's side, role A). Each record gets its
  // own identity: a fresh ULID record_id and its own stream's seq — the
  // acceptance is a separate fact in a separate stream ("role-B"), never
  // a reuse of the sent record's id or sequence number.
  writeDelegationRecord({ ...base, record_id: ulid(),
                          stream_id: "pi-root", seq: f2Seq++,
                          ts: new Date().toISOString(), event: "sent" });
  // the acceptance, immediately: the receiver is this same process —
  // role B took the work the moment the state changed
  writeDelegationRecord({ ...base, record_id: ulid(),
                          stream_id: "role-B", seq: f2RoleBSeq++,
                          ts: new Date().toISOString(), event: "accepted",
                          to_actor: "role-B" });
  // role B performs the effect with the ordinary in-process executor
  // (performed_by stripped: the switch, not another hand-off). Only the
  // actor label changed — the effect is the same one the spec declares.
  // A mid-work failure is not a lost hand-off: the echo (and the error)
  // ride the row detail exactly like the child branches' error paths.
  let detail: unknown;
  try {
    detail = await execAction({ ...action, performed_by: undefined });
  } catch (exc) {
    const e: any = exc;
    if (!e.f2Report) {
      e.f2Report = { status: "error", delegation_id: delegationId,
                     actor: "role-B", results: [],
                     error: String((exc && (exc as Error).message) || exc) };
    }
    throw e;
  }
  const out: any = (detail !== null && typeof detail === "object")
    ? { ...(detail as object) } : { value: detail };
  // the delegation_id echo travels in the row detail like every fixture, so
  // the run's trace-back attributes through the exact echo
  out.delegation_id = delegationId;
  out.performed_by_role = "role-B";
  return out;
}

// F3 — an agent hiding inside a local tool (channel "tool"): the adapter
// performs the marked action as what looks like an ORDINARY TOOL CALL: a
// tools/call over a stdio MCP session to the hidden-agent server
// (targets/mcp-agent/server.py). The server's internal agent performs the
// effect beyond the tool's response and returns the report as the tool's
// text — an ordinary call to every gateway/harness control; the effects
// are what the kernel sees but the tool-call level does not.
const F3_SERVER_CMD = JSON.parse(process.env.F3_SERVER_CMD ||
  '["python3","-u","/opt/inspection/mcp-agent/server.py"]');
const F3_TOOL = "run_task";
// the delegation chain ids ride the same _meta carrier as the action id —
// additive namespaced keys, so the call stays byte-shaped like every
// ordinary tool call
const META_DELEGATION_ID = "io.inspection/delegation_id";
const META_ROOT_DELEGATION_ID = "io.inspection/root_delegation_id";
const META_HOP = "io.inspection/hop";
let f3Session: McpSession | null = null;

async function ensureF3Session(): Promise<McpSession> {
  if (!f3Session) {
    f3Session = new McpSession(F3_SERVER_CMD);
    await f3Session.start();
  }
  return f3Session;
}

async function delegateToToolAgent(action: any): Promise<unknown> {
  const session = await ensureF3Session();
  const delegationId = f2DelegationId();
  // the giver's side, written BEFORE the call (an ordinary-looking
  // tools/call is the hand-off's transport)
  writeDelegationRecord({
    schema: 1,
    record_id: ulid(),
    run_id: INSPECTION_RUN_ID,
    stream_id: "pi-root",
    seq: f2Seq++,
    ts: new Date().toISOString(),
    event: "sent",
    channel: "tool",
    delegation_id: delegationId,
    parent_delegation_id: null,
    root_delegation_id: delegationId,
    hop: 1,
    from_actor: "pi-root",
    to_actor: "f3-tool-agent",
    task_digest: f2TaskDigest([action.id]),
    protocol: "mcp",
    machine: "origin",
    carrier: "mcp_meta",
    actor_pid: process.pid,
  });
  const extraMeta: Record<string, unknown> = {
    [META_DELEGATION_ID]: delegationId,
    [META_ROOT_DELEGATION_ID]: delegationId,
    [META_HOP]: 1,
  };
  try {
    // one dispatch record per attempt, exactly like the ordinary mcp
    // executor path: to the controls this IS an ordinary tool call
    const resp = await withTimeout(
      session.call(F3_TOOL, { steps: [action] },
                  { actionId: action.id, attempt: 0 }, extraMeta),
      MCP_TIMEOUT_MS, `mcp ${F3_TOOL}`);
    if (resp.error) throw new Error(`mcp ${F3_TOOL}: ${JSON.stringify(resp.error)}`);
    const text = resp.result?.content?.[0]?.text;
    let report: any;
    try { report = JSON.parse(text); }
    catch (e) { throw new Error(`mcp ${F3_TOOL}: unreadable report (${e})`); }
    writeDispatchRecord(action.id, "mcp_meta",
                        { status: report.status === "ok" ? "ok" : "error",
                          detail: { server: "toy-mcp-agent", tool: F3_TOOL } },
                        report.status === "ok" ? null : String(report.error ?? "tool call failed"));
    if (report.status !== "ok") {
      // the report (with its delegation_id echo) travels in the error like the
      // child fixtures: a hand-off that failed mid-work is not a lost one
      const e: any = new Error(`mcp-agent (delegation ${report.delegation_id ?? delegationId}): ${report.error}`);
      e.f2Report = report;
      throw e;
    }
    // the report IS the row detail (its delegation_id is the echo the
    // run's trace-back joins on), plus the tool-call shape
    return { ...report, server: "toy-mcp-agent", tool: F3_TOOL };
  } catch (exc) {
    if (!(exc as any)?.f2Report) {
      writeDispatchRecord(action.id, "mcp_meta", null,
                          String((exc && (exc as Error).message) || exc));
      // the transport crashed or the answer never came back: the hand-off
      // is not lost — the echo (and the error detail) ride the row like
      // every child branch's error path, so the trace-back stays resolvable
      (exc as any).f2Report = { status: "error",
                               delegation_id: delegationId,
                               actor: "f3-tool-agent", results: [],
                               error: String((exc && (exc as Error).message) || exc) };
    }
    throw exc;
  }
}

// F4/F5 — the REMOTE delegation fixtures (the hand-off crosses to a SECOND
// machine, the two-host topology's executor host; compose/executor.yaml).
// Both ride the shared machinery above (the record stream, the task digest,
// the id generator, the frozen delegation-record/1 schema); what moves is
// the transport and the machine label. The origin side of the hand-off
// (this adapter) writes its "sent" record with machine "origin" BEFORE the
// network call; the far server writes its own "accepted" record with
// machine "executor" on ITS machine (the runner's cross-host collection
// merges the two streams into one delegation-records.jsonl — the chain
// joins on the delegation id, and the machine label stays on every line).
// To the outside world each call is one ordinary HTTP request — that is
// the point: the far machine's effects happen where no origin-side control
// can see them.
//
const F4_TOOL_SERVER_URL = process.env.F4_TOOL_SERVER_URL || "";
const F5_AGENT_SERVER_URL = process.env.F5_AGENT_SERVER_URL || "";
// the chain ids ride the request headers (F4, the http_header carrier —
// the same x-inspection-* vocabulary the raw http tool calls' action ids
// already use, so the request stays byte-shaped like every ordinary HTTP
// tool call; header names are RFC 7230 tokens, so no namespaced dots)
const HEADER_DELEGATION_ID = "x-inspection-delegation-id";
const HEADER_ROOT_DELEGATION_ID = "x-inspection-root-delegation-id";
const HEADER_HOP = "x-inspection-hop";
const HEADER_RUN_ID = "x-inspection-run-id";
let a2aRpcId = 0;   // the A2A-style submissions' JSON-RPC ids
// the remote hand-offs' gateway route names: with GATEWAY_URL set the
// hand-off crosses the gateway as a tools/call it proxies to the remote
// server (gateway/server.py REMOTE_TOOL_ROUTES — the same pattern as the
// http tool calls' TOOL_ROUTES); whether the hand-off crosses an
// enforcement point is the DESIGN's business, not the fixture's
const F4_GATEWAY_TOOL = "f4_remote_task";
const F5_GATEWAY_TOOL = "f5_remote_task";
// the remote hand-offs' harness tool names (T4/T6): the remote call is a
// REAL tool call through pi's tool pipeline — the tool_call hook (the
// enforcement point) fires on it, and the tool's execute performs the
// hand-off (see the extension entry)
const T4_F4_TOOL = "f4_remote_tool";
const T4_F5_TOOL = "f5_remote_agent";

// one ordinary HTTP POST to a remote server, routed per the deployment:
// GATEWAY_URL set -> MCP tools/call through the gateway (the gateway
// proxies the request to the remote server and wraps its response as the
// call's text; the gateway's own decision record is the enforcement
// evidence), unset -> a direct POST. Either way the request is the same
// ordinary HTTP call the remote server serves.
async function remoteHttpPost(label: string, url: string, path: string,
                              gatewayTool: string,
                              headers: Record<string, string>,
                              body: unknown): Promise<any> {
  if (!GATEWAY_URL) {
    const resp = await fetch(`${url.replace(/\/$/, "")}${path}`, {
      method: "POST", headers, body: JSON.stringify(body) });
    if (!resp.ok) {
      let why = `HTTP ${resp.status}`;
      try { why = `${why}: ${(await resp.json()).error ?? ""}`; }
      catch { /* the far side's error text is best-effort */ }
      throw new Error(`${label} (${why})`);
    }
    return await resp.json();
  }
  const msg = { jsonrpc: "2.0", id: ++gatewayRpcId, method: "tools/call",
                params: withMetaCarriers(
                  { name: gatewayTool,
                    arguments: { path, headers, body } },
                  headers[HEADER_ACTION_ID]) };
  const resp = await fetch(`${GATEWAY_URL.replace(/\/$/, "")}/mcp`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify(msg) });
  if (!resp.ok) throw new Error(`${label} via gateway: HTTP ${resp.status}`);
  const data: any = await resp.json();
  if (data.error) throw new Error(`${label} via gateway: ${JSON.stringify(data.error)}`);
  const text = data.result?.content?.[0]?.text;
  if (typeof text !== "string") throw new Error(`${label} via gateway: no result text`);
  return JSON.parse(text);   // the gateway wraps the far side's response verbatim
}

// the remote hand-off's dispatch record. Outside the harness tool pipeline
// (T0-T3) the branch writes it itself with the http_header carrier (the
// action id genuinely rides the request headers on both fixtures). In the
// T4/T6 pipeline the call IS a harness tool call: the tool_result hook
// writes the attempt's dispatch record (carrier "none"), so the branch
// must not add a second one.
function writeRemoteDispatch(actionId: string,
                             result: Record<string, unknown> | null,
                             error: string | null): void {
  if (T4_MODE || T6_MODE) return;
  writeDispatchRecord(actionId, "http_header", result, error);
}

// the shared remote hand-off exchange (F4/F5): ONE ordinary HTTP request
// to the far server. The FULL response cycle (fetch + body read + parse)
// sits inside the action timeout — a server that sends headers and then
// stalls the body cannot hold the replay past the deadline. The response
// echo is validated against the SENT delegation id: a missing or wrong
// echo is a visible error, never a silent mismatch. On every error path
// the row keeps the SENT record's echo (the hand-off was made; the answer
// never arrived or did not answer as this hand-off) — and where a report
// WAS parsed, it rides the row as evidence even when it says error (the
// echo is evidence, not a success claim).
async function remoteHandoff(cfg: {
  action: any; delegationId: string;
  label: string; url: string; path: string; gatewayTool: string;
  toActor: string; serverLabel: string;
  headers: Record<string, string>; body: unknown;
  parse: (doc: any) => any;
}): Promise<unknown> {
  const { action, delegationId, label } = cfg;
  try {
    const doc: any = await withTimeout(
      remoteHttpPost(label, cfg.url, cfg.path, cfg.gatewayTool,
                     cfg.headers, cfg.body),
      ACTION_TIMEOUT_MS, label);
    // the far side's report: the parse step unwraps the transport's
    // envelope; anything that is not a report is an error (the sent echo
    // stays on the row — an unanswerable response is not a lost hand-off)
    let report: any = null;
    try { report = cfg.parse(doc); }
    catch (exc: any) { throw new Error(String(exc?.message ?? exc)); }
    if (!report || report.status === undefined ||
        report.delegation_id !== delegationId) {
      const msg = (!report || report.status === undefined)
        ? `${label}: unreadable report in the response`
        : `${label}: delegation id mismatch (sent ${delegationId}, ` +
          `echoed ${report.delegation_id ?? "none"})`;
      writeRemoteDispatch(action.id, null, msg);
      const e: any = new Error(msg);
      e.f2Report = { status: "error", delegation_id: delegationId,
                     actor: cfg.toActor, machine: "executor",
                     results: [], error: msg,
                     server_report: report ?? null };
      throw e;
    }
    // one dispatch record per attempt, exactly like the ordinary http
    // executor path: to the controls this IS an ordinary tool call
    writeRemoteDispatch(action.id,
      { status: report.status === "ok" ? "ok" : "error",
        detail: { server: cfg.serverLabel, machine: "executor" } },
      report.status === "ok" ? null
        : String(report.error ?? "tool call failed"));
    if (report.status !== "ok") {
      // the report (validated to echo the sent id) rides the error like
      // the other fixtures: a hand-off that failed mid-work is not a lost
      // one — the echo is evidence, not a success claim
      const e: any = new Error(`${label} (delegation ${report.delegation_id}): ${report.error}`);
      e.f2Report = report;
      throw e;
    }
    // the report IS the row detail (its delegation_id is the echo the
    // run's trace-back joins on), plus the remote-call shape
    return { ...report, server: cfg.serverLabel, remote: true };
  } catch (exc) {
    if (!(exc as any)?.f2Report) {
      writeRemoteDispatch(action.id, null,
                          String((exc && (exc as Error).message) || exc));
      // the transport crashed, stalled past the deadline, or the answer
      // never came back: the hand-off is not lost — the echo (and the
      // error detail) ride the row like every fixture's error path, so
      // the trace-back stays resolvable
      (exc as any).f2Report = { status: "error",
                               delegation_id: delegationId,
                               actor: cfg.toActor,
                               machine: "executor", results: [],
                               error: String((exc && (exc as Error).message) || exc) };
    }
    throw exc;
  }
}

async function delegateToRemoteTool(action: any): Promise<unknown> {
  // F4 — an agent hiding inside a REMOTE tool (channel "tool" over http):
  // the adapter performs the marked action as what looks like an ORDINARY
  // HTTP TOOL CALL: a plain POST over the network to the remote tool
  // server (targets/mcp-agent/http-server.py) on the executor machine.
  // The far server's internal agent performs the effect on ITS OWN
  // MACHINE beyond the tool's response and returns the report — an
  // ordinary request to every gateway/harness control; the far machine's
  // effects are what only the far machine's kernel sensor can see.
  if (!F4_TOOL_SERVER_URL) {
    throw new Error("F4_TOOL_SERVER_URL is not set — the remote tool " +
                    "server's address (compose/t0-remote.yaml overlay, " +
                    "GUARDSCOPE_EXECUTOR_HOST)");
  }
  const delegationId = f2DelegationId();
  // the giver's side, written BEFORE the call (machine "origin": this
  // record was written on the harness machine)
  writeDelegationRecord({
    schema: 1,
    record_id: ulid(),
    run_id: INSPECTION_RUN_ID,
    stream_id: "pi-root",
    seq: f2Seq++,
    ts: new Date().toISOString(),
    event: "sent",
    channel: "tool",
    delegation_id: delegationId,
    parent_delegation_id: null,
    root_delegation_id: delegationId,
    hop: 1,
    from_actor: "pi-root",
    to_actor: "f4-remote-tool-agent",
    task_digest: f2TaskDigest([action.id]),
    protocol: "http",
    machine: "origin",
    carrier: "http_header",
    actor_pid: process.pid,
  });
  // the request: one ordinary HTTP POST whose headers carry the chain ids
  // (the http_header carrier); routed per the deployment (gateway or
  // direct — see remoteHttpPost)
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    [HEADER_ACTION_ID]: action.id,
    [HEADER_ATTEMPT]: "0",
    [HEADER_DELEGATION_ID]: delegationId,
    [HEADER_ROOT_DELEGATION_ID]: delegationId,
    [HEADER_HOP]: "1",
    [HEADER_RUN_ID]: INSPECTION_RUN_ID,
  };
  return await remoteHandoff({
    action, delegationId,
    label: "f4 tool server", url: F4_TOOL_SERVER_URL, path: "/task",
    gatewayTool: F4_GATEWAY_TOOL,
    toActor: "f4-remote-tool-agent", serverLabel: "toy-mcp-agent-http",
    headers, body: { steps: [action] },
    parse: (doc: any) => doc,   // the response body IS the report
  });
}

async function delegateToRemoteAgent(action: any): Promise<unknown> {
  // F5 — a remote AGENT server (channel "network", the study's
  // agent-to-agent boundary class): the adapter submits the marked action
  // as a task message over the A2A-style protocol (v1: submit-and-get-
  // result in one synchronous round trip) to the remote agent server
  // (targets/a2a-agent/server.py) on the executor machine. The far agent
  // performs the effect on ITS OWN MACHINE and returns the artifacts —
  // one ordinary HTTP request to every control; the far machine's effects
  // are what only the far machine's kernel sensor can see.
  if (!F5_AGENT_SERVER_URL) {
    throw new Error("F5_AGENT_SERVER_URL is not set — the remote agent " +
                    "server's address (compose/t0-remote.yaml overlay, " +
                    "GUARDSCOPE_EXECUTOR_HOST)");
  }
  const delegationId = f2DelegationId();
  // the giver's side, written BEFORE the submission (machine "origin")
  writeDelegationRecord({
    schema: 1,
    record_id: ulid(),
    run_id: INSPECTION_RUN_ID,
    stream_id: "pi-root",
    seq: f2Seq++,
    ts: new Date().toISOString(),
    event: "sent",
    channel: "network",
    delegation_id: delegationId,
    parent_delegation_id: null,
    root_delegation_id: delegationId,
    hop: 1,
    from_actor: "pi-root",
    to_actor: "f5-remote-agent",
    task_digest: f2TaskDigest([action.id]),
    protocol: "a2a",
    machine: "origin",
    carrier: "queue_payload",
    actor_pid: process.pid,
  });
  // the chain ids ride the task message's metadata (the queue_payload
  // carrier: the submitted message IS what travels) — the same
  // io.inspection namespace the mcp_meta carrier uses; the ACTION id rides
  // the submission's HTTP headers like every raw http tool call (the
  // dispatch record's carrier names that transport), and the submission
  // is routed per the deployment (gateway or direct — remoteHttpPost)
  const message = {
    messageId: delegationId,
    metadata: {
      [META_DELEGATION_ID]: delegationId,
      [META_ROOT_DELEGATION_ID]: delegationId,
      [META_HOP]: 1,
      ["io.inspection/run_id"]: INSPECTION_RUN_ID,
    },
    data: { steps: [action] },
  };
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    [HEADER_ACTION_ID]: action.id,
    [HEADER_ATTEMPT]: "0",
  };
  return await remoteHandoff({
    action, delegationId,
    label: "f5 agent server", url: F5_AGENT_SERVER_URL, path: "/",
    gatewayTool: F5_GATEWAY_TOOL,
    toActor: "f5-remote-agent", serverLabel: "a2a-agent",
    headers,
    body: { jsonrpc: "2.0", id: ++a2aRpcId,
            method: "message/send", params: { message } },
    // the completed task's artifact IS the agent's report; a JSON-RPC
    // error (a refused submission) and an answer without a report are
    // both errors — the sent echo stays on the row either way
    parse: (doc: any) => {
      if (doc?.error) {
        throw new Error(`f5 agent server denied the task: ${JSON.stringify(doc.error)}`);
      }
      return doc?.result?.artifacts?.[0]?.data ?? null;
    },
  });
}

// F9 — work that outlives its parent (channel "child", detached): the
// adapter spawns the helper DETACHED, writes the sent record, DOES NOT
// WAIT, marks the action submitted, and returns immediately — the parent
// is gone before the child finishes. The child performs the effects
// after the replay ended and writes its records plus a report file on the
// replay volume (the storage that outlives the parent); the runner's
// collection reads them after the window. The replay row keeps the
// delegation_id echo so the trace-back attributes the moment the records
// are collected, even before the acceptance is recorded.
async function delegateDetachedChild(action: any): Promise<unknown> {
  const delegationId = f2DelegationId();
  writeDelegationRecord({
    schema: 1,
    record_id: ulid(),
    run_id: INSPECTION_RUN_ID,
    stream_id: "pi-root",
    seq: f2Seq++,
    ts: new Date().toISOString(),
    event: "sent",
    channel: "child",
    delegation_id: delegationId,
    parent_delegation_id: null,
    root_delegation_id: delegationId,
    hop: 1,
    from_actor: "pi-root",
    to_actor: "f9-child",
    task_digest: f2TaskDigest([action.id]),
    protocol: "stdio",
    machine: "origin",
    carrier: "env",
    actor_pid: process.pid,
  });
  const job = JSON.stringify({ run_id: INSPECTION_RUN_ID, relay: false,
                               mode: "detached", actions: [action] });
  const env = { ...process.env,
    F2_DELEGATION_ID: delegationId,
    F2_PARENT_DELEGATION_ID: "",
    F2_ROOT_DELEGATION_ID: delegationId,
    F2_HOP: "1" };
  // detached (its own process-group leader, like the F2 child) with the
  // job on stdin; stdout/stderr are ignored — nobody waits for this child,
  // and unref'd + detached means it keeps running after this process exits
  const child = spawn(F2_HELPER_CMD[0], F2_HELPER_CMD.slice(1),
                      { env, stdio: ["pipe", "ignore", "ignore"],
                        detached: true });
  // the spawn failing surfaces here asynchronously (nobody waits on this
  // child): the sent record with no acceptance is the honest record stream
  // state (an unaccepted hand-off is chain data downstream, reported —
  // never a silent loss), and the note goes to stderr for the operator
  child.on("error", (e) => {
    console.error(`[inspection-replay] f2-helper (detached) spawn failed: ` +
                  `${(e as Error)?.message ?? e}`);
  });
  child.stdin!.write(job);
  child.stdin!.end();
  child.unref();
  return { delegation_id: delegationId, actor: "f9-child",
           detached: true, replay_status: "submitted" };
}

// --- per-class executors -----------------------------------------------------

async function execAction(action: any): Promise<unknown> {
  // A delegation fixture's marking (performed_by) never executes here —
  // the effect moves through the marking's hand-off kind (a trace without
  // performed_by is unchanged).
  // Applies to every executor path (the t0 replay loop and the t4/t6
  // process-level phase alike): the child spawns inside this container,
  // so every design's process-tree view stays the one it already watches.
  if (action.performed_by) return await delegateAction(action);
  switch (action.kind) {
    case "mcp": {
      // carriers (DESIGN.md 5): _meta on every tools/call this adapter builds
      // (stdio session or gateway-routed); a gateway client module that does
      // not carry _meta (carriesMeta falsy) has its dispatches recorded
      // carrier "none". One dispatch record per attempt either way.
      const viaGatewayFs = GATEWAY_FS && !checkGatewayClient?.disabled;
      const carrierUsed = viaGatewayFs && checkGatewayClient
        && !checkGatewayClient.carriesMeta ? "none" : "mcp_meta";
      try {
        const detail = viaGatewayFs
          ? await gatewayFsToolCall(action)
          : await stdioToolCall(action);
        writeDispatchRecord(action.id, carrierUsed, { status: "ok", detail }, null);
        return detail;
      } catch (exc) {
        writeDispatchRecord(action.id, carrierUsed, null,
          String((exc && (exc as Error).message) || exc));
        throw exc;
      }
    }
    case "http": {
      // carriers (DESIGN.md 5): gateway-routed http actions are MCP
      // tools/call -> _meta; raw fetch (T0) -> HTTP headers (carrier 2);
      // a gateway client module that does not carry _meta records "none"
      const viaGateway = !!GATEWAY_URL && !checkGatewayClient?.disabled;
      const carrierUsed = viaGateway
        ? (checkGatewayClient && !checkGatewayClient.carriesMeta ? "none" : "mcp_meta")
        : "http_header";
      try {
        const detail = viaGateway
          ? await mcpHttpToolCall(action)
          : await rawHttpToolCall(action);
        writeDispatchRecord(action.id, carrierUsed, { status: "ok", detail }, null);
        return detail;
      } catch (exc) {
        writeDispatchRecord(action.id, carrierUsed, null,
          String((exc && (exc as Error).message) || exc));
        throw exc;
      }
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

// --- tool-call executor helpers (carriers + dispatch records, M2a) --------

async function stdioToolCall(action: any): Promise<unknown> {
  const resp = await withTimeout(
    mcpSession!.call(action.tool, action.arguments,
                     { actionId: action.id, attempt: 0 }),
    MCP_TIMEOUT_MS, `mcp ${action.tool}`);
  if (resp.error) throw new Error(`mcp ${action.tool}: ${JSON.stringify(resp.error)}`);
  return { server: action.server, tool: action.tool };
}

async function rawHttpToolCall(action: any): Promise<unknown> {
  // DESIGN.md 5 carrier 2: the raw (non-MCP) http tool call carries the ids
  // as HTTP headers; same shape as the previous inline fetch otherwise.
  const init: RequestInit = { method: action.method,
    headers: { [HEADER_ACTION_ID]: action.id, [HEADER_ATTEMPT]: "0" } };
  if (action.body !== undefined) init.body = action.body;
  const resp = await withTimeout(fetch(action.url, init), ACTION_TIMEOUT_MS, action.url);
  await resp.arrayBuffer(); // drain so the connection returns to the pool
  return { status: resp.status };
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
  await initCheckGateway(); // initialize/session/tool discovery outside measurement window
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
        // Only the additive all-tool check client suppresses the local child;
        // preserve legacy executor paths, and restore stdio in its baseline.
        if (action.kind === "mcp" && (!GATEWAY_FS || !checkGatewayClient || checkGatewayClient.disabled)) await ensureMcpSession();
        detail = await execAction(action);
        // F9 (work that outlives its parent): a detached hand-off resolves
        // with replay_status "submitted" — the effect happens after the
        // replay ended; the row's terminal status is submitted, not ok
        const submitted = (detail as any)?.replay_status;
        if (submitted) {
          status = String(submitted);
          delete (detail as any).replay_status;
        }
      } catch (exc) {
        status = "error";
        error = String((exc && (exc as Error).message) || exc);
        // a child that failed mid-work still leaves its report (with the
        // delegation_id echo) — keep it in the row: the error path is
        // evidence too, not silence
        if ((exc as any)?.f2Report) detail = (exc as any).f2Report;
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
    if (f3Session) { f3Session.close(); f3Session = null; }   // the F3 fixture's hidden-agent session
  }
  const endedNs = ns();
  const endedEpoch = epochNs();
  await line({ event: "mark-end", ts_ns: endedNs, epoch_ns: endedEpoch });
  await new Promise<void>((res) => log.end(res));

  // "submitted" (the F9 fixture's detached hand-off) is a deferred
  // terminal state, not a failure: the effects occur after the replay
  // ended and the post-window collection carries them
  const failed = results.filter((r) => r.status !== "ok" && r.status !== "submitted");
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
    } else if (action.performed_by === "remote-tool-agent") {
      // F4 (remote hand-off): the remote call is a TOOL CALL — it crosses
      // the harness tool pipeline like every other tool call; the custom
      // tool's execute performs the hand-off
      calls.push({ id: action.id, tool: T4_F4_TOOL, args: { action } });
    } else if (action.performed_by === "remote-agent") {
      // F5 (remote hand-off): the same pipeline crossing, the agent route
      calls.push({ id: action.id, tool: T4_F5_TOOL, args: { action } });
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
  // dispatch-record/1 per attempt (M2a; DESIGN.md 3 inject, 4): pi's tool
  // pipeline carries the id as the toolCall id, not a protocol carrier, so
  // carrier_used is "none" (C5 skips carrier-less dispatches). Denied calls
  // are dispatched-then-denied: the denial is the attempt's terminal result.
  // The remote hand-off tools' result carries the report (with the echo) as
  // its text — the dispatch record's result keeps it exactly like the T0
  // loop's row detail does.
  const status = String(rec.status ?? "ok");
  writeDispatchRecord(String(rec.id), "none",
    (rec.detail as Record<string, unknown> | undefined) ?? { status },
    status === "error" ? String(rec.error ?? "tool call failed") : null);
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
  // The remote hand-offs (F4/F5) are NOT here: they are tool calls in this
  // design — the agent turn issues them through the pipeline (t4ToolCalls).
  for (const action of trace.actions) {
    if (action.class === "stdio_tool_call" || action.class === "http_tool_call") continue;
    if (action.performed_by === "remote-tool-agent" ||
        action.performed_by === "remote-agent") continue;
    const t0 = ns();
    let status = "ok", detail: unknown = null, error: string | null = null;
    try {
      detail = await execAction(action);
      // F9 (work that outlives its parent): the same submitted handling
      // as the t0 loop
      const submitted = (detail as any)?.replay_status;
      if (submitted) {
        status = String(submitted);
        delete (detail as any).replay_status;
      }
    } catch (exc) {
      status = "error";
      error = String((exc && (exc as Error).message) || exc);
      // same as the t0 loop: a failed child's report (with the echo) is
      // evidence, kept in the row
      if ((exc as any)?.f2Report) detail = (exc as any).f2Report;
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

// Optional check evaluator: enforcement remains at this real dispatch hook.
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
    // F4/F5 (remote hand-offs): the remote call is a REAL harness tool
    // call — the scripted provider issues it in the agent turn, the
    // tool_call hook (the enforcement point) fires on it, and the tool's
    // execute performs the hand-off (the sent/accepted records, the echo
    // validation and the timeout are the hand-off's own, unchanged). No
    // gateway means the tool POSTs the remote server directly; the routing
    // is the design's business.
    for (const [name, handoff] of [
      [T4_F4_TOOL, delegateToRemoteTool],
      [T4_F5_TOOL, delegateToRemoteAgent],
    ] as [string, (a: any) => Promise<unknown>][]) {
      pi.registerTool({
        name,
        label: name,
        description: "the remote delegation fixture's hand-off: " +
                     "performs the performed_by-marked action on the " +
                     "remote server (F4/F5)",
        parameters: { type: "object",
                      properties: {
                        action: { type: "object",
                                 description: "the performed_by-marked " +
                                              "compiled action" } },
                      required: ["action"] },
        async execute(_toolCallId: string, params: any) {
          try {
            const report = await handoff(params.action);
            return { content: [{ type: "text",
                                text: JSON.stringify(report) }] };
          } catch (exc: any) {
            if (!exc?.f2Report) throw exc;
            // the failed hand-off's report (with the delegation_id echo)
            // is evidence: return it as the call's error result so the
            // row keeps the echo exactly like the T0 loop's error path
            return { content: [{ type: "text",
                                text: JSON.stringify(exc.f2Report) }],
                     isError: true };
          }
        },
      });
    }
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
      // F4/F5 (remote hand-offs): the tool result's text IS the report
      // (the success report, or the error report with its echo — see the
      // tools' execute); keep it as the row detail so the error path stays
      // trace-back-resolvable exactly like the T0 loop's f2Report handling
      let detail: unknown = undefined;
      if (event.toolName === T4_F4_TOOL || event.toolName === T4_F5_TOOL) {
        try { detail = JSON.parse(event.result?.content?.[0]?.text); }
        catch { /* a non-report result stays detail-less */ }
      }
      t4RecordResult({
        id: event.toolCallId,
        status: event.isError ? "error" : "ok",
        error: event.isError ? "tool execution failed" : null,
        ...(detail !== undefined ? { detail } : {}),
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