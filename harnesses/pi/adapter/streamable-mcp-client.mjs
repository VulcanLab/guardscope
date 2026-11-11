// Streamable-HTTP MCP gateway client for the pi adapter's
// GATEWAY_CLIENT_MODULE hook (replay.ts initCheckGateway). Ported from the
// pre-guardscope agentgateway-t1 probe's transport.mjs (read-only
// reference: realtime-control-coverage/code/probes/agentgateway-t1/
// transport.mjs), which drove agentgateway v1.5.0 live:
//
//  - every POST carries Accept: application/json, text/event-stream
//    (agentgateway v1.5.0's handle_post answers 406 without it; the v0 AGT
//    gateway ignores the header);
//  - the frontend is STATEFUL: initialize once, then carry the
//    Mcp-Session-Id the initialize response returned on every request
//    (agentgateway rejects session-less non-initialize requests; the v0
//    gateway ignores the header);
//  - responses may arrive SSE-framed (text/event-stream data: frames) or
//    as plain JSON — decoded by Content-Type (decodeRpc).
//
// The call interface carries the DESIGN.md 5 correlation carriers
// (params._meta io.inspection/action_id + attempt), so dispatches made
// through this client use carrier "mcp_meta" exactly like the adapter's
// built-in gateway route (replay.ts reads the carriesMeta property).

export const META_ACTION_ID = "io.inspection/action_id";
export const META_ATTEMPT = "io.inspection/attempt";
export const READINESS_TOOL = "__readiness_check__";

export function decodeRpc(body, contentType, id) {
  // plain JSON (the v0 gateway's shape) or the SSE framing agentgateway
  // answers with: the data: frame whose JSON-RPC id matches the request
  if (!contentType.includes("text/event-stream")) {
    const row = JSON.parse(body);
    if (row.id !== id) throw new Error(`MCP response id mismatch (${row.id} != ${id})`);
    return row;
  }
  for (const frame of body.replace(/\r\n/g, "\n").split("\n\n")) {
    const data = frame.split("\n").filter((l) => l.startsWith("data:"))
      .map((l) => l.slice(5).trimStart()).join("\n");
    if (!data) continue;
    const row = JSON.parse(data);
    if (row.id === id) return row;
  }
  throw new Error(`no correlated MCP response (id ${id}) in SSE stream`);
}

export class GatewayClient {
  carriesMeta = true;   // the dispatch records label these calls mcp_meta
  disabled = false;     // the adapter's suppression hook stays unused here
  url; fetcher; session = null; nextId = 0;

  constructor(url, fetcher = fetch) {
    this.url = url.replace(/\/$/, "") + "/mcp";
    this.fetcher = fetcher;
  }

  async rpc(method, params, id) {
    // Close each connection: pre-window discovery must not consume all of
    // the canonical window's connect evidence. Multiplicity stays in [1,N].
    const headers = { "Content-Type": "application/json",
                      Accept: "application/json, text/event-stream" };
    if (this.session) headers["Mcp-Session-Id"] = this.session;
    const body = JSON.stringify({ jsonrpc: "2.0",
                                  ...(id !== undefined ? { id } : {}),
                                  method, params });
    let response;
    try {
      response = await this.fetcher(this.url, {
        method: "POST", headers, body,
        signal: AbortSignal.timeout(20000),
      });
    } catch (exc) {
      throw new Error(`gateway ${method}: ${String((exc && exc.message) || exc)}`);
    }
    const sid = response.headers.get("Mcp-Session-Id");
    if (sid) this.session = sid;
    const text = await response.text();
    if (response.status >= 400) {
      // a denial is a decision, never a transport error: surface the
      // refusal with its status and body
      const err = new Error(`gateway HTTP ${response.status}: ${text}`);
      err.status = response.status;
      throw err;
    }
    if (id === undefined) return null;
    const row = decodeRpc(text, response.headers.get("Content-Type")
      ?? "application/json", id);
    if (row.error) throw new Error(`gateway RPC error: ${JSON.stringify(row.error)}`);
    return row.result;
  }

  async start() {
    const init = await this.rpc("initialize", {
      protocolVersion: "2025-06-18", capabilities: {},
      clientInfo: { name: "inspection-replay", version: "0.2.0" },
    }, ++this.nextId);
    if (!init) throw new Error("MCP initialize failed: no result");
    await this.rpc("notifications/initialized", {});
  }

  async call(tool, args, actionId) {
    // the params._meta correlation carriers (DESIGN.md 5 carrier 1), the
    // same injection the adapter's built-in route does
    const params = { name: tool, arguments: args ?? {},
                     _meta: { [META_ACTION_ID]: actionId,
                              [META_ATTEMPT]: 0 } };
    const result = await this.rpc("tools/call", params, ++this.nextId);
    if (result.isError) throw new Error(`MCP tool error: ${JSON.stringify(result)}`);
    const text = result.content?.[0]?.text;
    // the gateway wraps the endpoint's JSON payload in the result text
    // (the mcpHttpToolCall contract); a non-JSON text is carried verbatim.
    // The raw text stays on the return so the fs-tool call site (which
    // expects {text, via, tool}) works through the same client.
    let payload;
    try { payload = JSON.parse(text); } catch { payload = { text }; }
    return { ...payload, text, via: "gateway", tool };
  }
}
