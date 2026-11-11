// The runner-issued gateway readiness probe (framework/contracts.py
// READINESS_TOOL convention; DESIGN.md 3 ready(): readiness must PROVE
// enforcement works). The runner docker-execs this once, BEFORE the
// measurement window opens, when the bound control's recipe declares
// readiness (plugins/<control>/collect.yaml); the deployed config carries a
// dedicated deny rule for the reserved tool, so the probe's single tools/call
// must be refused. The probe carries no correlation ids (runner plumbing,
// not workload traffic) and reports the outcome as JSON on stdout; the
// runner gates the run on this report AND on the deny decision record in
// the collected stream.
//
//   node /opt/inspection/adapter/readiness-probe.mjs [tool]

import { GatewayClient, READINESS_TOOL } from "./streamable-mcp-client.mjs";

const tool = process.argv[2] ?? READINESS_TOOL;
const url = process.env.GATEWAY_URL;
const report = { tool, denied: false, status: null, detail: null,
                 prober: { kind: "pi-adapter-readiness-probe" } };

if (!url) {
  report.detail = "no GATEWAY_URL in the environment";
  console.log(JSON.stringify(report));
  process.exit(0);
}

try {
  const client = new GatewayClient(url);
  await client.start();
  try {
    // NO correlation carriers on the readiness call (runner plumbing, not
    // workload traffic: a decision record echoing a carrier id no dispatch
    // record carried is a C5 fabrication finding); rpc() throws on the
    // expected refusal — 403 (agentgateway's authorization failure) or a
    // JSON-RPC error (the v0 gateway's shape)
    await client.rpc("tools/call", { name: tool, arguments: {} },
                     ++client.nextId);
    report.detail = "the gateway ALLOWED the readiness call";
  } catch (exc) {
    const status = exc.status ?? null;
    // denied = refused at HTTP level (agentgateway's 403) or as a
    // JSON-RPC error (the v0 gateway's shape); anything else is a
    // transport failure and is reported honestly (never a deny)
    const rpcError = /gateway RPC error/.test(String(exc.message));
    report.status = status;
    report.denied = (status !== null && status >= 400) || rpcError;
    report.detail = String(exc.message);
  }
} catch (exc) {
  report.detail = `probe failed: ${String(exc.message ?? exc)}`;
}
console.log(JSON.stringify(report));
