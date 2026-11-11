#!/usr/bin/env python3
"""The live L2 correlation fidelity check for the agentgateway binding
(skypilot/, run ON the instance against the acceptance topology, still up,
with the checkout venv). framework/fidelity.py's formal check wired live:

  issuer(transport, action_id, attempt) — one marked tools/call through the
    LIVE gateway (the binding's streamable-HTTP MCP protocol: initialize,
    Mcp-Session-Id, Accept: application/json, text/event-stream), run
    inside the binding's collector container (python:3.12-alpine on the
    slot's network — the only in-network stdlib-python handle). Transport
    "mcp_meta" injects the params._meta namespaced carriers (DESIGN.md 5
    carrier 1), "http_header" sets the x-inspection-* headers (carrier 2).

  collector() — the vendor rows the control emitted since the call (cat'd
    from the binding's collector container, windowed by capture clock),
    translated by the binding's shim into decision-record/1 — the same
    record path the runs consume.

Then run_fidelity_check() asserts the marked (action_id, attempt) appears
in the emitted record per transport and reports per-transport capability
flags. Per the campaign brief, publish_fidelity_report() writes
plugins/agentgateway/fidelity.json ONLY when the check passes (--publish
flag; the manifest's echoes_meta/echoes_header stay false otherwise).

The raw vendor rows are ALSO inspected for the marked ids (evidence that
the control's own output retains the carrier even when the binding's
reader-side mapping does not surface it — reported either way, never
silently).

Usage:
  fidelity-agentgateway.py --collector t1-agentgateway-trace \
      --checkout ~/guardscope --out fidelity-check.json [--publish]
"""

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ISSUER_SRC = r'''
import json, os, urllib.request, urllib.error

url = os.environ["GATEWAY_URL"].rstrip("/") + "/mcp"
transport = os.environ["TRANSPORT"]
action_id = os.environ["ACTION_ID"]
attempt = int(os.environ["ATTEMPT"])

def post(payload, sid=None, extra=None):
    headers = {"Content-Type": "application/json",
               "Accept": "application/json, text/event-stream"}
    if sid:
        headers["Mcp-Session-Id"] = sid
    if extra:
        headers.update(extra)
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers=headers, method="POST")
    try:
        return urllib.request.urlopen(req, timeout=30)
    except urllib.error.HTTPError as exc:
        return exc            # a denial is a decision, never a transport error

def decode(body, ctype, rid):
    if "text/event-stream" not in ctype:
        return json.loads(body)
    for frame in body.replace("\r\n", "\n").split("\n\n"):
        data = "\n".join(l[5:].lstrip() for l in frame.split("\n")
                         if l.startswith("data:"))
        if data:
            row = json.loads(data)
            if row.get("id") == rid:
                return row
    raise RuntimeError(f"no correlated MCP response (id {rid}) in SSE stream")

report = {"transport": transport, "action_id": action_id,
          "attempt": attempt, "status": None, "ok": False, "detail": None}
try:
    r = post({"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                         "clientInfo": {"name": "inspection-fidelity",
                                        "version": "0.1"}}})
    report["init_status"] = getattr(r, "code", None) or r.status
    sid = r.headers.get("Mcp-Session-Id")
    row = decode(r.read().decode(), r.headers.get("Content-Type") or "", 1)
    if row.get("error"):
        raise RuntimeError(f"initialize error: {row['error']}")
    post({"jsonrpc": "2.0", "method": "notifications/initialized",
          "params": {}}, sid)

    params = {"name": "get_health", "arguments": {}}
    headers = None
    if transport == "mcp_meta":
        params["_meta"] = {"io.inspection/action_id": action_id,
                           "io.inspection/attempt": attempt}
    elif transport == "http_header":
        headers = {"x-inspection-action-id": action_id,
                   "x-inspection-attempt": str(attempt)}
    else:
        raise RuntimeError(f"unknown transport {transport!r}")
    r2 = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
               "params": params}, sid, headers)
    report["status"] = getattr(r2, "code", None) or r2.status
    body = r2.read().decode()
    if report["status"] >= 400:
        report["detail"] = f"HTTP {report['status']}: {body[:200]}"
    else:
        row2 = decode(body, r2.headers.get("Content-Type") or "", 2)
        result = row2.get("result") or {}
        report["detail"] = (f"tools/call result isError="
                            f"{result.get('isError')}")
    report["ok"] = True
except Exception as exc:
    report["detail"] = f"{type(exc).__name__}: {exc}"
print(json.dumps(report))
'''


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--collector", required=True,
                    help="the binding's collector container (on the slot network)")
    ap.add_argument("--checkout", required=True)
    ap.add_argument("--out", required=True, help="report JSON path")
    ap.add_argument("--publish", action="store_true",
                    help="publish plugins/agentgateway/fidelity.json when "
                         "the check passes")
    args = ap.parse_args()

    checkout = Path(args.checkout).resolve()
    sys.path.insert(0, str(checkout))
    from framework.fidelity import (publish_fidelity_report,
                                    run_fidelity_check)

    def vendor_rows():
        p = subprocess.run(["docker", "exec", args.collector, "cat",
                            "/var/log/gateway/agentgateway-trace.jsonl"],
                           capture_output=True, text=True, check=False)
        return [l for l in p.stdout.splitlines() if l.strip()]

    def issuer(transport, action_id, attempt):
        env = ["-e", f"TRANSPORT={transport}",
               "-e", f"ACTION_ID={action_id}",
               "-e", f"ATTEMPT={attempt}",
               "-e", "GATEWAY_URL=http://gateway:8090"]
        p = subprocess.run(["docker", "exec", "-i", *env, args.collector,
                            "python3", "-"], input=ISSUER_SRC,
                           capture_output=True, text=True, timeout=120)
        if p.returncode != 0:
            raise RuntimeError(f"issuer failed ({transport}): {p.stderr}")
        report = json.loads(p.stdout.strip().splitlines()[-1])
        if not report.get("ok"):
            raise RuntimeError(f"issuer transport error ({transport}): "
                               f"{report}")
        return report

    def collector():
        # records the control emitted since the (just-issued) call: rows
        # with a capture clock at/after the marked call's dispatch, run
        # through the binding's shim — the same record path the runs consume
        time.sleep(2.0)   # vendor-log flush grace (the runner's own rule)
        floor = time.time_ns() - int(3e9)   # the call's dispatch window
        rows = [l for l in vendor_rows()
                if (json.loads(l).get("received_epoch_ns") or 0) >= floor]
        with tempfile.TemporaryDirectory() as td:
            vendor = Path(td) / "vendor.jsonl"
            out = Path(td) / "records.jsonl"
            vendor.write_text("\n".join(rows) + ("\n" if rows else ""),
                              encoding="utf-8")
            p = subprocess.run([sys.executable,
                                str(checkout / "plugins/agentgateway/shim/translate.py"),
                                "--vendor-log", str(vendor),
                                "--out", str(out), "--run-id", "fidelity",
                                "--policy-file",
                                str(checkout / "plugins/agentgateway/config/t1-allow-all.json")],
                               capture_output=True, text=True)
            if p.returncode != 0:
                raise RuntimeError(f"shim failed: {p.stderr}")
            return [json.loads(l) for l in out.read_text().splitlines()
                    if l.strip()]

    issuer_reports = {}
    orig_run = run_fidelity_check

    def traced_issuer(transport, action_id, attempt):
        rep = issuer(transport, action_id, attempt)
        issuer_reports[transport] = rep
        return rep

    # the formal check: both carriers (DESIGN.md 5 carriers 1 and 2)
    report = run_fidelity_check(traced_issuer, collector, attempt=0)

    # raw-row evidence: the control's own output retains the marked ids?
    raw = vendor_rows()
    raw_evidence = {}
    for transport in report["per_transport"]:
        marker = f"fidelity-check:{transport}"
        hits = [l for l in raw if marker in l]
        raw_evidence[transport] = {
            "raw_rows_carrying_marker": len(hits),
            "in_headers": sum(1 for h in hits if "x-inspection-action-id" in h),
            "in_body": sum(1 for h in hits if '"_meta"' in h),
        }
    doc = {"fidelity_check": report,
           "issuer_reports": issuer_reports,
           "raw_vendor_row_evidence": raw_evidence,
           "collector": args.collector}
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=1, sort_keys=True) + "\n",
                   encoding="utf-8")

    print(json.dumps({"status": report["status"],
                      "preserves_meta": report["preserves_meta"],
                      "preserves_header": report["preserves_header"],
                      "per_transport": {t: {
                          "result": d["result"],
                          "records_collected": d["records_collected"],
                          "records_echoing": d["records_echoing"]}
                          for t, d in report["per_transport"].items()},
                      "raw_evidence": raw_evidence}, indent=1))
    if report["status"] == "pass" and args.publish:
        path = publish_fidelity_report("agentgateway", report,
                                        plugins_dir=checkout / "plugins")
        print(f"PUBLISHED: {path}")
    elif report["status"] != "pass":
        print("NOT PUBLISHED (the check did not pass; the manifest's "
              "echoes_meta/echoes_header stay false)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
