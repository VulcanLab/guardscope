"""The runner-issued gateway readiness probe (framework/contracts.py
READINESS_TOOL convention; DESIGN.md 3 ready(): readiness must PROVE that
enforcement works, not just that the container is running).

One tools/call for the framework-reserved tool name the deployed config's
dedicated deny rule must refuse — run PRE-WINDOW by the runner, exactly one
per run, from inside the topology (the probe must reach the gateway the way
the harness does: GATEWAY_URL, the fixture's internal network). The probe
carries NO correlation ids: it is runner plumbing, not workload traffic
(a decision record with action_id null is workload-external by definition,
DESIGN.md 5).

The probe reports what happened as JSON on stdout (exit 0 either way — the
RUNNER decides from the report AND verifies the deny decision record in the
collected stream; the probe itself only proves the request crossed the
enforcement point and was refused):

  {"denied": true|false, "status": <http status>, "detail": "..."}

  denied is true when the gateway refused the call: HTTP >= 400
  (agentgateway's authorization failure, a 403) or a JSON-RPC error object
  (the v0 AGT gateway's denial shape).

Usage (the runner docker-execs this into the harness container):
  python3 -m mock_harness.gateway_probe --tool __readiness_check__
"""

from __future__ import annotations

import argparse
import json
import os

from mock_harness import originators
from framework.contracts import READINESS_TOOL
from framework.version import __version__


def probe(gateway_url: str, tool: str) -> dict:
    """One readiness tools/call through a one-shot gateway session."""
    session = originators.GatewaySession(gateway_url)
    session.start()
    try:
        status, row = session.tools_call(tool, {})
    finally:
        session.close()
    denied = status >= 400 or bool(row.get("error"))
    return {
        "tool": tool,
        "denied": denied,
        "status": status,
        "detail": json.dumps(row.get("error") or row.get("result"),
                             sort_keys=True),
        "prober": {"kind": "mock-harness-gateway-probe",
                   "version": __version__},
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Issue one runner readiness tools/call through the "
                    "gateway and report the outcome as JSON (the runner "
                    "gates the run on it and on the deny decision record).")
    ap.add_argument("--tool", default=READINESS_TOOL,
                    help="the reserved readiness tool the deployed config "
                         "must deny (default: the framework's READINESS_TOOL)")
    ap.add_argument("--gateway-url", default=None,
                    help="the gateway's base URL (default: env GATEWAY_URL)")
    args = ap.parse_args(argv)
    url = args.gateway_url or os.environ.get("GATEWAY_URL")
    if not url:
        print("gateway probe: no GATEWAY_URL (env or --gateway-url)",
              file=__import__("sys").stderr)
        return 2
    try:
        report = probe(url, args.tool)
    except Exception as exc:  # noqa: BLE001 — the report is data, never a crash
        report = {"tool": args.tool, "denied": False, "status": None,
                  "detail": f"probe failed: {exc}"}
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
