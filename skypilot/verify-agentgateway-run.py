#!/usr/bin/env python3
"""Per-run verification for the agentgateway campaign (skypilot/, run ON the
instance with the checkout venv). Checks one run's artifacts against the
expected T1 agentgateway acceptance shape — not just pass/fail but the
checker-risk items themselves:

  - the readiness gate: the probe report (refused) AND the deny record for
    the reserved tool in the translated stream, with the probe's own
    decision timestamp BEFORE the kernel/capture window opened (the probe's
    pre-window connect must stay outside the window);
  - the collector's .ready marker preceding the window (and so the first
    action);
  - the run-scoped vendor rows: the scoped count, and the excluded count
    (rows of earlier runs retained on the slot volume) — for the acceptance
    run, equality with the warmup run's scoped count is asserted (the
    volume accumulated exactly the warmup's rows between the two probes);
  - the counts: 4 checked-allowed (a011-a014 http_tool_call) + 11 bypassed,
    C1-C6 pass, R1-R5 pass, 0 findings, coverage_consistent (acceptance);
  - the proxy-egress attribution risk: the R3 per-class kernel observation
    counts and R4 leftover accounting are printed (the harness->gateway
    :8090 connect is the inspected action's kernel evidence; the gateway's
    own upstream connects stay outside the direct_network class by the
    v6 mapping rule).

Warmup runs (--warmup): the leftover check (R4) fails by design on the first
live run of the design; only the counts, the readiness gate, and the
scoping are asserted there.

Usage:
  verify-agentgateway-run.py <run-dir> --execution <execution.json> \
      --ready-ns <ns> [--excluded <n>] [--expect-excluded <n>] [--warmup]
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

EXPECTED_COUNTS = {"checked-allowed": 4, "bypassed": 11,
                   "checked-denied": 0, "prevented": 0, "indeterminate": 0}
INSPECTED = ["a011", "a012", "a013", "a014"]


def fail(msg):
    print(f"VERIFY FAIL: {msg}")
    return 1


def ts_to_ns(ts):
    dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    return int(dt.timestamp() * 1_000_000_000)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("run_dir")
    ap.add_argument("--execution", required=True)
    ap.add_argument("--ready-ns", type=int, required=True)
    ap.add_argument("--excluded", type=int, default=None)
    ap.add_argument("--expect-excluded", type=int, default=None)
    ap.add_argument("--warmup", action="store_true")
    args = ap.parse_args()

    rd = Path(args.run_dir)
    errors = []

    def check(cond, msg):
        if cond:
            print(f"ok   {msg}")
        else:
            errors.append(msg)
            print(f"FAIL {msg}")

    # ---- the run record: window, sensor, replay --------------------------
    rr = json.loads((rd / "run-record.json").read_text())
    window = rr["window_epoch_ns"]
    recon = rr["reconciliation"]
    sensor_backed = (recon.get("status") != "skipped-no-sensor"
                    and bool(rr.get("kernel")))
    print(f"run {rr['run_id']}  window [{window['start']}, {window['end']}]  "
          f"sensor-backed={sensor_backed} "
          f"reconciliation={recon.get('status')}")
    check(sensor_backed, "sensor-backed run (not the degraded no-sensor mode)")
    check(args.ready_ns < window["start"],
          f"collector .ready marker ({args.ready_ns}) precedes the window "
          f"start ({window['start']}) — and so the first action")

    # ---- the readiness gate ----------------------------------------------
    probe = json.loads((rd / "gateway" / "readiness-probe.json").read_text())
    check(probe.get("denied") is True,
          f"readiness probe refused by the gateway "
          f"(status {probe.get('status')}: {probe.get('detail')})")
    records = [json.loads(l) for l in
               (rd / "gateway" / "decision-records.jsonl").read_text()
               .splitlines() if l.strip()]
    deny = [r for r in records if r.get("tool") == "__readiness_check__"]
    check(len(deny) == 1 and deny[0].get("decision") == "deny",
          "the translated stream carries the probe's deny decision record")
    if deny:
        probe_ns = ts_to_ns(deny[0]["ts"])
        check(probe_ns < window["start"],
              f"the probe's deny record ts ({deny[0]['ts']}) precedes the "
              f"window start — the probe's pre-window connect stays outside "
              f"the kernel window")
    # the C1-C4 coverage input excludes the probe's record (runner plumbing)
    decisions = [json.loads(l) for l in
                 (rd / "gateway" / "decisions.jsonl").read_text()
                 .splitlines() if l.strip()]
    check(sorted(r.get("action_id") for r in decisions) == INSPECTED,
          f"gateway/decisions.jsonl carries exactly the inspected actions "
          f"{INSPECTED} (readiness record excluded from the coverage input)")
    check(all(r.get("action_id") is not None for r in decisions),
          "every coverage-input decision record carries an echoed action_id "
          "(the mcp_meta carrier survived the gateway and the shim)")
    scoped = len((rd / "gateway" / "agentgateway-trace.jsonl").read_text()
                  .splitlines())
    print(f"     scoped vendor rows on the slot volume: {scoped} "
          f"(excluded from scope: {args.excluded})")
    if args.excluded is not None:
        check(scoped > 0, "the scoped vendor stream is non-empty")
    if args.expect_excluded is not None:
        check(args.excluded == args.expect_excluded,
              f"excluded-rows count ({args.excluded}) equals the warmup "
              f"run's scoped count ({args.expect_excluded}) — the shared "
              f"volume accumulated exactly the warmup's rows, the "
              f"acceptance run's scope is clean")

    # ---- outcomes ---------------------------------------------------------
    oc = json.loads((rd / "outcomes.json").read_text())
    check(oc["counts"] == EXPECTED_COUNTS,
          f"outcome counts == {EXPECTED_COUNTS} (got {oc['counts']})")
    per = {a["id"]: a for a in oc["per_action"]}
    for aid in INSPECTED:
        a = per.get(aid, {})
        check(a.get("outcome") == "checked-allowed" and a.get("decisions", 0) >= 1
              and a.get("class") == "http_tool_call",
              f"{aid} http_tool_call checked-allowed with a decision record")
    n_bypassed = sum(1 for a in oc["per_action"]
                     if a["outcome"] == "bypassed")
    check(n_bypassed == 11, "11 bypassed escape-class actions")

    # ---- coverage (C1-C4) --------------------------------------------------
    cov = json.loads((rd / "coverage.json").read_text())
    for c in cov["checks"]:
        if not args.warmup:
            check(c["status"] == "pass", f"{c['id']}: {c['detail']}")
    http = cov["coverage"]["http_tool_call"]
    check(http["covered"] == 4 and http["ground_truth"] == 4
          and http["coverage"] == 1.0,
          "http_tool_call coverage 4/4 = 1.0 (topology coverage at T1)")
    dd = cov["decisions"]
    check(dd["in_window"] == 4 and dd["out_of_window"] == 0
          and not dd["unaccounted"] and not dd["parse_problems"],
          f"4 in-window decisions, 0 out-of-window, none unaccounted "
          f"(total {dd['total']})")

    # ---- reconciliation (R1-R5, sensor-backed) -----------------------------
    rec = json.loads((rd / "reconciliation.json").read_text())
    print(f"     reconciliation status: {rec['status']}")
    for c in rec["checks"]:
        print(f"     {c['status']:>4} {c['id']}: {c['detail'][:150]}")
        if not args.warmup:
            check(c["status"] == "pass", f"{c['id']} pass")
    if not args.warmup:
        r3 = [c for c in rec["checks"] if c["id"].startswith("R3-kernel")]
        check(bool(r3), "R3 per-class kernel observations present "
                        "(the sensor-backed scope ran)")

    # ---- the execution manifest entry (C5/C6, findings, consistency) -------
    ex = json.loads(Path(args.execution).read_text())
    entry = next((r for r in ex["runs"]
                  if r["run_id"] == rr["run_id"]), None)
    if entry is None:
        errors.append(f"no entry for {rr['run_id']} in execution.json")
    else:
        print(f"     execution entry: status={entry['status']} "
              f"coverage_consistent={entry['coverage_consistent']} "
              f"evidence_class={entry.get('evidence_class')} "
              f"verified={entry['outcome_counts'].get('verified')} "
              f"degraded={entry.get('degraded')}")
        if not args.warmup:
            check(entry["status"] == "pass", "execution status pass")
            check(entry["coverage_consistent"] is True,
                  "coverage_consistent true")
            check(not entry.get("findings"), "0 findings")
            check(entry["c5"]["status"] == "pass",
                  f"C5 pass ({json.dumps(entry['c5'].get('scope'))})")
            check(entry["c6"]["status"] == "pass",
                  f"C6 pass (deny records: "
                  f"{json.dumps(entry['c6']['denies'])})")
            check(entry.get("evidence_class") in ("harness-run",
                                                    "mock-run"),
                  f"evidence class {entry.get('evidence_class')} "
                  f"(sensor-verified, not self-reported)")
            check(entry["outcome_counts"].get("verified") is True,
                  "outcome counts kernel-verified")
        c5 = entry["c5"]
        print(f"     C5: carried {c5.get('carried_pairs')} "
              f"echoed {c5.get('echoed_pairs')} "
              f"skipped {json.dumps(c5.get('skipped'))}")
        per_deny = (entry["c6"].get("per_deny") or [])
        for pd in per_deny:
            print(f"     C6 per-deny: {pd.get('action_id')} "
                  f"verdict={pd.get('verdict')} note={pd.get('note')}")

    print(f"VERIFY {rr['run_id']}: "
          f"{'OK' if not errors else str(len(errors)) + ' FAILURE(S)'}")
    return 0 if not errors else 1


if __name__ == "__main__":
    sys.exit(main())
