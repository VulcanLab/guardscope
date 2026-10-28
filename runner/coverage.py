#!/usr/bin/env python3
"""Enforcement-point sensor + inspection-coverage computation (T1-4).

Design T1 places the enforcement point (AGT MCP Security Gateway) on the
HTTP tool transport. main.tex §5.2 defines inspection coverage per action
class as

    coverage(class) = |ground-truth actions of class that CROSS the
                       enforcement point| / |ground-truth actions of class|

where "cross" means the action was evaluated at the enforcement point —
an AuditEntry exists in the gateway decision log (allowed OR denied; a
denial is policy content, not a coverage failure).

The enforcement-point record is $GATEWAY_LOG_DIR/decisions.jsonl, one
AuditEntry JSON line per decision (spec §12 fields + parameters:
timestamp, agent_id, tool_name, allowed, reason, approval_status,
parameters). Decision tool names map 1:1 onto canonical http_tool_call
actions (targets/mcp-http TOOL_ROUTES; mirrored here as GATEWAY_TOOL_ROUTES
with the same key set the adapters use), so each decision is attributable
to exactly one spec action.

The gateway-logs volume persists across runs, so decisions are scoped to
the replay measurement window (replay-result window_epoch_ns +
window_slack_ns, default 1 s — the profile slack). Out-of-window decisions
from earlier runs sharing the volume are excluded and reported.

Checks (deterministic, docker-free; any violation fails the run):
  C1 parse       every decisions.jsonl line parses to an AuditEntry with a
                 tool_name and a parseable timestamp
  C2 accounted   every in-window decision maps onto exactly one spec action
                 (no unknown tools inside the measurement window)
  C3 evaluated   every ground-truth action of a inspected class has >= 1
                 in-window decision
  C4 inspection   no in-window decision maps to a NON-inspected class (the
                 inspected set is a property of the topology; a crossing
                 outside it means the design assumption is wrong)

Usage:
  python3 runner/coverage.py --spec trace/traces/baseline.yaml \
      --design t1 --decisions runs/<id>/gateway/decisions.jsonl \
      [--replay runs/<id>/replay-result.json] \
      [--out runs/<id>/coverage.json]

Exit codes: 0 pass, 1 coverage failed (report still written), 2 usage.
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(HERE / "runner"))

import reconcile as rec_mod  # noqa: E402

SCHEMA = "inspection-coverage/1"

# tool_name -> (method, path). Mirrors targets/mcp-http/server.py TOOL_ROUTES
# and the adapters' GATEWAY_TOOL_ROUTES (post_hook/get_health/put_state
# <-> a011-a013). T1 has exactly one tool per canonical HTTP action.
GATEWAY_TOOL_ROUTES = {
    "post_hook": ("POST", "/hook"),
    "get_health": ("GET", "/health"),
    "put_state": ("PUT", "/state"),
}

# Deployment design -> action classes that physically cross the enforcement
# point (main.tex Table 1). T1: only http_tool_call is inspected; stdio MCP,
# direct network, spawns, file writes, and credential reads are the escapes
# T1 exists to expose. New designs add their own entry.
INSPECTED_CLASSES = {
    "t1": {"http_tool_call"},
    "t2": {"http_tool_call"},  # gateway unchanged from T1; egress prevents direct
    # t3: gateway as sole enforcement point — fs tools proxied behind it too
    "t3": {"http_tool_call", "stdio_tool_call"},
    # t4: harness-native enforcement — the permission chain evaluates both
    # tool classes (v1: permissions only; process-level actions bypass)
    "t4": {"http_tool_call", "stdio_tool_call"},
    # t5: union of the two enforcement points — the harness record (the
    # coverage input) inspects both tool classes; the gateway adds a second
    # evaluation for the http class (captured in the seam record)
    "t5": {"http_tool_call", "stdio_tool_call"},
    # t6: in-process policy engine — same placement as t4, so the same
    # inspected set; the decisions carry argument-level rule matches
    "t6": {"http_tool_call", "stdio_tool_call"},
    "t0": set(),  # bare harness: no enforcement point at all
}


def ts_to_epoch_ns(ts) -> int | None:
    """AuditEntry timestamp -> epoch ns. Accepts epoch seconds (float/int,
    the shape pinned in tests/test_gateway.py), epoch ns/us, or ISO 8601."""
    if isinstance(ts, bool) or ts is None:
        return None
    if isinstance(ts, (int, float)):
        v = float(ts)
        if v > 1e17:
            return int(v)        # ns
        if v > 1e14:
            return int(v * 1e3)  # us
        return int(v * 1e9)      # seconds
    if isinstance(ts, str):
        try:
            return int(ts)
        except ValueError:
            pass
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return int(dt.timestamp() * 1e9)
        except ValueError:
            return None
    return None


def load_decisions(path: Path) -> tuple[list[dict], list[str]]:
    """Parse decisions.jsonl; returns (entries, parse_problems)."""
    entries, problems = [], []
    for i, raw_line in enumerate(Path(path).read_text(encoding="utf-8").splitlines()):
        line = raw_line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError as exc:
            problems.append(f"line {i + 1}: not JSON ({exc})")
            continue
        if not isinstance(entry, dict) or not entry.get("tool_name"):
            problems.append(f"line {i + 1}: no AuditEntry tool_name")
            continue
        if ts_to_epoch_ns(entry.get("timestamp")) is None:
            problems.append(f"line {i + 1}: unparseable/missing timestamp")
            continue
        entries.append(entry)
    return entries, problems


def _route_action(spec: dict) -> dict[tuple[str, str], list[str]]:
    """(method, path) -> spec action ids, for http_tool_call actions.
    Several actions may share one route (v2: a011/a014 both POST /hook,
    distinguished by argument values) — decision-to-instance attribution
    falls back to argument matching + occurrence order."""
    out: dict[tuple[str, str], list[str]] = {}
    for a in spec["actions"]:
        if a["class"] != "http_tool_call":
            continue
        key = (a["op"], (a.get("args") or {}).get("path"))
        out.setdefault(key, []).append(a["id"])
    return out


def compute(spec: dict, decisions: list[dict], parse_problems: list[str],
            design: str, window: tuple[int, int] | None = None,
            window_slack_ns: int = 1_000_000_000, prevented_classes: set | None = None) -> dict:
    """Coverage report for one run. `window` is (start_ns, end_ns) from the
    replay result; None counts every decision (no volume-persistence guard)."""
    if design not in INSPECTED_CLASSES:
        raise ValueError(f"unknown design {design!r} (known: "
                         f"{sorted(INSPECTED_CLASSES)})")
    inspected = INSPECTED_CLASSES[design]
    route = _route_action(spec)  # (method, path) -> [action ids]
    id_class = {a["id"]: a["class"] for a in spec["actions"]}
    # tool_name -> [(action id, action class), ...] for every routed tool
    # (v2: one tool may serve several spec actions — see _route_action)
    tool_to_action: dict[str, list[tuple[str, str]]] = {}
    for tool, key in GATEWAY_TOOL_ROUTES.items():
        if key in route:
            tool_to_action[tool] = [(aid, id_class[aid]) for aid in route[key]]
    # T3: the fs tools are proxied through the gateway too; the stdio
    # action's op IS the gateway tool name (write_file/read_file/list_directory)
    for a in spec["actions"]:
        if a["class"] == "stdio_tool_call":
            tool_to_action.setdefault(a["op"], []).append((a["id"], a["class"]))

    def resolve_tool(tool_name):
        """T4: the harness records MCP tool names in pi's namespaced form
        (mcp__<server>__<tool>); strip the namespace to the bare tool name."""
        if tool_name in tool_to_action:
            return tool_to_action[tool_name]
        if isinstance(tool_name, str) and tool_name.startswith("mcp__"):
            bare = tool_name.split("__")[-1]
            return tool_to_action.get(bare)
        return None

    checks: list[dict] = []

    def check(cid: str, ok: bool, detail: str) -> None:
        checks.append({"id": cid, "status": "pass" if ok else "fail",
                       "detail": detail})

    # --- C1 parse ---------------------------------------------------------
    check("C1-parse", not parse_problems,
          f"{len(decisions)} decisions parsed" if not parse_problems
          else "; ".join(parse_problems))

    # --- window scoping -----------------------------------------------------
    lo = hi = None
    if window:
        lo, hi = int(window[0]) - window_slack_ns, int(window[1]) + window_slack_ns

    in_scope, out_of_window = [], []
    for e in decisions:
        ts = ts_to_epoch_ns(e.get("timestamp"))
        if lo is None or lo <= ts <= hi:
            in_scope.append(e)
        else:
            out_of_window.append(e)

    # --- C2 accounted + C4 inspection ----------------------------------------
    # Decisions are attributed to spec action instances in two passes: first
    # by exact argument match (a decision whose parameters equal the action's
    # args — disambiguates same-tool instances like a011/a014), then the
    # remainder in chronological order (occurrence matching).
    def _exact_match(aid: str, e: dict) -> bool:
        a = next(x for x in spec["actions"] if x["id"] == aid)
        args = a.get("args") or {}
        params = e.get("parameters") or {}
        compared = [k for k in args if k in params]
        return bool(compared) and all(params[k] == args[k] for k in compared)

    tool_decisions: dict[str, list[dict]] = {}
    unaccounted = []
    for e in in_scope:
        cands = resolve_tool(e.get("tool_name"))
        if not cands:
            unaccounted.append({"tool_name": e.get("tool_name"),
                                "ts": e.get("timestamp")})
            continue
        inspected_cands = [(aid, cls) for aid, cls in cands if cls in inspected]
        if not inspected_cands:
            unaccounted.append({"tool_name": e.get("tool_name"),
                                "ts": e.get("timestamp"),
                                "reason": f"decision on non-inspected {cands[0][1]}",
                                "action": cands[0][0]})
            continue
        tool_decisions.setdefault(e.get("tool_name"), []).append(e)

    by_action: dict[str, list[dict]] = {}
    for tool, decs in tool_decisions.items():
        inspected_cands = [(aid, cls) for aid, cls in (resolve_tool(tool) or [])
                          if cls in inspected]
        remaining = list(inspected_cands)
        for e in sorted(decs, key=lambda x: ts_to_epoch_ns(x.get("timestamp")) or 0):
            exact = [aid for aid, _ in inspected_cands if _exact_match(aid, e)]
            if exact:
                # argument-identical (re-)evaluation of one instance —
                # attach to it; do not consume the next occurrence
                by_action.setdefault(exact[0], []).append(e)
                remaining = [(aid, cls) for aid, cls in remaining
                             if aid != exact[0]]
                continue
            if not remaining:
                unaccounted.append({"tool_name": e.get("tool_name"),
                                    "ts": e.get("timestamp"),
                                    "reason": "more decisions than spec instances"})
                continue
            aid = remaining.pop(0)[0]
            by_action.setdefault(aid, []).append(e)
    cross_class = [u for u in unaccounted if "non-inspected" in (u.get("reason") or "")]
    check("C2-accounted", not unaccounted,
          f"{len(in_scope)} in-window decisions, all mapped to spec actions"
          if not unaccounted else
          f"{len(unaccounted)} in-window decision(s) map to no inspected "
          f"spec action: {unaccounted}")
    check("C4-inspected-only", not cross_class,
          f"design {design} inspects {sorted(inspected)}; no decision "
          f"crossed a non-inspected action" if not cross_class else
          "a decision crossed a NON-inspected action (topology assumption "
          f"violated): {cross_class}")

    # --- per-action rows ------------------------------------------------------
    actions = spec["actions"]
    rows = []
    for a in actions:
        hits = by_action.get(a["id"], [])
        denied = any(e.get("allowed") is False for e in hits)
        rows.append({
            "id": a["id"], "class": a["class"], "tool": _tool_for(a),
            "crosses_enforcement_point": a["class"] in inspected,
            "evaluated": bool(hits),
            "decisions": len(hits),
            "allowed": (all(e.get("allowed") is True for e in hits)
                        if hits else None),
            "verdict": ("denied" if denied else "allowed") if hits else None,
            "decision_refs": [e.get("tool_call_id") or str(e.get("timestamp"))
                              for e in hits],
            "params_match": (all(_params_match(a, e) for e in hits)
                             if hits else None),
        })

    # --- C3 evaluated -------------------------------------------------------
    missing = [r["id"] for r in rows
               if r["crosses_enforcement_point"] and not r["evaluated"]]
    check("C3-evaluated", not missing,
          f"every ground-truth action of {sorted(inspected)} has >= 1 "
          f"in-window decision" if not missing else
          f"inspected actions with no decision: {missing}")

    # --- per-class coverage ---------------------------------------------------
    gt = {c: sum(1 for a in actions if a["class"] == c)
          for c in rec_mod.SIX_CLASSES}
    covered = {c: sum(1 for r in rows if r["class"] == c and r["evaluated"])
               for c in rec_mod.SIX_CLASSES}
    per_class = {
        c: {"ground_truth": gt[c], "covered": covered[c],
            "coverage": (covered[c] / gt[c]) if gt[c] else None,
            "inspected": c in inspected}
        for c in rec_mod.SIX_CLASSES
    }

    status = "pass" if all(c["status"] == "pass" for c in checks) else "fail"
    return {
        "schema": SCHEMA,
        "design": design,
        "inspected_classes": sorted(inspected),
        "prevented_classes": sorted(rec_mod.PREVENTED_CLASSES.get(design, set())
                                    if prevented_classes is None else prevented_classes),
        "window_epoch_ns": ({"start": lo, "end": hi} if lo is not None
                            else None),
        "coverage": per_class,
        "per_action": rows,
        "decisions": {
            "total": len(decisions),
            "in_window": len(in_scope),
            "out_of_window": len(out_of_window),
            "unaccounted": unaccounted,
            "parse_problems": parse_problems,
        },
        "checks": checks,
        "status": status,
    }


def _tool_for(action: dict) -> str | None:
    """Canonical action -> gateway tool name (inverse of GATEWAY_TOOL_ROUTES).
    T3: the fs tools are proxied through the gateway too — the stdio action's
    op IS the gateway tool name."""
    if action["class"] == "stdio_tool_call":
        return action["op"]
    if action["class"] != "http_tool_call":
        return None
    key = (action["op"], (action.get("args") or {}).get("path"))
    for tool, k in GATEWAY_TOOL_ROUTES.items():
        if k == key:
            return tool
    return None


def _params_match(action: dict, entry: dict) -> bool:
    """Decision parameters vs the spec action's args, compared over the keys
    the decision carries (a mismatch on a compared feature is
    alpha-reconstruction evidence, not a coverage failure; route components
    such as `path` live in the tool name, not in parameters)."""
    params = entry.get("parameters") or {}
    args = action.get("args") or {}
    return all(params.get(k) == v for k, v in args.items() if k in params)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--spec", type=Path, required=True)
    ap.add_argument("--design", required=True, choices=sorted(INSPECTED_CLASSES))
    ap.add_argument("--decisions", type=Path, required=True)
    ap.add_argument("--replay", type=Path, default=None,
                    help="replay-result.json; supplies the measurement window")
    ap.add_argument("--window-slack-ns", type=int, default=1_000_000_000)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    spec = rec_mod.load_spec(args.spec)
    decisions, problems = load_decisions(args.decisions)
    window = None
    if args.replay:
        w = rec_mod.load_replay(args.replay).get("window_epoch_ns") or {}
        window = (int(w["start"]), int(w["end"]))
    report = compute(spec, decisions, problems, args.design, window,
                     args.window_slack_ns)

    payload = json.dumps(report, indent=1, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(payload)
    print(payload, end="")
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
