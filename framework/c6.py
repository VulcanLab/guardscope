"""C6: denial effectiveness (DESIGN.md 9, "Denial effectiveness: `prevented`
= deny record + verified absence of the action's kernel signature; the
expected per-class kernel signature is derived from mock harness baseline
runs").

C6 turns every DENY decision record (native or v0-mapped) into a verifiable
claim: the control claims it prevented the action, so the kernel evidence of
the run must NOT contain the action's expected signature. Three outcomes:

  prevented-confirmed  the deny is recorded and the action's expected
                       kernel signature is absent from the run's kernel
                       evidence inside the measurement window — the claim is
                       corroborated (this is the only fully kernel-verifiable
                       outcome, DESIGN.md 9 "Stated limit")
  C6-ineffective       the deny is recorded AND the action's expected kernel
                       signature IS present in-window — the key finding: the
                       control claimed prevention but the effect happened
  unverifiable         the action's class has no per-action attributable
                       kernel signature (multiplexed transport evidence,
                       reads colliding with unrelated events) — recorded with a note, never
                       silently confirmed and never a finding

The expected signatures are derived from the hash-pinned mock harness path
manifest (mock_harness/manifest.yaml, DESIGN.md 8: "a hash-pinned path manifest
(all 15 paths with class, operation, origin channel, expected kernel-visible
signature, ...)"), read-only here, cross-referenced with the canonical
trace spec for the per-action target identity. The kernel evidence is the
run's mapped-actions stream (sensor/mapping/map_events.py output — the
runner's mapped view, not raw Tracee events; DESIGN.md 9 kernel layer).

Attribution ladder for a deny record (DESIGN.md 5, priority order):
  1. action_id — native records echo the carrier id; used when non-null and
     a known spec action
  2. target_identity — v0-mapped records carry no ids: the deny is resolved
     onto a spec action by tool route + exact argument match (the same
     ladder the runner's C2 attribution uses)

Design notes / v1 limitations (documented, not hidden):

- Effect vs crossing evidence. The http gateway route produces TWO
  connects per allowed call (the harness's crossing connect to gateway:8090
  and the upstream/effect connect to the endpoint). C6 verifies the
  EFFECT: the connect to the trace's endpoint port (8080), direct or
  proxied (DESIGN.md 9 proxy-egress attribution rule attributes the
  gateway's upstream connect to the inspected action). The crossing connect
  is inspection evidence — it fires exactly when the call was inspected,
  denied or not, so its presence proves nothing about prevention.
- Pooled transports. http (and stdio response writes) are multiplexed at
  the kernel level ([1..n] connect counts); a denied call that reused a
  warm pool can take effect without a new connect. C6's per-action absence
  verdict on those classes is therefore corroborating, not exhaustive; the
  served layer (R2) carries the per-instance denial evidence in the runner.
  Only per-action classes (process_spawn, file_write, credential_access,
  direct_network: exact target/port match, mirroring the runner's
  PER_ACTION_CLASSES + the manifest's per-port attribution rules) give
  exact verdicts.
- stdio read/list effects (read-mode opens of the tool paths) are
  colliding with unrelated events by the manifest's own note ("read-mode
  opens of /workspace/out are allowlisted as unrelated tool reads"), so they cannot ground
  an absence verdict; only the write-mode tool effect (a001's
  tool_effect_open) is a usable stdio effect signature.

Docker-free: everything reads retained run artifacts. When the run has no
kernel evidence (no mapped-actions.jsonl on disk, e.g. the degraded
no-sensor mode) C6 is SKIPPED with a note, never a finding (DESIGN.md 9).
"""

import json
from functools import lru_cache
from pathlib import Path

import yaml

from framework.reconcile import (  # noqa: E402
    GATEWAY_TOOL_ROUTES, ts_to_epoch_ns,
)

C6_ID = "C6"

REPO_ROOT = Path(__file__).resolve().parent.parent
MOCK_HARNESS_MANIFEST = REPO_ROOT / "mock_harness" / "manifest.yaml"
BASELINE_SPEC = REPO_ROOT / "trace" / "traces" / "baseline.yaml"

# The gateway's fs tools (T3+; framework/records.py V0_FS_TOOLS) — the stdio
# route in the target-identity ladder for v0-mapped records.
V0_FS_TOOLS = ("write_file", "read_file", "list_directory")

# Write-mode open(2) tokens: a kernel open carrying one of these is a write
# effect (the mapping layer's file_write class is built on the same split).
_WRITE_FLAG_TOKENS = ("O_WRONLY", "O_RDWR")


# --- the pinned expected signatures (mock harness manifest, DESIGN.md 8) ------------


@lru_cache(maxsize=1)
def _manifest_paths() -> dict:
    """The mock harness path manifest's `paths` list, by action id (read-only;
    the manifest is hash-pinned and never written here)."""
    doc = yaml.safe_load(MOCK_HARNESS_MANIFEST.read_text(encoding="utf-8"))
    return {p["id"]: p for p in doc.get("paths") or []}


def _norm_path(value) -> str | None:
    """Normalize a kernel/spec path for comparison: the spec pins
    credential targets as file:// URLs while the mapping layer and the
    manifest carry bare paths (observed live: mapped records keep the
    file:// form) — compare over the scheme-stripped form."""
    if not isinstance(value, str) or not value:
        return None
    if value.startswith("file://"):
        value = value[len("file://"):]
    return value.rstrip("/") or "/"


def _target_port(target: str) -> int | None:
    """The effect endpoint port of a spec target: `net-peer:9000` (direct
    network) or `http://http-endpoint:8080` (the trace's own endpoint)."""
    if not isinstance(target, str):
        return None
    tail = target.rsplit("/", 1)[-1] if target.startswith("http") else target
    if ":" not in tail:
        return None
    try:
        return int(tail.rsplit(":", 1)[1])
    except ValueError:
        return None


def _write_mode(flags) -> bool:
    return isinstance(flags, str) and any(
        tok in flags.split("|") for tok in _WRITE_FLAG_TOKENS)


def expected_effect_signature(action: dict) -> dict:
    """The per-action kernel EFFECT signature: the mapped kernel records the
    action would produce if it took effect (the "action would have produced
    X" premise of the absence verification). Derived from the mock harness
    manifest's per-path kernel_signature + the spec's target identity.

    Returns {"class", "predicates": [...], "note": str | None}: each
    predicate matches a mapped record when all its fields hold:

      {"kind": "path",  "class"?, "path", "write_mode"?: bool}
      {"kind": "port",  "class",  "events": [...], "port": int}

    An empty predicate list with a note means the class has no
    per-action attributable effect signature in v1 (the deny is then
    unverifiable, never confirmed by absence alone).
    """
    cls, target = action["class"], action.get("target", "")
    mpath = _manifest_paths().get(action["id"]) or {}
    signature = (mpath.get("kernel_signature") or {})
    attrs = signature.get("attributes") or {}

    if cls in ("process_spawn", "file_write", "credential_access"):
        # Exact target match — the runner's per-action kernel rule
        # (runner/reconcile.py kernel_per_action); the manifest's declared
        # flags (a041's O_WRONLY|O_CREAT|O_TRUNC) cross-check the target.
        return {"class": cls,
                "predicates": [{"kind": "path", "class": cls,
                               "path": target}]}

    if cls in ("http_tool_call", "direct_network"):
        # The effect endpoint connect (the trace's own port), with the
        # manifest's declared syscall/event names. http: the endpoint
        # connect, direct or proxied (proxy-egress attribution rule);
        # direct_network: the manifest's per-port attribution rule.
        port = _target_port(target)
        if port is None:
            return {"class": cls, "predicates": [],
                    "note": "spec target carries no port"}
        return {"class": cls,
                "predicates": [{"kind": "port", "class": cls,
                                "events": list(signature.get("syscalls")
                                               or (["connect"] if cls ==
                                                   "http_tool_call" else [])),
                                "port": port}]}

    if cls == "stdio_tool_call":
        # The effect lives in the manifest's open attributes (the tool's
        # args path), not in the mcp:// target. Only write-mode opens are
        # per-action attributable: read-mode tool opens collide with the
        # profile's allowlisted unrelated tool reads (the manifest's own note),
        # so they cannot ground an absence verdict.
        preds = []
        for attr in attrs.values():
            if not isinstance(attr, dict) or "path" not in attr:
                continue
            if _write_mode(attr.get("flags")):
                preds.append({"kind": "path", "path": attr["path"],
                              "write_mode": True})
        note = None
        if not preds:
            note = ("no per-action attributable effect signature: the "
                    "manifest's tool effect for this path is a read-mode "
                    "open, colliding with unrelated events by the manifest's own note "
                    "(absence proves nothing per action)")
        return {"class": cls, "predicates": preds, "note": note}

    return {"class": cls, "predicates": [],
            "note": f"class {cls!r} has no expected signature in the "
                    f"mock harness manifest"}


def _record_matches(rec: dict, pred: dict) -> bool:
    """One mapped kernel record vs one effect predicate."""
    detail = rec.get("detail") or {}
    if pred["kind"] == "path":
        if "class" in pred and rec.get("class") != pred["class"]:
            return False
        value = detail.get("target")
        if value is None:
            value = detail.get("path")
        if _norm_path(value) != _norm_path(pred["path"]):
            return False
        if pred.get("write_mode") and not _write_mode(detail.get("flags")):
            return False
        return True
    # port predicate: class + declared event + the effect endpoint port
    return (rec.get("class") == pred["class"]
            and rec.get("event") in (pred.get("events") or [])
            and detail.get("target_port") == pred["port"])


# --- deny-record attribution (DESIGN.md 5 priority: id -> target_identity) --------


def _route_candidates(record: dict, spec: dict) -> list[dict]:
    """Spec actions a deny record may resolve onto by tool route (the v0 /
    target-identity ladder; the same routing the runner's C2 attribution
    uses: gateway tool routes for http, the fs tool names for stdio)."""
    tool = record.get("tool")
    if not isinstance(tool, str):
        return []
    out: list[dict] = []
    if tool in GATEWAY_TOOL_ROUTES:
        method, path = GATEWAY_TOOL_ROUTES[tool]
        out = [a for a in spec["actions"]
               if a["class"] == "http_tool_call" and a["op"] == method
               and (a.get("args") or {}).get("path") == path]
    elif tool in V0_FS_TOOLS:
        out = [a for a in spec["actions"]
               if a["class"] == "stdio_tool_call" and a["op"] == tool]
    else:
        cls = record.get("action_class")
        out = [a for a in spec["actions"] if a["class"] == cls
               and a["op"] == tool]
    return out


def _exact_params_match(action: dict, record: dict) -> bool:
    """Exact argument match over the keys the record carries (disambiguates
    same-route instances, e.g. a011/a014 both POST /hook)."""
    args = action.get("args") or {}
    params = record.get("parameters") or {}
    compared = [k for k in args if k in params]
    return bool(compared) and all(params[k] == args[k] for k in compared)


def _resolve_action(record: dict, spec: dict) -> tuple[dict | None, str, str]:
    """Resolve one deny record onto a spec action. Returns
    (action, attribution_method, note); method is "id" or "target_identity"
    (DESIGN.md 5 attribution ladder), or the action is None with a note
    when unresolvable (organic/unknown traffic — recorded, never dropped,
    and left to the C1-C4 accounting checks to flag)."""
    aid = record.get("action_id")
    by_id = {a["id"]: a for a in spec["actions"]}
    if isinstance(aid, str) and aid in by_id:
        return by_id[aid], "id", ""
    if aid is not None:
        return None, "none", (f"action_id {aid!r} is not a spec action "
                              "(organic or off-spec traffic)")
    candidates = _route_candidates(record, spec)
    exact = [a for a in candidates if _exact_params_match(a, record)]
    if len(exact) == 1:
        return exact[0], "target_identity", ""
    if not exact and len(candidates) == 1:
        return candidates[0], "target_identity", \
            "no parameters carried; route-only match"
    if len(exact) > 1:
        return None, "none", (f"ambiguous route match: "
                               f"{sorted(a['id'] for a in exact)}")
    return None, "none", "no spec action matches the record's identity"


# --- the check --------------------------------------------------------------------


def _load_mapped(run_dir: Path) -> list[dict] | None:
    """The run's kernel evidence: the mapped-actions stream (the runner's
    mapped view of the Tracee capture). None when absent or empty — the
    caller treats that as a skip, never a finding."""
    path = Path(run_dir) / "mapped-actions.jsonl"
    if not path.is_file():
        return None
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line.startswith("{"):
            records.append(json.loads(line))
    return records or None


def _ref(rec: dict) -> dict:
    return {"raw_index": (rec.get("provenance") or {}).get("raw_index"),
            "event": rec.get("event"), "ts": rec.get("ts"),
            "pid": rec.get("pid"),
            "container": rec.get("container")}


def run_c6(run_dir, decision_records, *, window,
           window_tolerance_ns: int = 1_000_000_000,
           spec: dict | None = None, run_id: str | None = None) -> dict:
    """Run the C6 denial-effectiveness check over one run's artifacts.

    run_dir: the run's artifact directory (mapped-actions.jsonl lives
    here; the run's own id is taken from its name when run_id is None).
    decision_records: decision-record/1 dicts (the run's mapped v0 records
    and/or the native stream; only decision == "deny" is examined). window:
    (start_epoch_ns, end_epoch_ns) or None (no time scoping); the same
    tolerance convention the C1-C4/C5 window uses. spec: the canonical trace
    spec (defaults to the baseline-15 pack, the only registered workload).

    Returns {"id": "C6", "status": "pass"|"fail"|"skipped", "note",
    "denies", "per_deny", "findings"}; findings are check-shaped dicts so
    they merge into the run's findings list unchanged. A deny with the
    action's kernel signature present is the C6-ineffective finding; no
    kernel evidence is a skip with a note.
    """
    run_dir = Path(run_dir)
    run_id = run_id if run_id is not None else run_dir.name

    mapped = _load_mapped(run_dir)
    if mapped is None:
        return {"id": C6_ID, "status": "skipped",
                "note": ("no kernel evidence (mapped-actions.jsonl absent "
                         "or empty in the run dir): C6 not run (a skip "
                         "with a note, never a finding; DESIGN.md 9 — "
                         "prevented requires kernel verification, and "
                         "claims cannot self-upgrade)"),
                "denies": {"records": 0}, "per_deny": [], "findings": []}

    if spec is None:
        spec = yaml.safe_load(BASELINE_SPEC.read_text(encoding="utf-8"))

    # scope decision records to the run (native streams accumulate across
    # runs on the enforcement-point volume): run_id when any record carries
    # it, else the window — the C5 convention
    records = [r for r in decision_records if isinstance(r, dict)]
    scope = "all"
    if any(r.get("run_id") == run_id for r in records):
        records = [r for r in records if r.get("run_id") == run_id]
        scope = "run_id"
    elif window is not None:
        lo, hi = int(window[0]) - window_tolerance_ns, int(window[1]) + window_tolerance_ns
        kept = []
        for r in records:
            # decision-record/1 ts is RFC3339 ms; v0-mapped records
            # carry the raw epoch-seconds timestamp in their ids map
            ts = ts_to_epoch_ns(r.get("ts"))
            if ts is None:
                ts = ts_to_epoch_ns((r.get("ids") or {}).get("v0_timestamp"))
            if ts is not None and lo <= ts <= hi:
                kept.append(r)
        records = kept
        scope = "window"

    # in-window kernel records (ts is epoch ns in the mapped stream)
    in_window = mapped
    if window is not None:
        lo, hi = int(window[0]) - window_tolerance_ns, int(window[1]) + window_tolerance_ns
        in_window = [r for r in mapped
                     if isinstance(r.get("ts"), int) and lo <= r["ts"] <= hi]

    findings: list[dict] = []
    per_deny: list[dict] = []
    seen: dict[tuple, dict] = {}
    n_denies = 0
    for record in records:
        if record.get("decision") != "deny":
            continue
        n_denies += 1
        action, method, note = _resolve_action(record, spec)

        if action is None:
            per_deny.append({"action_id": record.get("action_id"),
                             "attempt": record.get("attempt", 0),
                             "record_id": record.get("record_id"),
                             "attribution_method": "none",
                             "verdict": "unresolved", "note": note,
                             "signature": None, "evidence": []})
            continue

        key = (action["id"], int(record.get("attempt", 0) or 0))
        sig = expected_effect_signature(action)
        if key in seen:
            # the same deny seen in two streams (the v0 log + the native
            # stream of one decision): one verification, the duplicate
            # counted (C5's duplication check polices the stream level)
            seen[key]["deny_records"] += 1
            continue
        evidence = ([_ref(r) for r in in_window
                     if any(_record_matches(r, p) for p in sig["predicates"])]
                    if sig["predicates"] else [])
        verdict = "C6-ineffective" if evidence else "prevented-confirmed"
        if not sig["predicates"]:
            verdict = "unverifiable"
        entry = {"action_id": action["id"],
                 "class": action["class"],
                 "attempt": int(record.get("attempt", 0) or 0),
                 "attribution_method": method,
                 "verdict": verdict,
                 "signature": {"class": sig["class"],
                               "predicates": sig["predicates"],
                               "note": sig.get("note")},
                 "evidence": evidence, "deny_records": 1}
        seen[key] = entry
        per_deny.append(entry)
        if verdict == "C6-ineffective":
            findings.append({
                "id": "C6-ineffective", "status": "fail",
                "detail": (f"a deny record for action {action['id']} "
                           f"({action['class']}) is followed by the "
                           f"action's expected kernel signature in-window: "
                           f"{[e['event'] for e in evidence]} — the control "
                           f"claimed prevention but the effect happened "
                           f"(DESIGN.md 9: prevented = deny record + "
                           f"verified absence of the kernel signature)"),
            })

    counts = {"records": n_denies,
              "unique": len(seen),
              "prevented_confirmed": sum(1 for e in seen.values()
                                         if e["verdict"] == "prevented-confirmed"),
              "ineffective": len(findings),
              "unverifiable": sum(1 for e in seen.values()
                                  if e["verdict"] == "unverifiable"),
              "unresolved": sum(1 for e in per_deny
                                if e["verdict"] == "unresolved")}
    return {"id": C6_ID,
            "status": "fail" if findings else "pass",
            "scope": {"method": scope, "kernel_records": len(mapped),
                      "in_window": len(in_window)},
            "denies": counts,
            "per_deny": per_deny,
            "findings": findings}
