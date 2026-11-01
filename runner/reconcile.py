#!/usr/bin/env python3
"""Expected-vs-observed reconciliation (C7, M6).

Reconciles the canonical trace spec (ground truth) against three observation
layers for one replay run:

  replay layer   the harness adapter's replay result: per-action execution
                 status + the measurement window (window_epoch_ns)
  kernel layer   mapped Tracee records (JSONL from sensor/mapping/
                 map_events.py; includes unmapped records)
  served layer   optional target served-action logs (shared target-logs
                 volume, one JSON line per served action; M2) — authoritative
                 per-action evidence for transport-multiplexed classes (HTTP
                 connection pooling, stdio request/response)

Reconciliation is scoped to the measurement window and (optionally) the
harness container, applies the per-harness profile (runner/profiles/
<harness>.yaml: unrelated-events list, expected extras, kernel expected
count ranges), and then checks:

  R1 replay layer   executed == spec action count; every action status ok and
                    matching the spec's id/class/op
  R2 served layer   (when target logs are given) every action with a
                    target-facing observable is served within the window
  R3 kernel layer   per-action kernel support for spawn/file-write/credential
                    (exact target match, deduped multiplicity), expected
                    count ranges for stdio/http/network
  R4 no leftovers   every in-scope kernel record is allowlisted as an
                    unrelated event (with a reason) or accounted to a spec
                    action / profile expected-extra; anything else fails the run
  R5 counts         effective per-class counts equal the spec's ground-truth
                    counts EXACTLY

A deliberately corrupted mapping or a missing action FAILS the run.

Usage:
  python3 runner/reconcile.py --harness pi \
      --spec trace/traces/baseline.yaml \
      --mapped runs/pi/mapped-actions.jsonl \
      --replay runs/pi/replay-result.json \
      [--container-id <docker inspect -f '{{.Id}}' t0-pi>] \
      [--target-logs runs/pi/target-logs/] \
      [--out runs/pi/reconciliation.json]

Exit codes: 0 pass, 1 reconciliation failed (report still written), 2 usage.
"""

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent.parent
DEFAULT_SPEC = HERE / "trace" / "traces" / "baseline.yaml"

SIX_CLASSES = [
    "stdio_tool_call", "http_tool_call", "direct_network",
    "process_spawn", "file_write", "credential_access",
]

# Classes whose kernel observations match per action (exact target string);
# the rest are reconciled as documented expected-count-range groups, with
# per-action evidence from the served layer when target logs are available.
PER_ACTION_CLASSES = ("process_spawn", "file_write", "credential_access")
GROUP_CLASSES = ("stdio_tool_call", "http_tool_call", "direct_network")

# classes with a target-facing served observable (R2)
SERVED_CLASSES = ("http_tool_call", "stdio_tool_call", "direct_network")

# Deployment design -> action classes a NETWORK-LAYER policy prevents
# (main.tex Table 1 / §5.2): the attempt fires but the target never serves —
# the action takes no effect because a mechanism outside the policy denied
# it. Reconciliation design-awareness (R1/R2/R3/R5) keys off this map; t0
# and t1 prevent nothing. Prevented classes are disjoint from the inspected
# set (coverage.py): prevention is not a policy decision, so the
# enforcement-point record stays empty for them.
PREVENTED_CLASSES = {
    "t0": set(),
    "t1": set(),
    # t2/t3 forced egress: direct connections to net-peer are rejected at the
    # harness netns output hook (targets/egress-jail/apply.sh)
    "t2": {"direct_network"},
    "t3": {"direct_network"},
    # t4 v1 (permissions only): the permission chain evaluates tool calls;
    # the process-level actions are bypassed (they take effect), nothing is
    # prevented — no sandbox and no egress in the v1 configuration
    "t4": set(),
    # t5: same v1 configuration as t4; the gateway adds an evaluation for the
    # http tool class (recorded in the gateway-side record), still nothing prevented
    "t5": set(),
    # t6 v1 (workspace-scoped policy): all canonical trace actions pass the
    # in-process policy; the process-level actions bypass (invisible by
    # construction), nothing prevented
    "t6": set(),
    # t7 (0.2.0): the fixture policy's kill arm denies the a032 spawn
    # (exec /bin/echo) at the kernel — deny record + verified kernel
    # absence = prevented (C6); every other mediated class is notified
    # (checked). The runner tolerates a failed replay action whose class
    # is here (same mechanism as the t2/t3 egress-jail failures).
    "t7": {"process_spawn"},
}

# designs in which ALL tool calls share one pooled origin (gateway:8090): the
# kernel cannot attribute connects to the stdio vs http class — the gateway
# collapses the transport distinction T0–T2 exposed. Reconciliation (R3)
# uses one shared pooled expected count range for the two tool classes; per-action
# evidence moves to the served + decision (coverage) layers.
T3_SHARED_POOL_DESIGNS = {"t3"}
T3_TOOL_CLASSES = ("stdio_tool_call", "http_tool_call")

# refusal errnos that evidence a network-layer block (nft reject produces
# ECONNREFUSED); a timeout is NOT accepted (it suggests a DROP-style policy,
# which is slow and non-deterministic — the jail uses reject)
_REFUSAL_RE = re.compile(
    r"ECONNREFUSED|EHOSTUNREACH|ENETUNREACH|ENETDOWN|ENETRESET"
    r"|ECONNABORTED|ECONNRESET|EHOSTDOWN|EACCES|EPERM|ICMP"
    # the same refusals as Python OSError text (the mock harness records
    # exceptions verbatim, e.g. "[Errno 111] Connection refused"; the
    # real-harness adapters format errno names)
    r"|Connection refused|Operation not permitted|Permission denied"
    r"|Network is unreachable|Network is down|Network dropped"
    r"|Connection aborted|Connection reset|No route to host")

# tolerance (ns) around the replay window for target-log timestamps (container
# clocks are the host clock; small scheduling jitter tolerated)
SERVED_TOLERANCE_NS = 2_000_000_000


# --- loading -------------------------------------------------------------------


def load_spec(path: Path) -> dict:
    spec = yaml.safe_load(Path(path).read_text())
    for cls in SIX_CLASSES:
        if not any(a["class"] == cls for a in spec["actions"]):
            raise ValueError(f"spec {path}: no action of class {cls}")
    return spec


def load_profile(path: Path, _seen: tuple = ()) -> dict:
    path = Path(path).resolve()
    if path in _seen:
        raise ValueError(f"profile inheritance cycle: {path}")
    profile = yaml.safe_load(path.read_text())
    parent = profile.pop("extends", None)
    if parent:
        if not isinstance(parent, str) or Path(parent).name != parent:
            raise ValueError("profile extends must name a sibling YAML file")
        base = load_profile(path.parent / parent, (*_seen, path))
        profile = {**base, **profile,
                   "unrelated_events": base["unrelated_events"] + profile.get("unrelated_events", []),
                   "expected_extras": base["expected_extras"] + profile.get("expected_extras", []),
                   "multiplicity": {**base["multiplicity"], **profile.get("multiplicity", {})}}
    for key in ("profile", "harness", "unrelated_events", "expected_extras", "multiplicity"):
        if key not in profile:
            raise ValueError(f"profile {path}: missing '{key}'")
    pin = profile["multiplicity"].get("stdio_startup_calibration")
    if isinstance(pin, dict) and pin.get("kind") == "gateway-wire":
        if (pin.get("stdout_frames_per_startup") != 3
                or type(pin.get("max_startups_in_window")) is not int or pin["max_startups_in_window"] < 1
                or pin.get("extra_frames") != [0, 3 * pin["max_startups_in_window"]]
                or pin.get("response_methods") != ["initialize", "tools/list"]
                or pin.get("notification_methods") != ["notifications/tools/list_changed"]
                or not valid_argv(pin.get("gateway_argv"))
                or not isinstance(pin.get("rationale"), str) or not pin["rationale"].strip()):
            raise ValueError(f"profile {path}: invalid gateway stdio startup calibration pin")
    elif pin is not None and (not isinstance(pin, dict)
            or type(pin.get("writes_per_startup")) is not int or pin["writes_per_startup"] != 2
            or type(pin.get("max_startups_in_window")) is not int or pin["max_startups_in_window"] < 1
            or pin.get("extra_writes") != [0, 2 * pin["max_startups_in_window"]]
            or not isinstance(pin.get("rationale"), str) or not pin["rationale"].strip()):
        raise ValueError(f"profile {path}: invalid stdio startup calibration pin")
    http_pin = profile["multiplicity"].get("http_startup_calibration")
    if http_pin is not None and (not isinstance(http_pin, dict)
            or http_pin.get("port") != 8090
            or type(http_pin.get("connects_per_startup")) is not int or http_pin["connects_per_startup"] != 3
            or type(http_pin.get("max_startups_in_window")) is not int or http_pin["max_startups_in_window"] != 2
            or not isinstance(http_pin.get("rationale"), str) or not http_pin["rationale"].strip()
            or not valid_argv(http_pin.get("replay_argv"))
            or not valid_argv(http_pin.get("readiness_argv"))):
        raise ValueError(f"profile {path}: invalid HTTP startup calibration pin")
    for rule in profile.get("pre_window_unrelated", []):
        if (not valid_argv(rule.get("argv")) or not rule.get("reason") or not rule.get("records")
                or any(not r.get("where") or ("max_records" in r and
                       (type(r["max_records"]) is not int or r["max_records"] < 1))
                       for r in rule["records"])):
            raise ValueError(f"profile {path}: invalid pre-window unrelated-events rule")
    return profile


def prevented_for(design: str, profile: dict | None = None) -> set:
    """Explicit deployment axis; omission preserves canonical compose semantics."""
    axes = (profile or {}).get("deployment_axes", {})
    if axes:
        if axes != {"harness_egress": "none", "shared_tool_pool": "harness-only"}:
            raise ValueError("unsupported deployment axes")
        return set()  # tool-container confinement is NOT harness prevention
    return PREVENTED_CLASSES.get(design, set())


def valid_argv(argv) -> bool:
    return isinstance(argv, list) and bool(argv) and all(isinstance(a, str) and a for a in argv)


def load_mapped(path: Path) -> list[dict]:
    records = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line.startswith("{"):
                records.append(json.loads(line))
    return records


def load_replay(path: Path) -> dict:
    return json.loads(Path(path).read_text())


def load_target_logs(paths: list[str]) -> list[dict]:
    """Target served-action logs: files or directories of *.log JSONL."""
    records = []
    for p in map(Path, paths):
        files = sorted(p.glob("*.log")) if p.is_dir() else [p]
        for f in files:
            for line in f.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("{"):
                    records.append(json.loads(line))
    return records


def _iso_to_epoch_ns(ts) -> int | None:
    if not isinstance(ts, str):
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1_000_000_000)


# --- record normalization + rule matching ---------------------------------------


def flatten(rec: dict) -> dict:
    """Uniform view over mapped + unmapped records for scoping/matching."""
    d = rec.get("detail") or {}
    prov = rec.get("provenance") or {}
    argv = d.get("cmd") or d.get("argv") or []
    return {
        "class": rec.get("class", "unmapped"),
        "event": rec.get("event"),
        "process": rec.get("process") or "",
        "pid": rec.get("pid"),
        "container": rec.get("container"),
        "ts": rec.get("ts"),
        "retval": prov.get("returnValue", prov.get("retval")),
        "path": d.get("target") or d.get("path") or "",
        "port": d.get("target_port", d.get("port")),
        "transport": d.get("transport"),
        "flags": d.get("flags") or "",
        "argv": " ".join(str(x) for x in argv),
    }


def _match_one(flat: dict, cond: dict) -> bool:
    for key, value in cond.items():
        if key == "any_of":
            if not any(_match_one(flat, c) for c in value):
                return False
        elif key == "event":
            if flat["event"] not in (value if isinstance(value, list) else [value]):
                return False
        elif key == "class":
            if flat["class"] not in (value if isinstance(value, list) else [value]):
                return False
        elif key == "process_contains":
            procs = value if isinstance(value, list) else [value]
            if not any(p in flat["process"] for p in procs):
                return False
        elif key == "argv_contains":
            needles = value if isinstance(value, list) else [value]
            if not any(n in flat["argv"] for n in needles):
                return False
        elif key == "path":
            if flat["path"] != value:
                return False
        elif key == "path_prefix":
            prefixes = value if isinstance(value, list) else [value]
            if not any(flat["path"].startswith(p) for p in prefixes):
                return False
        elif key == "path_basename":
            names = [str(b) for b in (value if isinstance(value, list) else [value])]
            if Path(flat["path"]).name not in names:
                return False
        elif key == "path_glob":
            import fnmatch
            if not fnmatch.fnmatch(flat["path"], value):
                return False
        elif key == "port":
            if flat["port"] not in (value if isinstance(value, list) else [value]):
                return False
        elif key == "flags_contain":
            tokens = value if isinstance(value, list) else [value]
            have = set(flat["flags"].split("|"))
            if not all(t in have for t in tokens):
                return False
        elif key == "retval_nonzero":
            rv = flat["retval"]
            if value and (rv is None or rv == 0):
                return False
            if not value and rv is not None and rv != 0:
                return False
        else:
            raise ValueError(f"unknown matcher key: {key}")
    return True


def match_where(flat: dict, where: dict) -> bool:
    return _match_one(flat, where)


_EXTRA_MATCH_KEYS = ("any_of", "argv_contains", "path_basename", "path",
                     "path_prefix", "port", "flags_contain", "retval_nonzero")


def match_extra(flat: dict, extra: dict) -> dict | None:
    """Match a record against a profile expected-extra; returns attribution."""
    if flat["class"] != extra.get("class"):
        return None
    where = {k: v for k, v in extra.get("where", {}).items()
             if k in _EXTRA_MATCH_KEYS}
    if not where or not _match_one(flat, where):
        return None
    return {"extra": extra.get("id"), "due_to": extra.get("where", {}).get("due_to")}


# --- reconciliation --------------------------------------------------------------


class Reconciler:
    def __init__(self, spec: dict, profile: dict, replay: dict,
                 mapped: list[dict], target_logs: list[dict] | None = None,
                 container_id: str | None = None, design: str = "t0",
                 calibration_logs: list[dict] | None = None,
                 gateway_stdio_wire: list[dict] | None = None,
                 gateway_lifecycle: list[dict] | None = None):
        self.spec = spec
        self.profile = profile
        self.replay = replay
        self.mapped = mapped
        self.target_logs = target_logs or []
        # Cumulative enabled/disabled snapshots are used ONLY for startup
        # attribution, never for served effects (notably denied a014).
        self.calibration_logs = calibration_logs if calibration_logs is not None else self.target_logs
        self.gateway_stdio_wire = gateway_stdio_wire or []
        self.gateway_lifecycle = gateway_lifecycle or []
        self.container_id = container_id
        self.design = design
        self.prevented = prevented_for(design, profile)
        self.mult = profile.get("multiplicity", {})
        self.actions = spec["actions"]
        self.by_class = {c: [a for a in self.actions if a["class"] == c]
                         for c in SIX_CLASSES}
        self._served_per_action: dict[str, list[str]] = {}
        self._replay_status: dict[str, str] = {}
        self._unrelated: list[dict] = []
        self.checks: list[dict] = []
        self.leftovers: list[dict] = []
        self.extras: list[dict] = []   # in-scope records attributed to expected-extras

    # -- helpers -----------------------------------------------------------

    def check(self, cid: str, ok: bool, detail: str, hard: bool = True) -> None:
        self.checks.append({"id": cid, "status": "pass" if ok else "fail",
                            "hard": hard, "detail": detail})

    def window(self) -> tuple[int, int]:
        w = self.replay.get("window_epoch_ns") or {}
        tolerance = int(self.profile.get("window_tolerance_ns", 0))
        return int(w["start"]) - tolerance, int(w["end"]) + tolerance

    @staticmethod
    def _ref(rec: dict) -> dict:
        return {"raw_index": (rec.get("provenance") or {}).get("raw_index"),
                "event": rec.get("event"), "ts": rec.get("ts"),
                "pid": rec.get("pid")}

    # -- R1: replay layer ----------------------------------------------------

    def reconcile_replay(self) -> dict:
        results = self.replay.get("results") or []
        problems = []
        if self.replay.get("executed") != len(self.actions):
            problems.append(f"executed {self.replay.get('executed')} != "
                            f"spec {len(self.actions)}")
        by_id = {r.get("id"): r for r in results}
        for a in self.actions:
            r = by_id.get(a["id"])
            if r is None:
                problems.append(f"{a['id']}: missing from replay result")
                continue
            status = r.get("status")
            self._replay_status[a["id"]] = status
            if status == "denied" and a["class"] in self.prevented:
                problems.append(f"{a['id']}: DENIED but its class is prevented "
                                f"(the enforcement point never sees prevented actions)")
                continue
            if status == "denied":
                # checked-DENY (policy denial): a valid terminal state for a
                # non-prevented action — the enforcement point evaluated the
                # call and refused it. The denial verdict's decision backing
                # is cross-checked in coverage (C2) and the outcome
                # classifier; the served layer (R2) requires absence of effect.
                continue
            if a["class"] in self.prevented:
                # prevented (design t2): the network layer must refuse the
                # attempt. tcp: expect the refusal errno (an `ok` tcp connect
                # would mean the action took effect — a bypass, i.e. the
                # egress policy is NOT in force). udp: `ok` is expected (the
                # send succeeds locally; unconnected sockets do not surface
                # the icmp reject) — the served layer adjudicates effect.
                refused = status == "error" and _REFUSAL_RE.search(r.get("error") or "")
                if a["op"] == "tcp_connect" and not refused:
                    problems.append(f"{a['id']}: tcp connect {status} but egress "
                                    f"is forced ({r.get('error')}?) — prevention broken")
                elif a["op"] != "tcp_connect" and status == "error" and not refused:
                    problems.append(f"{a['id']}: status {status} is not a "
                                    f"network-layer refusal ({r.get('error')})")
            else:
                if status != "ok":
                    problems.append(f"{a['id']}: status {status} ({r.get('error')})")
            for field in ("class", "op"):
                if r.get(field) != a[field]:
                    problems.append(f"{a['id']}: {field} {r.get(field)!r} != "
                                    f"spec {a[field]!r}")
        n_prevented = sum(1 for a in self.actions if a["class"] in self.prevented)
        self.check("R1-replay-layer", not problems,
                   f"{len(results)} results; " +
                   (f"all actions match the spec ({n_prevented} prevented by "
                    f"egress refused as expected)" if not problems
                    else "; ".join(problems)))
        return {"executed": self.replay.get("executed"),
                "failed": self.replay.get("failed"),
                "problems": problems,
                "per_action": {r.get("id"): r.get("status") for r in results}}

    # -- R2: served layer ------------------------------------------------------

    def served_in_window(self) -> list[dict]:
        start, end = self.window()
        lo, hi = start - SERVED_TOLERANCE_NS, end + SERVED_TOLERANCE_NS
        out = []
        for rec in self.target_logs:
            ts = _iso_to_epoch_ns(rec.get("ts"))
            if ts is None or lo <= ts <= hi:
                out.append(rec)
        return out

    def reconcile_served(self, served: list[dict]) -> dict:
        per_action = {a["id"]: [] for a in self.actions}
        if not self.target_logs:
            self.check("R2-served-layer", True,
                       "target logs not provided; served layer skipped "
                       "(kernel expected count ranges are the only per-action "
                       "evidence for pooled transports)", hard=False)
            return {"available": False, "per_action": per_action}

        by_target: dict[str, list[dict]] = {}
        for rec in served:
            by_target.setdefault(rec.get("target", ""), []).append(rec)

        # served-target names are profile-configurable: the MCP stdio server
        # logs under its SERVER_NAME ("toy-mcp-fs"), not the class name
        st = self.profile.get("served_targets", {})
        t_http = st.get("http", "http-endpoint")
        t_mcp = st.get("stdio", "toy-mcp-fs")
        t_net = st.get("network", "net-peer")

        def hits(target: str, pred) -> list[dict]:
            return [r for r in by_target.get(target, []) if pred(r)]

        problems = []
        for a in self.actions:
            denied = self._replay_status.get(a["id"]) == "denied"
            if a["class"] == "http_tool_call":
                if denied:
                    # checked-DENY: the call was refused before execution —
                    # the endpoint must NOT show the request (body-level
                    # evidence disambiguates same-route instances)
                    body = (a.get("args") or {}).get("body")
                    h = hits(t_http, lambda r: r.get("event") == "request"
                             and r.get("method") == a["op"]
                             and r.get("path") == a.get("args", {}).get("path")
                             and (body is None or r.get("body_text") == body))
                    if h:
                        per_action[a["id"]] = ["served"]
                        problems.append(f"{a['id']} ({a['class']}/{a['op']}): SERVED "
                                        f"though the enforcement point denied it")
                    continue
                h = hits(t_http, lambda r: r.get("event") == "request"
                         and r.get("method") == a["op"]
                         and r.get("path") == a.get("args", {}).get("path"))
            elif a["class"] == "stdio_tool_call":
                if denied:
                    h = hits(t_mcp, lambda r: r.get("event") == "tool_call"
                             and r.get("op") == a["op"])
                    if h:
                        per_action[a["id"]] = ["served"]
                        problems.append(f"{a['id']} ({a['class']}/{a['op']}): SERVED "
                                        f"though the enforcement point denied it")
                    continue
                h = hits(t_mcp, lambda r: r.get("event") == "tool_call"
                         and r.get("op") == a["op"])
            elif a["class"] == "direct_network":
                transport = "tcp" if a["op"] == "tcp_connect" else "udp"
                h = hits(t_net, lambda r: r.get("event") == "received"
                         and r.get("transport") == transport)
                if a["class"] in self.prevented:
                    # prevented (design t2): the target must NOT have served —
                    # any served evidence means the action took effect, i.e.
                    # the egress policy is not in force (a bypass)
                    if h:
                        per_action[a["id"]] = ["served"]
                        problems.append(f"{a['id']} ({a['class']}/{a['op']}): SERVED though "
                                        f"egress is forced (design {self.design})")
                    continue
            else:
                continue  # spawn/file/credential have no target-facing log
            if h:
                per_action[a["id"]] = ["served"]
            else:
                problems.append(f"{a['id']} ({a['class']}/{a['op']}): not served")
        self.check("R2-served-layer", not problems,
                   "all target-facing actions served within the window"
                   if not problems else "; ".join(problems))
        return {"available": True, "per_action": per_action}

    # -- scoping + unrelated events (window / container / list) ------------------

    def in_scope(self) -> tuple[list[dict], dict]:
        start, end = self.window()
        cid = self.container_id
        stats = {"records_total": len(self.mapped), "in_window": 0,
                 "in_container": 0, "in_scope": 0}
        scoped = []
        in_window_all: list[dict] = []
        for rec in self.mapped:
            ts = rec.get("ts")
            if ts is not None and not (start <= ts <= end):
                continue
            stats["in_window"] += 1
            in_window_all.append(rec)
            if cid is not None and (rec.get("container") or "") != cid:
                continue
            stats["in_container"] += 1
            scoped.append(rec)
        stats["in_scope"] = len(scoped)
        self._in_window_all = in_window_all
        return scoped, stats

    def pre_window_source(self, rec: dict) -> dict | None:
        """Latest non-failed exec for this PID/container, from the full capture.

        Use exact argv at the call site; processName alone is not attribution.
        Later execs terminate the binding, so a reused PID cannot inherit it.
        """
        if type(rec.get("ts")) is not int or type(rec.get("pid")) is not int:
            return None
        candidates = [r for r in self.mapped if r.get("event") == "execve"
                      and r.get("container") == rec.get("container") and r.get("pid") == rec["pid"]
                      and type(r.get("ts")) is int and r["ts"] <= rec["ts"]
                      and flatten(r)["retval"] == 0]
        return max(candidates, key=lambda r: (r["ts"], (r.get("provenance") or {}).get("raw_index", -1)),
                   default=None)

    @staticmethod
    def exec_argv(rec: dict | None):
        return ((rec or {}).get("detail") or {}).get("cmd")

    def split_unrelated(self, scoped: list[dict]) -> tuple[list[dict], list[dict]]:
        """Apply ordinary allowlists and command-bound pre-window readiness.

        Readiness is not a workload allowance: post-start records, unmatched
        commands and over-budget connects remain subject to R3/R4.
        """
        unrelated, account, used = [], [], {}
        start = self.replay["window_epoch_ns"]["start"]
        for rec in scoped:
            flat = flatten(rec)
            before = type(rec.get("ts")) is int and rec["ts"] < start
            attribution = None
            if before:
                for rule in self.profile.get("pre_window_unrelated", []):
                    candidates = [(i, item) for i, item in enumerate(rule["records"])
                                  if match_where(flat, item["where"])]
                    if not candidates:
                        continue
                    source = self.pre_window_source(rec)
                    if self.exec_argv(source) != rule["argv"]:
                        continue
                    for i, item in candidates:
                        key = (rule["id"], source.get("container"), source["pid"], source["ts"], i)
                        if used.get(key, 0) < item.get("max_records", float("inf")):
                            used[key] = used.get(key, 0) + 1
                            attribution = {"record": rec, "rule": rule["id"], "reason": rule["reason"],
                                           "source_exec": {**self._ref(source), "argv": self.exec_argv(source)}}
                            break
                    if attribution:
                        break
            if attribution:
                unrelated.append(attribution)
                continue
            for rule in self.profile.get("unrelated_events", []):
                if rule.get("before_replay") and not before:
                    continue
                if match_where(flat, rule.get("where", {})):
                    unrelated.append({"record": rec, "rule": rule.get("id", "?"),
                                      "reason": (rule.get("reason") or "").strip()})
                    break
            else:
                account.append(rec)
        return unrelated, account

    # -- R3: kernel layer --------------------------------------------------------

    def _extra_match(self, flat: dict) -> dict | None:
        for extra in self.profile.get("expected_extras", []):
            attribution = match_extra(flat, extra)
            if attribution:
                return attribution
        return None

    def kernel_per_action(self, cls: str, recs: list[dict]) -> dict:
        """Per-action kernel support by exact target match; unmatched records
        must be profile expected-extras or they become leftovers."""
        actions = self.by_class[cls]
        spec_targets = {a["target"] for a in actions}
        path_groups: dict[str, list[dict]] = {}
        for rec in recs:
            path = flatten(rec)["path"]
            path_groups.setdefault(path, []).append(rec)

        # spawn multiplicity: failed execve attempts (e.g. failed PATH
        # lookups that slipped past the unrelated-events list) must not
        # count as spawns
        if cls == "process_spawn":
            for path, group in list(path_groups.items()):
                ok_rec = [r for r in group if (flatten(r)["retval"] or 0) == 0]
                failed = [r for r in group if r not in ok_rec]
                path_groups[path] = ok_rec
                for rec in failed:
                    self.leftovers.append({**self._ref(rec),
                                           "disposition": "failed-execve",
                                           "detail": {"class": cls, "path": path}})

        supported = [bool(path_groups.get(a["target"])) for a in actions]

        # multiplicity expected count range: documented opens per action
        mult_problems = []
        rng = self.mult.get({"file_write": "file_write_opens_per_action",
                             "credential_access": "credential_opens_per_action"
                             }.get(cls))
        if rng:
            for path, group in path_groups.items():
                if path in spec_targets and not rng[0] <= len(group) <= rng[1]:
                    mult_problems.append(f"{path}: {len(group)} opens not in {rng}")

        # leftover detection: any record whose target matches neither a spec
        # action nor a profile expected-extra is unexplained
        for path, group in path_groups.items():
            if path in spec_targets:
                continue
            for rec in group:
                extra = self._extra_match(flatten(rec))
                if extra:
                    self.extras.append({**self._ref(rec),
                                        "extra": extra["extra"],
                                        "due_to": extra["due_to"]})
                else:
                    self.leftovers.append({**self._ref(rec),
                                           "disposition": "unmatched",
                                           "detail": {"class": cls, "path": path}})

        return {
            "spec": len(actions),
            "supported": [bool(path_groups.get(a["target"])) for a in actions],
            "kernel_raw": len(recs),
            "evidence": "kernel-per-action",
            "matched": {p: len(g) for p, g in path_groups.items() if p in spec_targets},
            "problems": mult_problems,
        }

    def calibrated_stdio(self, recs: list[dict]) -> dict:
        """Derive extras from each real no-tool config pre-window events, not a
        guessed count.

        Only start(pid) -> initialize -> tools/list -> first tools/call (or
        stop) transcript intervals qualify. Sizes are diagnostics, not matching
        signatures. The registered-server mapping and PID bind response writes
        to the transcript. Full capture is needed even if startup precedes the
        measurement/tolerance window.
        """
        pin = self.mult["stdio_startup_calibration"]
        target = self.profile.get("served_targets", {}).get("stdio", "toy-mcp-fs")
        # Snapshots are cumulative; identical transcript rows must count once.
        unique = {json.dumps(r, sort_keys=True): r for r in self.calibration_logs
                  if r.get("target") == target}
        transcript = sorted(unique.values(), key=lambda r: _iso_to_epoch_ns(r.get("ts")) or 0)
        sessions, current = [], None
        for row in transcript:
            ts = _iso_to_epoch_ns(row.get("ts"))
            if ts is None:
                continue
            if row.get("event") == "start":
                current = {"pid": row.get("pid"), "start": ts, "transcript": [row], "requests": []}
                sessions.append(current)
            elif current is not None and "end" not in current:
                current["transcript"].append(row)
                if row.get("event") == "request":
                    if row.get("method") == "tools/call":
                        current["end"] = ts
                    elif row.get("method") in ("initialize", "tools/list"):
                        current["requests"].append((row["method"], ts))
                elif row.get("event") == "stop":
                    current["end"] = ts
        mapped = [r for r in self.mapped if r.get("class") == "stdio_tool_call"
                  and r.get("event") == "write" and (r.get("detail") or {}).get("fd") == 1
                  and (self.container_id is None or r.get("container") == self.container_id)]
        problems, calibrated, startup_keys = [], [], set()
        lo, hi = self.window()

        def key(r):
            return ((r.get("provenance") or {}).get("raw_index"), r.get("pid"), r.get("ts"))

        for s in sessions:
            writes = [r for r in mapped if r.get("pid") == s["pid"]
                      and type(r.get("ts")) is int
                      and s["start"] <= r["ts"] < s.get("end", s["start"])]
            writes.sort(key=lambda r: r["ts"])
            reqs = s["requests"]
            valid = (type(s["pid"]) is int and [x[0] for x in reqs] == ["initialize", "tools/list"]
                     and len(writes) == pin["writes_per_startup"] == 2
                     and reqs[0][1] <= writes[0]["ts"] <= reqs[1][1]
                     and reqs[1][1] <= writes[1]["ts"]
                     and all((flatten(r)["retval"] or 0) > 0 for r in writes))
            if not valid:
                problems.append(f"startup pid={s['pid']}: expected two request-correlated response writes; "
                                f"observed {len(writes)} writes, requests {[x[0] for x in reqs]}")
            else:
                startup_keys.update(key(r) for r in writes)
            calibrated.append({"pid": s["pid"], "window_epoch_ns": {"start": s["start"], "end": s.get("end")},
                               "status": "pass" if valid else "fail",
                               "expected_writes": pin["writes_per_startup"], "observed_writes": len(writes),
                               "in_scope_writes": sum(lo <= r["ts"] <= hi for r in writes),
                               "writes": [{**self._ref(r), "bytes": flatten(r)["retval"]} for r in writes],
                               "transcript": s["transcript"],
                               "transcript_sha256": hashlib.sha256(json.dumps(s["transcript"], sort_keys=True).encode()).hexdigest()})
        if not sessions:
            problems.append("startup transcript missing; no calibration pre-window events")
        intersecting = sum(s["in_scope_writes"] > 0 for s in calibrated)
        extra = [r for r in recs if key(r) in startup_keys]
        workload = len(recs) - len(extra)
        n = sum(self._replay_status.get(a["id"]) != "denied" for a in self.by_class["stdio_tool_call"])
        bounds = [n + x for x in pin["extra_writes"]]
        if intersecting > pin["max_startups_in_window"]:
            problems.append(f"{intersecting} startups exceed pinned {pin['max_startups_in_window']}")
        if workload != n:
            problems.append(f"{workload} non-startup writes != {n} tool responses")
        if not bounds[0] <= len(recs) <= bounds[1]:
            problems.append(f"{len(recs)} stdio writes outside calibrated {bounds}")
        calibration = {"status": "fail" if problems else "pass", "pin": pin,
                       "expected": {"tool_writes": n, "total_writes": bounds,
                                    "max_startups": pin["max_startups_in_window"]},
                       "observed": {"tool_writes": workload, "startup_writes": len(extra),
                                    "total_writes": len(recs), "startups_in_window": intersecting},
                       "sessions": calibrated, "problems": problems}
        return {"spec": len(self.by_class["stdio_tool_call"]), "kernel_raw": len(recs),
                "evidence": "kernel-group+calibrated-startup-pre-window", "problems": problems,
                "calibration": calibration}

    def calibrated_gateway_stdio(self) -> dict:
        """Native stdout *frames*, never harness syscalls or fs-sibling writes.

        Derive each no-tool pre-window event sequence from the frozen bridge
        wire and bind it to the exact gateway exec/session lifetime. HTTP
        remains kernel support.
        """
        pin = self.mult["stdio_startup_calibration"]
        problems, sessions = [], []
        starts = [r for r in self.gateway_lifecycle if r.get("event") == "start"]
        if not starts or not self.gateway_stdio_wire:
            problems.append("gateway startup wire/lifecycle missing")
        ids = [r.get("session") for r in starts]
        if any(not isinstance(s, str) or not s for s in ids) or len(set(ids)) != len(ids):
            problems.append("gateway startup sessions missing or duplicated")
        if any(r.get("session") not in ids for r in self.gateway_stdio_wire):
            problems.append("gateway wire has an unbound session")
        lo, hi = self.window()
        rw = self.replay["window_epoch_ns"]
        for start in starts:
            sid, pid, ts = start.get("session"), start.get("pid"), start.get("received_epoch_ns")
            stops = [r for r in self.gateway_lifecycle if r.get("event") == "stop" and r.get("pid") == pid
                     and type(r.get("received_epoch_ns")) is int and type(ts) is int
                     and r["received_epoch_ns"] >= ts]
            end = min((r["received_epoch_ns"] for r in stops), default=hi)
            rows = [r for r in self.gateway_stdio_wire if r.get("session") == sid]
            errors, decoded = [], []
            if len(stops) != 1:
                errors.append("gateway stop lifetime missing or ambiguous")
            if (type(pid) is not int or pid <= 0 or type(ts) is not int or ts <= 0
                    or start.get("argv") != pin["gateway_argv"]):
                errors.append("gateway lifecycle PID/argv/time mismatch")
            last = ts if type(ts) is int else 0
            for row in rows:
                stamp = row.get("received_epoch_ns")
                if type(stamp) is not int or not last <= stamp <= end:
                    errors.append("wire outside gateway lifetime or out of order")
                else:
                    last = stamp
                if type(stamp) is not int:
                    continue  # Already failed; do not compare malformed timestamps below.
                try:
                    msg = (row["message"] if row.get("direction") == "stdin"
                           else json.loads(row["raw_line"]) if row.get("direction") == "stdout" else None)
                except (KeyError, TypeError, ValueError):
                    msg = None
                if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
                    errors.append("invalid gateway wire frame")
                else:
                    decoded.append((row, msg))
            first_call = next((i for i, (r, m) in enumerate(decoded)
                               if r["direction"] == "stdin" and m.get("method") == "tools/call"), len(decoded))
            pre_window = decoded[:first_call]
            requests = [(r, m) for r, m in pre_window if r["direction"] == "stdin"]
            frames = [(r, m) for r, m in pre_window if r["direction"] == "stdout"]
            if [m.get("method") for _, m in requests] != ["initialize", "notifications/initialized", "tools/list"]:
                errors.append("gateway pre-window request sequence mismatch")
            replies = [(r, m) for r, m in frames if "id" in m]
            notifications = [m.get("method") for _, m in frames if "id" not in m]
            correlated = [requests[i] for i in (0, 2)] if len(requests) == 3 else []
            if (len(replies) != 2 or len(correlated) != 2
                    or len({m.get("id") for _, m in correlated}) != 2
                    or any("id" not in req or resp.get("id") != req["id"] or "result" not in resp or "error" in resp
                           or r["received_epoch_ns"] < q["received_epoch_ns"]
                           for (q, req), (r, resp) in zip(correlated, replies))
                    or (len(requests) == 3 and len(replies) == 2
                        and replies[0][0]["received_epoch_ns"] > requests[1][0]["received_epoch_ns"])):
                errors.append("gateway pre-window response ID/time mismatch")
            if notifications != pin["notification_methods"] or len(frames) != pin["stdout_frames_per_startup"]:
                errors.append("gateway pre-window stdout frame count mismatch")
            role = "replay" if first_call < len(decoded) else "readiness"
            if role == "replay":
                call_ts = decoded[first_call][0]["received_epoch_ns"]
                if not rw["start"] <= call_ts <= rw["end"]:
                    errors.append("gateway tool call outside replay window")
            elif any(r["received_epoch_ns"] >= rw["start"] for r, _ in pre_window):
                errors.append("readiness pre-window events not before replay")
            in_scope = sum(type(r.get("received_epoch_ns")) is int and lo <= r["received_epoch_ns"] <= hi
                           for r, _ in frames)
            sessions.append({"session": sid, "pid": pid, "role": role, "lifecycle": start,
                             "status": "fail" if errors else "pass", "observed_frames": len(frames),
                             "in_scope_frames": in_scope, "transcript": [r for r, _ in pre_window],
                             "transcript_sha256": hashlib.sha256(json.dumps([r for r, _ in pre_window], sort_keys=True).encode()).hexdigest()})
            problems += [f"session {sid}: {e}" for e in errors]
        intersecting = sum(s["in_scope_frames"] > 0 for s in sessions)
        extras = sum(s["in_scope_frames"] for s in sessions)
        if len(sessions) > pin["max_startups_in_window"] or intersecting > pin["max_startups_in_window"]:
            problems.append("gateway startups exceed pinned maximum")
        if sum(s["role"] == "replay" for s in sessions) != 1 or sum(s["role"] == "readiness" for s in sessions) > 1:
            problems.append("expected one replay and at most one readiness gateway session")
        if not pin["extra_frames"][0] <= extras <= pin["extra_frames"][1]:
            problems.append("gateway startup frames outside pinned frame range")
        return {"status": "fail" if problems else "pass", "kind": "gateway-wire", "pin": pin,
                "scope": "gateway native protocol only; not harness kernel writes",
                "expected": {"frames_per_startup": pin["stdout_frames_per_startup"],
                             "extra_frames": pin["extra_frames"], "max_startups": pin["max_startups_in_window"]},
                "observed": {"startup_frames": extras, "startups_in_window": intersecting,
                             "sessions": len(sessions)}, "sessions": sessions, "problems": problems}

    def calibrated_http(self, recs: list[dict], n: int | None = None) -> dict:
        """Separate GatewayClient's discovery pre-window events from canonical
        connects.

        The tolerance window may include current Pi discovery plus the
        preceding Node readiness client. Neither is a tool decision. Bind both to exact exec argv and
        retain the ledger; do not borrow evidence from another container (T3).
        """
        pin = self.mult["http_startup_calibration"]
        start = self.replay["window_epoch_ns"]["start"]
        startups, workload, problems, ledger = {}, [], [], []
        for rec in recs:
            source = self.pre_window_source(rec)
            argv = self.exec_argv(source)
            before = type(rec.get("ts")) is int and rec["ts"] < start
            valid = (rec.get("event") == "connect" and flatten(rec)["port"] == pin["port"]
                     and flatten(rec)["transport"] == "tcp"
                     and bool(self.container_id) and rec.get("container") == self.container_id
                     and argv in (pin["replay_argv"], pin["readiness_argv"]))
            role = "replay" if argv == pin["replay_argv"] else "readiness"
            if not valid or (not before and role != "replay"):
                problems.append(f"unattributed HTTP connect raw_index={self._ref(rec)['raw_index']}")
            elif before:
                startups.setdefault((role, rec["pid"], source["ts"]), []).append(rec)
            else:
                workload.append(rec)
            ledger.append({**self._ref(rec), "container": rec.get("container"),
                           "port": flatten(rec)["port"], "phase": "startup" if before else "workload",
                           "status": "pass" if valid and (before or role == "replay") else "fail",
                           "source_exec": {**self._ref(source), "argv": argv} if source else None})
        if len(startups) > pin["max_startups_in_window"]:
            problems.append(f"{len(startups)} HTTP startups exceed pinned {pin['max_startups_in_window']}")
        for (role, pid, _), group in startups.items():
            if len(group) > pin["connects_per_startup"]:
                problems.append(f"startup {role} pid={pid}: {len(group)} connects exceed {pin['connects_per_startup']}")
        for role in ("replay", "readiness"):
            if sum(k[0] == role for k in startups) > 1:
                problems.append(f"multiple {role} startup clients")
        n = len(self.by_class["http_tool_call"]) if n is None else n
        lo = int(self.mult.get("http_connects_min", 1))
        # Preserve the standard pooled 1..N contract; per-action backing is
        # R2 + native decisions/C1-C4, never inferred from connection counts.
        if not lo <= len(workload) <= max(n, lo):
            problems.append(f"{len(workload)} workload connects outside [{lo}, {max(n, lo)}]")
        calibration = {"status": "fail" if problems else "pass", "pin": pin,
                       "expected": {"workload_connects": [lo, max(n, lo)],
                                    "max_startups": pin["max_startups_in_window"],
                                    "max_connects_per_startup": pin["connects_per_startup"]},
                       "observed": {"workload_connects": len(workload), "startups": len(startups),
                                    "startup_connects": sum(map(len, startups.values()))},
                       "records": ledger, "problems": problems}
        return {"spec": n, "kernel_raw": len(recs), "evidence": "kernel-group+calibrated-http-pre-window",
                "problems": problems, "calibration": calibration}

    def kernel_group(self, cls: str, recs: list[dict]) -> dict:
        """Group kernel support under the documented expected count range."""
        if (cls == "http_tool_call" and "http_startup_calibration" in self.mult
                and not self.mult["http_startup_calibration"].get("all_tool_classes")):
            return self.calibrated_http(recs)
        if (cls == "stdio_tool_call" and "stdio_startup_calibration" in self.mult
                and self.mult["stdio_startup_calibration"].get("kind") != "gateway-wire"):
            return self.calibrated_stdio(recs)
        actions = self.by_class[cls]
        n = len(actions)
        problems = []
        if cls == "stdio_tool_call":
            if self.design in ("t4", "t5", "t6"):
                # T4: pi's MCP config clients hold the connections — the fs
                # server's initialize + tools/list responses may land inside
                # the window (the command marks the window before the agent
                # run; the config handshake completes around it). Expected:
                # the 3 tool-response writes plus 0..2 config-handshake writes.
                if not n <= len(recs) <= n + 2:
                    problems.append(f"{len(recs)} stdio writes outside "
                                    f"[{n}, {n + 2}] (tool responses + config handshake)")
            else:
                handshake = int(self.mult.get("stdio_handshake_extra_writes", 1))
                expected = n + handshake
                if len(recs) != expected:
                    problems.append(f"{len(recs)} response writes != expected "
                                    f"{expected} ({n} tool calls + {handshake} handshake)")
        elif cls == "http_tool_call":
            lo = int(self.mult.get("http_connects_min", 1))
            hi = max(n, lo)
            if not lo <= len(recs) <= hi:
                problems.append(f"{len(recs)} pooled connects outside [{lo}, {hi}]")
        else:  # direct_network
            tcp = [r for r in recs if flatten(r)["transport"] == "tcp"
                   or flatten(r)["event"] == "connect"]
            udp = [r for r in recs if r not in tcp]
            n_tcp = len([a for a in actions if a["op"] == "tcp_connect"])
            n_udp = len([a for a in actions if a["op"] == "udp_send"])
            if cls in self.prevented:
                # prevented (design t2): kernel evidence is the ATTEMPT.
                # TCP: connect events fire regardless of outcome (rejected
                # connects still map via port 9000) and must equal the spec
                # count. UDP: net_packet_udp may not fire when netfilter
                # rejects the packet at the output hook, so the raw sendmsg
                # syscalls (allowlisted as node-socket-churn unrelated
                # events) are the attempt evidence; a lower bound suffices
                # there — effect is adjudicated by the served layer (R2
                # requires absence).
                if len(tcp) != n_tcp:
                    problems.append(f"{len(tcp)} tcp connect attempts != {n_tcp}")
                unrelated_udp = sum(1 for n in self._unrelated
                                if (n.get("record") or {}).get("event") == "sendmsg")
                if n_udp and len(udp) + unrelated_udp < n_udp:
                    problems.append(f"{len(udp)} udp + {unrelated_udp} unrelated sendmsg "
                                    f"< {n_udp} attempted datagrams")
            else:
                if len(tcp) != n_tcp:
                    problems.append(f"{len(tcp)} tcp connects != {n_tcp}")
                udp_max = int(self.mult.get("udp_max_per_action", 2))
                if n_udp and not n_udp <= len(udp) <= n_udp * udp_max:
                    problems.append(f"{len(udp)} udp observations outside "
                                    f"[{n_udp}, {n_udp * udp_max}]")
        return {
            "spec": n, "kernel_raw": len(recs),
            "evidence": "kernel-group", "problems": problems,
        }

    # -- R3 + R4 ---------------------------------------------------------------

    def pooled_gateway_records(self, account: list[dict]) -> list[dict]:
        """In-window, allowlisted-as-unrelated pooled-origin connect records
        from ANY container (see the T3 pooled-evidence note above): the
        harness's connects INTO the gateway (gateway:8090) and the gateway's
        own downstream connects to the endpoint (http-endpoint:8080 —
        reachable only through the gateway under forced egress)."""
        scoped_http = [r for r in account if r.get("class") == "http_tool_call"]
        if self.profile.get("deployment_axes", {}).get("shared_tool_pool") == "harness-only":
            return scoped_http
        seen = {id(r) for r in scoped_http}
        unrelated_ids = {id(n["record"]) for n in self._unrelated}
        extra = []
        for rec in self._in_window_all:
            if id(rec) in seen or id(rec) in unrelated_ids:
                continue
            if rec.get("class") == "http_tool_call":
                extra.append(rec)
        return scoped_http + extra

    def reconcile_kernel(self, account: list[dict]) -> dict:
        by_class: dict[str, list[dict]] = {"unmapped": []}
        for rec in account:
            by_class.setdefault(rec.get("class", "unmapped"), []).append(rec)

        per_class: dict[str, dict] = {}
        for cls in SIX_CLASSES:
            if (self.design in T3_SHARED_POOL_DESIGNS
                    and cls in T3_TOOL_CLASSES):
                # T3: all tool calls cross the gateway on one pooled origin —
                # the kernel connects are shared between the two tool classes
                # and not attributable per class (the T3 finding itself).
                # Evidence: pooled-connect expected count range + served
                # per-action + gateway decisions (coverage layer). The range
                # counts in-window connects to the gateway origin from ANY
                # testbed container (the harness or its proxied upstreams):
                # node's connection pooling may establish the harness's
                # connect BEFORE the measurement window, and every in-window
                # call then reuses it (observed live 2026-10-07 — a warm
                # openclaw pool yielded 0 harness connects in-window while
                # the calls crossed and were served). Records from other
                # containers are still checked against the unrelated-events
                # list before counting.
                recs = self.pooled_gateway_records(account)
                n_tool_calls = (len(self.by_class["stdio_tool_call"])
                                + len(self.by_class["http_tool_call"]))
                if self.profile.get("deployment_axes", {}).get("shared_tool_pool") == "harness-only":
                    result = self.calibrated_http(recs, n_tool_calls)
                    # This topology has no harness-local stdio tool server.
                    # Never silently absorb bypass writes into the HTTP pool.
                    if by_class.get("stdio_tool_call"):
                        result["problems"].append(
                            f"{len(by_class['stdio_tool_call'])} unexpected harness stdio tool records")
                    result["spec"] = len(self.by_class[cls])
                    result["evidence"] = "kernel-harness-shared+calibrated-http-pre-window"
                    if (cls == "stdio_tool_call" and self.mult.get("stdio_startup_calibration", {}).get("kind") == "gateway-wire"):
                        result["http_calibration"] = result["calibration"]
                        result["calibration"] = self.calibrated_gateway_stdio()
                        result["problems"].extend(result["calibration"]["problems"])
                        result["evidence"] += "+gateway-stdio-wire-pre-window"
                else:
                    problems = []
                    # The pooled expected count range upper bound: a
                    # pooling client contributes ~1 gateway connect (pi) and the gateway's
                    # downstream connects to the http endpoint (one per
                    # http twin) are the per-call evidence; a no-pooling
                    # client (the mock harness, plain python) contributes
                    # one connect per tool call, so the bound that holds for
                    # both is n_tool_calls + n_http (e.g. t3: 1+4=5 pi,
                    # 7+4=11 mock; DESIGN.md 9 kernel evidence).
                    upper = n_tool_calls + len(self.by_class["http_tool_call"])
                    if not 1 <= len(recs) <= upper:
                        problems.append(f"{len(recs)} pooled gateway connects "
                                        f"outside [1, {upper}]")
                    result = {"spec": len(self.by_class[cls]),
                              "kernel_raw": len(recs),
                              "evidence": "kernel-pooled-shared",
                              "problems": problems}
            else:
                recs = by_class.get(cls, [])
                result = (self.kernel_per_action(cls, recs)
                          if cls in PER_ACTION_CLASSES
                          else self.kernel_group(cls, recs))
            served_ok = True
            if cls in self.prevented:
                # prevented (design t2): the target must NOT have served —
                # any served evidence means the action took effect (a bypass,
                # i.e. the egress policy is not in force)
                if cls in SERVED_CLASSES and self.target_logs:
                    served_ok = all(not self._served_per_action.get(a["id"])
                                    for a in self.by_class[cls])
                    result["evidence"] += "+served-absence"
            elif cls in SERVED_CLASSES and self.target_logs:
                # checked-DENY instances are required NOT to have served
                # (their R2 absence check ran in reconcile_served); they are
                # exempt from the served-per-action requirement here
                to_check = [a for a in self.by_class[cls]
                            if self._replay_status.get(a["id"]) != "denied"]
                served_ok = all(self._served_per_action.get(a["id"])
                                for a in to_check)
                result["evidence"] += "+served-per-action"
            if "supported" in result:  # per-action classes
                ok = all(result["supported"]) and not result["problems"] and served_ok
            else:  # group classes: expected count range + served evidence
                ok = not result["problems"] and served_ok
            per_class[cls] = result
            self.check(f"R3-kernel-{cls}", ok,
                       f"{result['kernel_raw']} kernel observations; " +
                       ("expected range satisfied" if not result["problems"]
                        else "; ".join(result["problems"])))

        # R4: leftovers — every in-scope record must be accounted for
        for rec in by_class.get("unmapped", []):
            self.leftovers.append({**self._ref(rec), "disposition": "unmatched",
                                   "detail": flatten(rec)})
        for cls, recs in by_class.items():
            if cls in SIX_CLASSES or cls == "unmapped":
                continue
            for rec in recs:
                self.leftovers.append({**self._ref(rec), "disposition": "unknown-class",
                                       "detail": {"class": cls}})

        return per_class

    # -- effective counts (R5) ------------------------------------------------

    def effective_counts(self, per_class: dict) -> dict:
        eff = {}
        for cls in SIX_CLASSES:
            actions = self.by_class[cls]
            if cls in PER_ACTION_CLASSES:
                eff[cls] = sum(1 for ok, a in zip(per_class[cls]["supported"], actions) if ok)
            elif self.target_logs:
                # pooled transports: per-action evidence comes from the
                # served layer (kernel observations are multiplexed)
                eff[cls] = sum(1 for a in actions if self._served_per_action.get(a["id"]))
            else:
                eff[cls] = len(actions) if not per_class[cls]["problems"] else 0
        return eff

    # -- orchestration ---------------------------------------------------------

    def run(self) -> dict:
        replay = self.reconcile_replay()
        served_recs = self.served_in_window()
        served = self.reconcile_served(served_recs)
        self._served_per_action = served["per_action"]

        scoped, stats = self.in_scope()
        unrelated, account = self.split_unrelated(scoped)
        self._unrelated = unrelated
        per_class = self.reconcile_kernel(account)
        effective = self.effective_counts(per_class)

        spec_counts = {c: len(self.by_class[c]) for c in SIX_CLASSES}
        # expected effective counts: spec ground truth minus the classes the
        # design's network-layer policy prevents (design t2: direct_network
        # must NOT take effect; their effective count is 0 by construction —
        # the served layer adjudicates effect and R2 requires absence) and
        # minus the instances the enforcement point denied (checked-DENY:
        # evaluated but not effective — R2 requires absence per instance)
        denied_by_class: dict[str, int] = {}
        for a in self.actions:
            if self._replay_status.get(a["id"]) == "denied":
                denied_by_class[a["class"]] = denied_by_class.get(a["class"], 0) + 1
        expected = dict(spec_counts)
        for c in self.prevented:
            expected[c] = 0
        for c, n in denied_by_class.items():
            expected[c] = max(0, expected[c] - n)
        r5 = effective == expected
        self.check("R5-effective-counts", r5,
                   f"effective counts match spec minus prevented "
                   f"{sorted(self.prevented)} minus denied "
                   f"{sorted(denied_by_class)} "
                   f"({sum(expected.values())} effective actions)" if r5 else
                   f"mismatch: effective {effective} vs expected {expected} "
                   f"(spec {spec_counts}, prevented {sorted(self.prevented)}, "
                   f"denied {denied_by_class})")
        self.check("R4-leftovers", not self.leftovers,
                   f"{len(account)} in-scope records fully accounted "
                   f"({len(unrelated)} unrelated events allowlisted)" if not self.leftovers
                   else f"{len(self.leftovers)} leftover records (see report)")

        hard_fail = any(c["status"] == "fail" for c in self.checks if c["hard"])
        return {
            "schema": "inspection-reconciliation/1",
            "status": "fail" if hard_fail else "pass",
            "harness": self.profile["harness"],
            "profile": self.profile["profile"],
            "spec": {"name": self.spec["meta"]["name"],
                     "version": self.spec["meta"]["version"],
                     "actions": len(self.actions)},
            "window_epoch_ns": self.replay.get("window_epoch_ns"),
            "container_id": self.container_id,
            "scope": stats,
            "replay": replay,
            "served": {"available": served["available"],
                       "per_action": self._served_per_action},
            "kernel": {"per_class": per_class,
                       "noise_count": len(unrelated),
                       "account_count": len(account),
                       "scoped_records": scoped,
                       "extras": self.extras,
                       "noise": [{"rule": n["rule"], "reason": n["reason"],
                                  **self._ref(n["record"]), "detail": flatten(n["record"]),
                                  **({"source_exec": n["source_exec"]} if "source_exec" in n else {})}
                                 for n in unrelated]},
            "ground_truth_counts": spec_counts,
            "effective_counts": effective,
            "leftovers": self.leftovers,
            "checks": self.checks,
        }


# --- CLI ------------------------------------------------------------------------


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--harness", required=True, choices=["openclaw", "pi"])
    ap.add_argument("--spec", type=Path, default=HERE / "trace" / "traces" / "baseline.yaml")
    ap.add_argument("--mapped", type=Path, required=True,
                    help="mapped-action JSONL (map_events.py output)")
    ap.add_argument("--replay", type=Path, required=True, help="replay-result.json")
    ap.add_argument("--target-logs", action="append", default=[],
                    help="target served-action log file or dir (repeatable)")
    ap.add_argument("--calibration-target-logs", action="append", default=[],
                    help="startup-only transcript evidence, including adjacent replay snapshots (repeatable)")
    ap.add_argument("--container-id", default=None,
                    help="harness container id (docker inspect -f '{{.Id}}' <name>)")
    ap.add_argument("--design", default="t0", choices=sorted(PREVENTED_CLASSES),
                    help="deployment design (design-aware prevented-class checks)")
    ap.add_argument("--profile", type=Path, default=None,
                    help="profile YAML (default runner/profiles/<harness>.yaml)")
    ap.add_argument("--out", type=Path, default=None, help="report JSON path")
    args = ap.parse_args()

    profile_path = args.profile or (HERE / "runner" / "profiles" / f"{args.harness}.yaml")
    try:
        spec = load_spec(args.spec)
        profile = load_profile(profile_path)
        replay = load_replay(args.replay)
        mapped = load_mapped(args.mapped)
        target_logs = load_target_logs(args.target_logs) if args.target_logs else None
        calibration_logs = load_target_logs(args.calibration_target_logs) if args.calibration_target_logs else None
    except (OSError, ValueError, KeyError, yaml.YAMLError) as exc:
        print(f"reconcile: error: {exc}", file=sys.stderr)
        return 2

    rec = Reconciler(spec, profile, replay, mapped, target_logs, args.container_id,
                     design=args.design, calibration_logs=calibration_logs)
    report = rec.run()

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report, indent=1, sort_keys=True) + "\n")
    print(json.dumps({"status": report["status"],
                      "effective_counts": report["effective_counts"],
                      "leftovers": len(report["leftovers"]),
                      "out": str(args.out) if args.out else None}, indent=1))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())