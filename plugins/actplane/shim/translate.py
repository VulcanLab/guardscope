#!/usr/bin/env python3
"""ActPlane match-event shim (plugins/actplane/shim/translate.py).

Translates the pinned ActPlane config-at-load loader's match-event stream
(decision-record/1 is emitted by the control supervisor from this) into
decision-record/1 (DESIGN.md 3 "Shims are not a separate tier":
record_source ingested, mandatory raw_ref provenance per record).

The loader emits ONE JSON OBJECT PER LINE (verified live 2026-11-01 on the
T7 acceptance host; samples below are verbatim captures):

    {"timestamp":436729180567,"event":"TAINT_VIOLATION","effect":"kill",
     "blocked":false,"killed":true,"comm":"cat","pid":5234,"ppid":5228,
     "op":1,"domain_id":0,"session_root":1213,
     "target":"/run/secrets/token","rule_id":4,"taint_label":1,
     "matched_label":1,"matched_labels":1,
     "provenance":{"label":1,"timestamp_ns":436728691714,"pid":5234,
                   "op":0,"ip":0,"target":"cat"}}

    {"timestamp":436729592475,"event":"TAINT_VIOLATION","effect":"notify",
     "blocked":false,"killed":false,"comm":"containerd-shim","pid":1213,
     ...,"op":2,"target":"/proc/self/fd/28","rule_id":1,...}

Field semantics (bpf/taint.h enum taint_op, and the event writer in
bpf/process.c):
  effect: kill | notify | block (the emit-time decision of the rule)
  op:  0 TOP_EXEC    -> process_spawn
       1 TOP_OPEN   -> credential_access under /run/secrets/** only
                       (the taxonomy has no generic file-read class;
                       other opens are expected-extras, skipped)
       2 TOP_WRITE  -> file_write (write/unlink/rename)
       3 TOP_CONNECT-> direct_network
  comm: the acting process name (the kernel position has no tool identity;
        DESIGN.md 1: it identifies actors, not tools)

Infrastructure-noise skip rule (a measurement-scope choice of the SHIM,
recorded here and in the fixture notes): the seeded scope is the harness
container's SHIM process (docker-exec'd harness processes are its
children, not the container init's), so the shim's own bookkeeping
(containerd-shim, runc) appears in the stream. Those events are the
measurement plumbing, not agent behavior, and are skipped.

Streaming: records are emitted as event lines arrive (the control
supervisor pipes `tail -f` into this process; stdin never EOFs mid-run).

Usage:
    translate.py [--stream-id ID] [--run-id ID] [--plugin P]
                 [--plugin-version V] < events.log >> decisions.jsonl
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import time
import uuid
from datetime import datetime, timezone

TOP_EXEC = 0
TOP_OPEN = 1
TOP_WRITE = 2
TOP_CONNECT = 3

SECRET_PREFIX = "/run/secrets/"

# measurement plumbing inside the seeded scope (module docstring)
INFRA_COMM = frozenset({"containerd-shim", "runc"})

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid() -> str:
    t = int(time.time() * 1000)
    rand = int.from_bytes(uuid.uuid4().bytes[:10], "big")
    chars = []
    for shift in range(44, -1, -4):
        chars.append(_CROCKFORD[(t >> shift) & 0xF])
    for shift in range(76, -1, -4):
        chars.append(_CROCKFORD[(rand >> shift) & 0xF])
    return "".join(chars)[:26]


def _now_ms() -> str:
    return (datetime.now(timezone.utc)
            .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z")


def _classify(op: int, target: str) -> str | None:
    if op == TOP_EXEC:
        return "process_spawn"
    if op == TOP_OPEN:
        if (target or "").startswith(SECRET_PREFIX):
            return "credential_access"
        return None
    if op == TOP_WRITE:
        return "file_write"
    if op == TOP_CONNECT:
        return "direct_network"
    return None


def _decision(effect: str, blocked: bool, killed: bool) -> str:
    if effect == "kill" and killed:
        return "deny"
    if effect == "block" and blocked:
        return "deny"
    if effect == "notify":
        return "observe"
    if effect == "kill" or effect == "block":
        # the effect was decided but did not land: the control's own
        # accounting question — an error-class record, never silently
        # treated as an allow
        return "error"
    return "error"


def iter_records(lines, *, stream_id: str, run_id: str, plugin: str,
                 plugin_version: str):
    """Yield one decision record per match event (streaming)."""
    seq = 0
    for lineno, raw in enumerate(lines, start=1):
        raw = raw.strip()
        if not raw or not raw.startswith("{"):
            # loader banners and non-JSON lines are never events
            continue
        try:
            ev = json.loads(raw)
        except json.JSONDecodeError:
            print(f"translate: line {lineno}: unparseable event skipped",
                  file=sys.stderr)
            continue
        if ev.get("event") != "TAINT_VIOLATION":
            continue
        op = ev.get("op")
        target = (ev.get("target") or "").strip()
        action_class = _classify(op, target)
        if action_class is None:
            print(f"translate: line {lineno}: skipped event "
                  f"(op={op!r} target={target[:40]!r} has no canonical "
                  f"action class; expected-extra at reconcile)",
                  file=sys.stderr)
            continue
        comm = ev.get("comm") or ""
        if comm in INFRA_COMM:
            print(f"translate: line {lineno}: skipped event "
                  f"(measurement plumbing: comm={comm!r})",
                  file=sys.stderr)
            continue
        seq += 1
        effect = str(ev.get("effect") or "error")
        blocked = bool(ev.get("blocked"))
        killed = bool(ev.get("killed"))
        digest = hashlib.sha256(
            f"{ev.get('pid')}|{op}|{target}|{comm}".encode()).hexdigest()[:16]
        yield {
            "schema": 1,
            "record_id": _ulid(),
            "run_id": run_id,
            "stream_id": stream_id,
            "seq": seq,
            "ts": _now_ms(),
            "enforcement_point": {
                "slot_id": "kernel-control",
                "product": "actplane",
                "product_version": plugin_version,
            },
            "producer": {
                "plugin": plugin,
                "plugin_version": plugin_version,
                "record_source": "ingested",
            },
            "action_class": action_class,
            # DESIGN.md 4: the kernel position carries no application
            # protocol (schema enum 'none', added with the T7 fixture)
            "protocol": "none",
            # no tool identity below the tool layer: the acting process
            "tool": comm or "unknown",
            "target": {
                "kind": "kernel_path_or_endpoint",
                "value": target,
                "note": f"kernel op={op} comm={comm}",
            },
            "parameters_digest": digest,
            "action_id": None,
            "attempt": 0,
            "correlation_transport": "none",
            "decision": _decision(effect, blocked, killed),
            "policy": {
                "policy_id": "t7-fixture",
                "policy_version": "1",
                # the deployed policy artifact's hash; the runner
                # overwrites this with the manifest hash of the
                # enforcement_config it captured for the run
                "policy_hash": "t7.ap.yaml#runner-hashed",
                "rule_id": f"rule-{ev.get('rule_id')}",
            },
            "evidence": [
                # DESIGN.md 3 shims: mandatory raw_ref provenance — the
                # source stream line the record was translated from
                {"kind": "vendor_event",
                 "locator": {"source": "actplane-events.log",
                             "line": lineno}},
            ],
        }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Translate ActPlane loader events (JSON-lines) into "
                    "decision-record/1 (streaming).")
    ap.add_argument("--stream-id", default="kernel-control")
    ap.add_argument("--run-id", default="unknown-run")
    ap.add_argument("--plugin", default="actplane")
    ap.add_argument("--plugin-version", default="0.1.8")
    args = ap.parse_args()
    for rec in iter_records(
            sys.stdin, stream_id=args.stream_id, run_id=args.run_id,
            plugin=args.plugin, plugin_version=args.plugin_version):
        print(json.dumps(rec))
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    sys.exit(main())
