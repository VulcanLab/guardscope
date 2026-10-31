#!/usr/bin/env python3
"""ActPlane match-event shim (plugins/actplane/shim/translate.py).

Translates the pinned ActPlane engine's match-event stream (the config-at-
load loader's stdout on the T7 control service) into decision-record/1
(DESIGN.md 3 "Shims are not a separate tier": record_source ingested,
mandatory raw_ref provenance per record).

Event grammar (the 2026-10-31 probe's live capture — KILLED and BLOCKED
are verbatim samples from results/actplane-probe-20261031/ in the
wider-control project; the notify header spelling follows the engine's
event writer and is re-verified at the live acceptance run):

    <flag> KILLED: process 'touch' (pid 1089, ppid 1086) — /usr/bin/touch
       effect: kill
       reason: probe: kernel-level kill test
       provenance: pid 1089 exec touch -> label COMMAND
    <flag> BLOCKED: process 'bash' (pid 8403, ppid 8401) — /usr/bin/touch
       effect: block
       ...
    <flag> NOTIFY: process 'X' (pid N, ppid M) — <path-or-endpoint>
       effect: notify
       ...

The `effect:` line is the authoritative decision; the `provenance:` line
(`pid N <op> <rest>`) completes the block and selects the action class:

    exec                     -> process_spawn
    write | unlink | rename  -> file_write
    read of /run/secrets/**  -> credential_access
    connect (numeric IPv4)    -> direct_network

`tool` carries the acting process name (the kernel position has no tool
identity; DESIGN.md 1: the least-semantic position identifies actors, not
tools). Events mapping to no six-class class (non-secret reads, plain
opens) are SKIPPED with a stderr note: the taxonomy has no class for them
(they are expected-extras at reconcile time) and a record without an
action class cannot be accounted (C3). Their mediation still happens at
the kernel by construction.

Streaming: records are emitted as blocks complete (the control supervisor
pipes `tail -f` into this process; stdin never EOFs during a run).

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

# --- the event grammar --------------------------------------------------------

_HEADER = re.compile(
    r"(?:.*?)(?:KILLED|BLOCKED|NOTIFY)\s*:\s*process\s*'(?P<proc>[^']*)'"
    r"\s*\(pid\s*(?P<pid>\d+),\s*ppid\s*(?P<ppid>\d+)\)\s*[—-]\s*(?P<target>.+)$")
_EFFECT = re.compile(
    r"^\s*effect:\s*(?P<effect>kill|block|notify|allow|error)\s*$")
_REASON = re.compile(r"^\s*reason:\s*(?P<reason>.+)$")
_PROVENANCE = re.compile(
    r"^\s*provenance:\s*pid\s*(?P<pid>\d+)\s+"
    r"(?P<op>exec|read|write|open|unlink|rename|connect|recv)"
    r"(?:\s+(?P<rest>[^->]*?))?\s*(?:->\s*(?P<label>.+))?$")

EFFECT_TO_DECISION = {
    "kill": "deny",
    "block": "deny",
    "notify": "observe",
    "allow": "allow",
    "error": "error",
}

SECRET_PREFIX = "/run/secrets/"

# ActPlane's provenance line carries the vendor's op keyword for file
# ops ("read file /path", "write file /path") and bare argv/endpoint
# otherwise ("exec touch", "connect 10.0.2.11:9000"): normalize before
# classification.
_FILE_KEYWORD = re.compile(r"^file\s+")


def _normalize_rest(op: str, rest: str) -> str:
    return _FILE_KEYWORD.sub("", rest).strip()

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid() -> str:
    """A ULID: 48-bit timestamp + 80-bit randomness, Crockford base32."""
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


def _classify(op: str, rest: str) -> str | None:
    if op == "exec":
        return "process_spawn"
    if op in ("write", "unlink", "rename"):
        return "file_write"
    if op == "connect":
        return "direct_network"
    if op in ("read", "open"):
        if (rest or "").startswith(SECRET_PREFIX):
            return "credential_access"
        return None
    return None


def iter_records(lines, *, stream_id: str, run_id: str, plugin: str,
                 plugin_version: str):
    """Yield one decision record per parsed match event (streaming:
    yields as each provenance line completes a block)."""
    seq = 0
    header = effect = reason = None
    block_start = 0
    for lineno, raw in enumerate(lines, start=1):
        line = raw.rstrip("\n")
        m = _HEADER.match(line)
        if m:
            header, effect, reason = m, None, None
            block_start = lineno
            continue
        m = _EFFECT.match(line)
        if m:
            effect = m.group("effect")
            continue
        m = _REASON.match(line)
        if m:
            reason = m.group("reason").strip()
            continue
        m = _PROVENANCE.match(line)
        if m and header is not None:
            prov, hdr = m, header
            eff, rsn = effect, reason
            header = effect = reason = None
            op = prov.group("op")
            rest = _normalize_rest(op, (prov.group("rest") or "").strip())
            action_class = _classify(op, rest)
            if action_class is None:
                print(f"translate: line {lineno}: skipped event "
                      f"(op={op!r} has no canonical action class; "
                      f"expected-extra at reconcile)", file=sys.stderr)
                continue
            if eff is None:
                print(f"translate: line {lineno}: skipped event "
                      f"(block without an effect line)", file=sys.stderr)
                continue
            seq += 1
            target_value = hdr.group("target").strip()
            digest = hashlib.sha256(
                f"{hdr.group('pid')}|{op}|{rest}|{target_value}"
                .encode()).hexdigest()[:16]
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
                "tool": hdr.group("proc"),
                "target": {
                    "kind": "kernel_path_or_endpoint",
                    "value": target_value,
                    "note": f"kernel op={op}",
                },
                "parameters_digest": digest,
                "action_id": None,
                "attempt": 0,
                "correlation_transport": "none",
                "decision": EFFECT_TO_DECISION.get(eff, "error"),
                "policy": {
                    "policy_id": "t7-fixture",
                    "policy_version": "1",
                    # the deployed policy artifact's hash; the runner
                    # overwrites this with the manifest hash of the
                    # enforcement_config it captured for the run
                    "policy_hash": "t7.ap.yaml#runner-hashed",
                    "rule_id": rsn,
                },
                "evidence": [
                    # DESIGN.md 3 shims: mandatory raw_ref provenance —
                    # the source stream line the record was translated from
                    {"kind": "vendor_event",
                     "locator": {"source": "actplane-events.log",
                                 "line": block_start}},
                ],
            }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Translate ActPlane match events into "
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
