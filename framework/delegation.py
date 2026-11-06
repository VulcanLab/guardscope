"""Delegation records and tracing back (the delegation study's record
layer; delegation-record/1).

Three jobs, in plain words:

1. READ the records. The harness/fixture side writes one
   delegation-record/1 per hand-off (and one acceptance event per
   hand-off the receiver actually took). Loading validates against the
   schema and reports problems, never silently drops a line.

2. BUILD THE CHAIN. Every hand-off record carries a came-from pointer
   (parent_delegation_id) and the root of its chain
   (root_delegation_id). The chain table is the came-from map: roots,
   edges, hops, orphans (a parent pointer to a hand-off that never
   appeared), and acceptance pairing (a hand-off the receiver never
   accepted stays visible, not silently merged away).

3. TRACE BACK. Given effect records (kernel observations, decisions),
   answer the study's third question — can the effect be traced back to
   the original request, through which chain — under two strict rules:

   - EXACT ECHO FIRST: an effect record that carries a delegation_id
     traces to that hand-off's chain, full stop. No guessing.
   - NEVER GUESS BY TIME: without an echo, the only fallback is a
     labeled actor-and-window match with EXACTLY ONE live candidate —
     two or more candidates means AMBIGUOUS (the candidates are listed,
     the answer refused), zero means UNRESOLVED. The nearest-timestamp
     guess is forbidden by design: the two-workers fixture exists to
     catch exactly that mistake.

   And the depth-decay analysis: first_break_hop reports, per chain,
   the first hop where the trace died (the first hand-off after which
   no effect echoes the chain) — the study's tracing-back-decay
   measurement, computed over measured records rather than assumed.

The traveling record (the study's block-4 comparison) is a POLICY on
this record layer, not new machinery: the same fixtures run with
carrier: none (the control condition) or carrier: mcp_meta | http_header
| queue_payload (the traveling record present). The trace-back rules
above are identical either way; the echo simply exists or does not.

Records are claims like every other record: the reconciler's kernel
evidence (DESIGN.md 9) remains the only fact about effects. This module
attributes records to chains; it never decides outcomes.

Run from the repo root:  python3 -m pytest tests/test_delegation.py -v
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from framework.schemas import load_schema

SCHEMA_NAME = "delegation-record/1"
_VALIDATOR = jsonschema.Draft202012Validator(
    load_schema("delegation-record"))


class DelegationError(ValueError):
    """The delegation records are malformed (their own schema or their
    internal consistency: cycles, wrong hop counts)."""


# --- 1. read ---------------------------------------------------------------------

def load_delegation_records(path) -> tuple[list[dict], list[str]]:
    """Parse delegation-records.jsonl; returns (records, problems).

    A line that fails the schema is a PROBLEM, not a silent drop: the
    study's numbers must be able to say "N records were unusable"."""
    records: list[dict] = []
    problems: list[str] = []
    for i, raw in enumerate(Path(path).read_text(
            encoding="utf-8").splitlines(), start=1):
        line = raw.strip()
        if not line:
            continue
        try:
            doc = json.loads(line)
        except json.JSONDecodeError as exc:
            problems.append(f"line {i}: not JSON ({exc})")
            continue
        error = _VALIDATOR.iter_errors(doc)
        first = next(iter(error), None)
        if first is not None:
            problems.append(f"line {i}: {first.message}")
            continue
        records.append(doc)
    return records, problems


# --- 2. the chain ----------------------------------------------------------------

@dataclass
class ChainTable:
    """The came-from map over one run's hand-off records."""
    by_id: dict[str, dict] = field(default_factory=dict)
    roots: dict[str, dict] = field(default_factory=dict)   # root id -> root
    children: dict[str, list[str]] = field(default_factory=dict)
    orphans: list[str] = field(default_factory=list)       # parent ids that
    # never appeared as hand-offs
    unaccepted: list[str] = field(default_factory=list)   # sent, never
    # accepted
    accepted: dict[str, str] = field(default_factory=dict)  # hand-off ->
    # accepting actor
    problems: list[str] = field(default_factory=list)

    def ancestry(self, delegation_id: str) -> list[str]:
        """The chain from the root down to this hand-off, oldest first.
        Uses the came-from pointers; the root id is checked against the
        walked root (a mismatch is an inconsistency, reported once at
        build time, not silently corrected)."""
        chain: list[str] = []
        seen: set[str] = set()
        cur = self.by_id.get(delegation_id)
        while cur is not None:
            if cur["delegation_id"] in seen:
                raise DelegationError(
                    f"cycle at {cur['delegation_id']} in the came-from "
                    f"chain")
            seen.add(cur["delegation_id"])
            chain.append(cur["delegation_id"])
            parent = cur.get("parent_delegation_id")
            cur = self.by_id.get(parent) if parent else None
        chain.reverse()
        return chain

    def hop_of(self, delegation_id: str) -> int:
        return self.by_id[delegation_id]["hop"]


def build_chains(records: list[dict]) -> ChainTable:
    """Build the came-from map + acceptance pairing over the records.

    Internal consistency checks (each is a problem, never a crash):
      - a hand-off whose parent never appeared (an orphan);
      - a hop count that disagrees with the walked chain length;
      - a root id that disagrees with the walked root;
      - a cycle in the came-from chain;
      - a sent record whose acceptance never arrived (unaccepted — the
        edge-vs-effect questions need sent-vs-accepted visible)."""
    t = ChainTable()
    for r in records:
        if r["event"] == "sent":
            t.by_id[r["delegation_id"]] = r
            parent = r.get("parent_delegation_id")
            if parent:
                t.children.setdefault(parent, []).append(r["delegation_id"])
    for r in records:
        if r["event"] == "accepted":
            d = r["delegation_id"]
            if d in t.by_id:
                t.accepted[d] = r.get("to_actor") or "unknown"
            else:
                t.problems.append(
                    f"accepted hand-off {d} was never sent")
    for did, r in t.by_id.items():
        if did not in t.accepted:
            t.unaccepted.append(did)
        parent = r.get("parent_delegation_id")
        if parent and parent not in t.by_id:
            t.orphans.append(did)
            continue
        try:
            chain = t.ancestry(did)
        except DelegationError as exc:
            t.problems.append(str(exc))
            continue
        if chain[0] != r["root_delegation_id"]:
            t.problems.append(
                f"{did}: root_delegation_id {r['root_delegation_id']!r} "
                f"but the came-from chain starts at {chain[0]!r}")
        if r["hop"] != len(chain):
            t.problems.append(
                f"{did}: hop {r['hop']} but the chain has "
                f"{len(chain)} hand-off(s)")
        if not r.get("parent_delegation_id"):
            t.roots[chain[0]] = t.by_id[chain[0]]
    for did in t.orphans:
        t.problems.append(
            f"{did}: came from {t.by_id[did].get('parent_delegation_id')!r},"
            f" which never appeared as a hand-off")
    for did in t.unaccepted:
        t.problems.append(
            f"{did}: sent but never accepted")
    return t


# --- 3. trace back ---------------------------------------------------------------

ATTRIBUTED = "attributed"
AMBIGUOUS = "ambiguous"
UNRESOLVED = "unresolved"


def _ts_to_epoch_ns(value) -> int | None:
    """A delegation timestamp -> epoch ns, or None when unusable.

    delegation-record/1 carries RFC3339 ms in `ts` (the schema forbids
    `ts_epoch_ns`: additionalProperties false), so the record side is
    always the string; an effect record may carry either the RFC3339
    string or a raw epoch-ns integer (the replay rows' ts_epoch_ns).
    Never a nearest-timestamp guess on an unparseable value: None means
    the time-window join cannot run."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return int(value)          # epoch ns (ts_epoch_ns)
    if isinstance(value, str):
        try:
            dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return int(dt.timestamp() * 1e9)
    return None


def trace_back(effects: list[dict], table: ChainTable,
               window_ns: int = 1_000_000_000) -> list[dict]:
    """For every effect record, where it traces back to.

    An effect record (the reconciler's kernel observations or a
    decision record) may carry a `delegation_id` echo. Rules, in order:

      1. an echo that names a known hand-off -> ATTRIBUTED, method
         'id-echo', chain = that hand-off's ancestry. No guessing.
      2. no echo (or carrier: none — the study's control condition):
         live candidates = hand-offs of the same actor (`from_actor` or
         the accepting actor) whose send-to-effect distance is inside
         the window AND that are ancestors-or-equal of nothing that
         already explains a closer effect (candidates are only ever
         all-or-nothing):
           exactly one -> ATTRIBUTED, method 'actor-window' (labeled:
           this is a fallback, never the primary evidence)
           more than one -> AMBIGUOUS, candidates listed, answer
           REFUSED (never the nearest timestamp)
           zero -> UNRESOLVED
      3. an echo naming an unknown hand-off -> UNRESOLVED with the
         echoed id kept (a record the chain table cannot account for is
         a finding, not a dropped line).

    Returns one result per effect: {effect, status, chain, method,
    candidates}. The study's four-metric table reads: attributed =
    ATTRIBUTED; everything else is reported by its status."""
    results = []
    for e in effects:
        ts = _ts_to_epoch_ns(e.get("ts_epoch_ns"))
        if ts is None:
            ts = _ts_to_epoch_ns(e.get("ts"))
        echo = e.get("delegation_id")
        if echo is not None:
            if echo in table.by_id:
                chain = table.ancestry(echo)
                results.append({
                    "effect": e, "status": ATTRIBUTED,
                    "method": "id-echo", "chain": chain,
                    "candidates": []})
            else:
                results.append({
                    "effect": e, "status": UNRESOLVED,
                    "method": "id-echo-unknown", "chain": [],
                    "candidates": []})
            continue
        actor = e.get("actor")
        cands: list[str] = []
        if actor and ts is not None:
            for did, r in table.by_id.items():
                # the sent record's RFC3339 ts (the schema-forbidden
                # ts_epoch_ns read zero for every real record before this)
                send_ns = _ts_to_epoch_ns(r.get("ts"))
                if send_ns is None:
                    continue
                # causal direction: an effect BEFORE the hand-off was sent
                # can never be that hand-off's effect; the window bounds
                # only the send-to-effect distance
                if (r.get("from_actor") == actor
                        or table.accepted.get(did) == actor):
                    if send_ns < ts <= send_ns + window_ns:
                        cands.append(did)
        if len(cands) == 1:
            results.append({
                "effect": e, "status": ATTRIBUTED,
                "method": "actor-window", "chain": table.ancestry(cands[0]),
                "candidates": cands})
        elif len(cands) > 1:
            results.append({
                "effect": e, "status": AMBIGUOUS,
                "method": "actor-window", "chain": [],
                "candidates": sorted(cands)})
        else:
            results.append({
                "effect": e, "status": UNRESOLVED,
                "method": "actor-window", "chain": [],
                "candidates": []})
    return results


# --- the depth-decay analysis ----------------------------------------------------

def first_break_hop(results: list[dict], table: ChainTable) -> dict:
    """Per root chain, the first hop where the trace died: the largest
    hop whose hand-off still has an ATTRIBUTED effect on its chain,
    reported against the chain's deepest hand-off. A chain fully traced
    to its deepest hand-off has no break (reported as None); a chain
    with no attributed effect at all broke at hop 1 (the study's
    first-break measurement — computed, never assumed)."""
    deepest_attributed: dict[str, int] = {}
    deepest_sent: dict[str, int] = {}
    for res in results:
        if res["status"] != ATTRIBUTED or not res["chain"]:
            continue
        root = res["chain"][0]
        hop = len(res["chain"])
        deepest_attributed[root] = max(deepest_attributed.get(root, 0), hop)
    for r in table.by_id.values():
        root = r["root_delegation_id"]
        deepest_sent[root] = max(deepest_sent.get(root, 0), r["hop"])
    out: dict[str, dict] = {}
    for root, sent in deepest_sent.items():
        traced = deepest_attributed.get(root, 0)
        out[root] = {
            "deepest_hand_off": sent,
            "deepest_traced": traced,
            "first_break_hop": (traced + 1) if traced < sent else None,
        }
    return out
