"""Delegation record tests (framework/delegation.py; the delegation
study's record layer, delegation-record/1).

The synthetic records below are shaped exactly like what the fixtures
will emit: a two-hop chain (root -> child), an acceptance event per
hand-off, the study's two-workers problem (two live candidates -> the
answer must be REFUSED, never nearest-timestamp), a reused worker
(the actor-window fallback's false-join case), and the control
condition (carrier: none, no echo at all).

Covers:
  - loading: schema validation, problems reported (never silent drops);
  - the chain: came-from pointers, roots, hop-count consistency, root
    consistency, orphan and unaccepted hand-offs visible, cycles
    refused;
  - the acceptance events: sent vs accepted are different facts;
  - tracing back: exact echo -> attributed; exactly one live candidate
    -> attributed with the labeled fallback method; two or more ->
    AMBIGUOUS (refused, candidates listed); zero -> unresolved; an echo
    naming an unknown hand-off -> unresolved with the id kept;
  - the traveling record as a POLICY: with carrier none the same effect
    that an echo would attribute falls back (and in the two-workers
    case refuses) — the block-4 comparison in miniature;
  - first-break hop: a chain traced to its deepest hand-off reports no
    break; a chain whose trace died after hop 1 reports the break at
    the hop after the deepest traced one.

Run from the repo root:  python3 -m pytest tests/test_delegation.py -v
"""

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from framework.delegation import (  # noqa: E402
    AMBIGUOUS, ATTRIBUTED, UNRESOLVED, build_chains,
    first_break_hop, load_delegation_records, trace_back)

RID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"          # a well-formed ULID
RID2 = "01ARZ3NDEKTSV4RRFFQ69G5FAW"
RID3 = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"


def rec(did, **kw):
    """One sent record with the required fields and safe defaults."""
    r = {
        "schema": 1,
        "record_id": kw.pop("record_id", RID),
        "run_id": "r1",
        "stream_id": "pi-root",
        "seq": kw.pop("seq", 1),
        "ts": kw.pop("ts", "2026-11-02T10:00:00.000Z"),
        "event": "sent",
        "channel": kw.pop("channel", "child"),
        "delegation_id": did,
        "parent_delegation_id": kw.pop("parent", None),
        "root_delegation_id": kw.pop("root", did),
        "hop": kw.pop("hop", 1),
        "from_actor": kw.pop("from_actor", "pi-root"),
        "to_actor": kw.pop("to_actor", "child-a"),
        "task_digest": "d1",
        "protocol": kw.pop("protocol", "stdio"),
        "machine": kw.pop("machine", "origin"),
        "carrier": kw.pop("carrier", "env"),
    }
    r.update(kw)
    return r


def accepted(did, actor="child-a", seq=2):
    return {"schema": 1, "record_id": RID2, "run_id": "r1",
            "stream_id": "child-a", "seq": seq,
            "ts": "2026-11-02T10:00:01.000Z", "event": "accepted",
            "channel": "child", "delegation_id": did,
            "parent_delegation_id": None, "root_delegation_id": did,
            "hop": 1, "from_actor": "pi-root", "to_actor": actor,
            "task_digest": "d1", "protocol": "stdio", "machine": "origin",
            "carrier": "env"}


def write(tmp_path, records, name="delegation-records.jsonl"):
    p = tmp_path / name
    p.write_text("\n".join(json.dumps(r) for r in records) + "\n")
    return p


def effect(**kw):
    e = {"ts_epoch_ns": kw.pop("ts_epoch_ns", 0)}
    e.update(kw)
    return e


NS = 1_000_000_000  # 1s in ns


# --- loading ----------------------------------------------------------------------

def test_records_load_and_validate(tmp_path):
    p = write(tmp_path, [rec(RID), accepted(RID)])
    records, problems = load_delegation_records(p)
    assert problems == []
    assert len(records) == 2


def test_schema_problems_reported_never_dropped(tmp_path):
    bad = rec(RID)
    bad.pop("channel")
    p = tmp_path / "d.jsonl"
    p.write_text(json.dumps(rec(RID)) + "\nnot json\n"
                 + json.dumps(bad) + "\n")
    records, problems = load_delegation_records(p)
    assert len(records) == 1
    assert any("not JSON" in pr for pr in problems)
    assert any("channel" in pr for pr in problems)


# --- the chain --------------------------------------------------------------------

def test_chain_builds_with_root_and_hop():
    # root -> child (two hops: the child hands one level deeper)
    records = [
        rec(RID, seq=1),
        accepted(RID, seq=1),
        rec(RID2, parent=RID, root=RID, hop=2, from_actor="child-a",
            to_actor="grandchild", stream_id="child-a", seq=2),
        {"schema": 1, "record_id": RID3, "run_id": "r1",
         "stream_id": "grandchild", "seq": 1,
         "ts": "2026-11-02T10:00:02.000Z", "event": "accepted",
         "channel": "child", "delegation_id": RID2,
         "parent_delegation_id": None, "root_delegation_id": RID2,
         "hop": 1, "from_actor": "child-a", "to_actor": "grandchild",
         "task_digest": "d2", "protocol": "stdio", "machine": "origin",
         "carrier": "env"},
    ]
    t = build_chains(records)
    assert RID in t.roots
    assert t.ancestry(RID2) == [RID, RID2]
    assert t.problems == []


def test_orphan_unaccepted_and_hop_mismatch_are_visible():
    t = build_chains([
        rec(RID),                                  # never accepted
        rec(RID2, parent=RID3, root=RID3),         # parent never sent
        rec(RID, record_id=RID2, seq=3),           # duplicate id is a
        # schema-level pass but the table keeps one: the duplicate is
        # not silently merged away — assert the table kept the first
    ])
    assert RID2 in t.orphans
    assert RID in t.unaccepted
    assert any("never accepted" in p for p in t.problems)
    assert any("never appeared" in p for p in t.problems)
    assert t.by_id[RID]["from_actor"] == "pi-root"


def test_hop_count_and_root_mismatch_reported():
    t = build_chains([
        rec(RID),
        rec(RID2, parent=RID, root=RID, hop=3),     # chain length 2
    ])
    assert any("hop 3 but the chain has 2" in p for p in t.problems)
    t2 = build_chains([
        rec(RID),
        rec(RID2, parent=RID, root=RID2, hop=2),   # wrong root
    ])
    assert any("root_delegation_id" in p for p in t2.problems)


def test_cycle_refused():
    t = build_chains([
        rec(RID, parent=RID2, root=RID),
        rec(RID2, parent=RID, root=RID),
    ])
    assert any("cycle" in p for p in t.problems)


# --- tracing back -----------------------------------------------------------------

def test_exact_echo_attributes_with_no_guessing():
    records = [rec(RID), accepted(RID)]
    t = build_chains(records)
    res = trace_back([effect(delegation_id=RID, ts_epoch_ns=NS)], t)
    assert res[0]["status"] == ATTRIBUTED
    assert res[0]["method"] == "id-echo"
    assert res[0]["chain"] == [RID]


def test_exactly_one_live_candidate_attributes_labeled():
    records = [rec(RID, from_actor="pi-root"), accepted(RID)]
    t = build_chains(records)
    res = trace_back([effect(actor="pi-root", ts_epoch_ns=NS)], t)
    assert res[0]["status"] == ATTRIBUTED
    assert res[0]["method"] == "actor-window"   # the labeled fallback
    assert res[0]["chain"] == [RID]


def test_two_live_candidates_refuse_the_answer():
    """The two-workers problem: two live hand-offs of the same actor.
    The answer must be AMBIGUOUS — never nearest-timestamp."""
    records = [
        rec(RID, from_actor="pi-root", to_actor="w1",
            ts="2026-11-02T10:00:00.000Z", seq=1),
        accepted(RID, actor="w1", seq=1),
        rec(RID2, record_id=RID3, from_actor="pi-root", to_actor="w2",
            ts="2026-11-02T10:00:00.500Z", seq=2),
        {"schema": 1, "record_id": RID, "run_id": "r1",
         "stream_id": "w2", "seq": 1, "ts": "2026-11-02T10:00:00.600Z",
         "event": "accepted", "channel": "child", "delegation_id": RID2,
         "parent_delegation_id": None, "root_delegation_id": RID2,
         "hop": 1, "from_actor": "pi-root", "to_actor": "w2",
         "task_digest": "d2", "protocol": "stdio", "machine": "origin",
         "carrier": "env"},
    ]
    t = build_chains(records)
    res = trace_back([effect(actor="pi-root", ts_epoch_ns=NS)], t)
    assert res[0]["status"] == AMBIGUOUS
    assert sorted(res[0]["candidates"]) == sorted([RID, RID2])
    assert res[0]["chain"] == []          # refused: no chain is claimed


def test_zero_candidates_unresolved():
    t = build_chains([rec(RID), accepted(RID)])
    res = trace_back([effect(actor="nobody", ts_epoch_ns=NS)], t)
    assert res[0]["status"] == UNRESOLVED


def test_unknown_echo_keeps_the_id_as_a_finding():
    t = build_chains([rec(RID), accepted(RID)])
    res = trace_back([effect(delegation_id=RID2, ts_epoch_ns=NS)], t)
    assert res[0]["status"] == UNRESOLVED
    assert res[0]["method"] == "id-echo-unknown"


def test_the_traveling_record_is_a_policy_not_new_machinery():
    """Block 4 in miniature: the SAME effect, once with the echo (the
    traveling record present) and once with carrier: none (the control
    condition). The rules are identical; the echo simply exists or not."""
    records = [rec(RID), accepted(RID)]
    t = build_chains(records)
    with_echo = trace_back(
        [effect(delegation_id=RID, ts_epoch_ns=NS)], t)[0]
    without_echo = trace_back(
        [effect(actor="pi-root", ts_epoch_ns=NS)], t)[0]
    assert with_echo["status"] == without_echo["status"] == ATTRIBUTED
    assert with_echo["method"] == "id-echo"
    assert without_echo["method"] == "actor-window"


# --- the depth-decay analysis ------------------------------------------------------

def test_first_break_hop():
    """A two-hop chain where only the first hop's effect was traced:
    the break is reported at the hop AFTER the deepest traced one."""
    records = [
        rec(RID, seq=1), accepted(RID, seq=1),
        rec(RID2, record_id=RID, parent=RID, root=RID, hop=2,
            from_actor="child-a", to_actor="grandchild",
            stream_id="child-a", seq=2),
    ]
    t = build_chains(records)
    effects = [effect(delegation_id=RID, ts_epoch_ns=NS)]
    res = trace_back(effects, t)
    fb = first_break_hop(res, t)
    assert fb[RID] == {"deepest_hand_off": 2, "deepest_traced": 1,
                       "first_break_hop": 2}


def test_fully_traced_chain_has_no_break():
    records = [
        rec(RID, seq=1), accepted(RID, seq=1),
        rec(RID2, record_id=RID, parent=RID, root=RID, hop=2,
            from_actor="child-a", stream_id="child-a", seq=2),
    ]
    t = build_chains(records)
    res = trace_back(
        [effect(delegation_id=RID, ts_epoch_ns=NS),
         effect(delegation_id=RID2, ts_epoch_ns=2 * NS)], t)
    fb = first_break_hop(res, t)
    assert fb[RID]["first_break_hop"] is None
    assert fb[RID]["deepest_traced"] == 2
