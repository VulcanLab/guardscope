"""ActPlane shim tests (plugins/actplane/shim/translate.py).

The event samples are VERBATIM captures from the 2026-11-01 live T7
acceptance session (the loader's JSON event stream on the kernel-control
service): the kill sample is the first live kernel-level credential-read
denial through the fixture; the notify sample is the seeded shim's own
bookkeeping write (the documented infrastructure-noise skip).

Covers:
  - the JSON event grammar: TAINT_VIOLATION objects, banners ignored;
  - the class mapping (taint.h enum taint_op): 0 exec -> process_spawn,
    1 open -> credential_access under /run/secrets/** only (other opens
    skipped: no canonical class), 2 write -> file_write,
    3 connect -> direct_network;
  - the decision mapping: effect kill/killed -> deny, block/blocked ->
    deny, notify -> observe, decided-but-unlanded -> error;
  - the infrastructure-noise skip (containerd-shim, runc);
  - schema validity: every emitted record validates against
    decision-record/1 (ingested raw_ref evidence; kernel 'none' protocol);
  - streaming: records are yielded as event lines arrive (a generator —
    the supervisor pipes `tail -f` into it and stdin never EOFs mid-run);
  - the fixture policy and the manifest's kernel-interference declaration.

Run from the repo root:  python3 -m pytest tests/test_actplane_shim.py -v
"""

import importlib.util
import json
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    "actplane_shim", ROOT / "plugins" / "actplane" / "shim" / "translate.py")
shim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shim)

SCHEMA = json.loads((ROOT / "framework" / "schemas" / "decision-record"
                     / "1.schema.json").read_text())

# VERBATIM: the live credential-read kill through the T7 fixture
# (2026-11-01, t7-actplane acceptance host; the docker-exec'd `cat`
# reading /run/secrets/token is SIGKILLed by the kernel engine).
KILL_EVENT = (
    '{"timestamp":436729180567,"event":"TAINT_VIOLATION","effect":"kill",'
    '"blocked":false,"killed":true,"comm":"cat","pid":5234,"ppid":5228,'
    '"op":1,"domain_id":0,"session_root":1213,'
    '"target":"/run/secrets/token","rule_id":4,"taint_label":1,'
    '"matched_label":1,"matched_labels":1,'
    '"provenance":{"label":1,"timestamp_ns":436728691714,"pid":5234,'
    '"op":0,"ip":0,"target":"cat"}}')

# VERBATIM: the seeded shim's own bookkeeping write (infrastructure noise)
SHIM_WRITE_EVENT = (
    '{"timestamp":436729592475,"event":"TAINT_VIOLATION","effect":"notify",'
    '"blocked":false,"killed":false,"comm":"containerd-shim","pid":1213,'
    '"ppid":1,"op":2,"domain_id":0,"session_root":1213,'
    '"target":"/proc/self/fd/28","rule_id":1,"taint_label":1,'
    '"matched_label":1,"matched_labels":1,'
    '"provenance":{"label":1,"timestamp_ns":427999922851,"pid":5106,'
    '"op":0,"ip":0,"target":"runc"}}')

# same grammar, an agent file write (synthetic; grammar verified live)
WRITE_EVENT = (
    '{"timestamp":436730000000,"event":"TAINT_VIOLATION","effect":"notify",'
    '"blocked":false,"killed":false,"comm":"pi","pid":5300,"ppid":5299,'
    '"op":2,"domain_id":0,"session_root":1213,'
    '"target":"/workspace/out/b.txt","rule_id":2,"taint_label":1,'
    '"matched_label":1,"matched_labels":1,'
    '"provenance":{"label":1,"timestamp_ns":436729000000,"pid":5300,'
    '"op":0,"ip":0,"target":"pi"}}')

# same grammar, a direct network connect (synthetic; grammar verified live)
CONNECT_EVENT = (
    '{"timestamp":436731000000,"event":"TAINT_VIOLATION","effect":"notify",'
    '"blocked":false,"killed":false,"comm":"node","pid":5400,"ppid":5299,'
    '"op":3,"domain_id":0,"session_root":1213,'
    '"target":"10.0.2.11:9000","rule_id":3,"taint_label":1,'
    '"matched_label":1,"matched_labels":1,'
    '"provenance":{"label":1,"timestamp_ns":436730900000,"pid":5400,'
    '"op":0,"ip":0,"target":"node"}}')

# same grammar, a non-secret open (skipped: no canonical class)
PLAIN_OPEN_EVENT = (
    '{"timestamp":436732000000,"event":"TAINT_VIOLATION","effect":"notify",'
    '"blocked":false,"killed":false,"comm":"node","pid":5500,"ppid":5299,'
    '"op":1,"domain_id":0,"session_root":1213,'
    '"target":"/workspace/out/a.txt","rule_id":5,"taint_label":1,'
    '"matched_label":1,"matched_labels":1,'
    '"provenance":{"label":1,"timestamp_ns":436731900000,"pid":5500,'
    '"op":0,"ip":0,"target":"node"}}')

BANNER = "ActPlane: 1 updates, 5 rules"


def records(lines):
    return list(shim.iter_records(
        lines, stream_id="s", run_id="r",
        plugin="actplane", plugin_version="0.1.8"))


def test_kill_event_translates_to_credential_access_deny():
    recs = records([BANNER, KILL_EVENT])
    assert len(recs) == 1
    r = recs[0]
    assert r["action_class"] == "credential_access"
    assert r["decision"] == "deny"
    assert r["tool"] == "cat"
    assert r["target"]["value"] == "/run/secrets/token"
    assert r["evidence"][0]["locator"]["source"] == "actplane-events.log"
    assert r["evidence"][0]["locator"]["line"] == 2


def test_shim_bookkeeping_is_infrastructure_noise():
    assert records([SHIM_WRITE_EVENT]) == []


def test_write_connect_classify_and_observe():
    recs = records([WRITE_EVENT, CONNECT_EVENT])
    assert [r["action_class"] for r in recs] == ["file_write",
                                                 "direct_network"]
    assert all(r["decision"] == "observe" for r in recs)


def test_plain_open_skipped():
    assert records([PLAIN_OPEN_EVENT]) == []


def test_decided_but_unlanded_is_error_not_allow():
    ev = json.loads(KILL_EVENT)
    ev["killed"] = False          # decided kill, did not land
    recs = records([json.dumps(ev)])
    assert recs[0]["decision"] == "error"


def test_records_validate_against_decision_record_1():
    validator = jsonschema.Draft202012Validator(SCHEMA)
    recs = records([BANNER, KILL_EVENT, WRITE_EVENT, CONNECT_EVENT])
    assert len(recs) == 3
    for r in recs:
        errs = list(validator.iter_errors(r))
        assert errs == [], [e.message for e in errs]


def test_streaming_yield_per_event():
    """Records are yielded as event lines arrive: consuming the generator
    one next() at a time, the first record arrives exactly when its event
    line is consumed — before any later line (a `tail -f` pipe never
    EOFs mid-run)."""
    consumed = {"n": 0}

    def counting(lines):
        for line in lines:
            consumed["n"] += 1
            yield line

    source = counting([BANNER, KILL_EVENT, WRITE_EVENT])
    gen = shim.iter_records(source, stream_id="s", run_id="r",
                            plugin="actplane", plugin_version="0.1.8")
    first = next(gen)
    assert consumed["n"] == 2          # banner + the kill event line
    assert first["action_class"] == "credential_access"
    second = next(gen)
    assert consumed["n"] == 3
    assert second["action_class"] == "file_write"


def test_seq_monotonic_per_stream():
    recs = records([KILL_EVENT, WRITE_EVENT, CONNECT_EVENT])
    assert [r["seq"] for r in recs] == [1, 2, 3]


def test_fixture_policy_wellformed_with_expected_rules():
    """The t7 fixture policy (the design's enforcement_config): YAML
    well-formed, and the rule inventory matches the design comment (notify
    over the mediated classes + the kill rule on secret reads)."""
    doc = yaml.safe_load(
        (ROOT / "plugins" / "actplane" / "policy" / "t7.ap.yaml").read_text())
    assert doc["version"] == 1
    body = doc["policy"]
    assert "notify write file" in body
    assert "notify unlink file" in body
    assert "notify connect endpoint" in body
    assert "notify open file \"/run/secrets/**\"" in body
    assert "kill read file" not in body          # reads are notified (v2)
    # v4: the spawn class is the deny rule (both instances; the class-level
    # outcome model needs the whole class denied, like t2's egress)
    assert "notify exec" in body               # v5: a031's allowed twin
    assert 'kill exec "/bin/echo"' in body        # the instance deny rule
    assert 'kill exec "/bin/sh"' not in body      # harness plumbing


def test_manifest_declares_kernel_interference():
    m = json.loads((ROOT / "plugins" / "actplane" / "manifest.json").read_text())
    assert m["slot_kinds"] == ["kernel"]
    assert m["supported_designs"] == ["t7"]
    assert m["record_source"] == "ingested"
    assert m["kernel_interference"]["declared"] is True
    from framework.contracts import load_capabilities
    loaded = load_capabilities("actplane")
    assert loaded["kernel_interference"]["declared"] is True
