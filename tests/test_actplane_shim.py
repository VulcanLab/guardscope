"""ActPlane shim tests (plugins/actplane/shim/translate.py).

The event samples are the 2026-10-31 probe's LIVE capture (KILLED and
BLOCKED verbatim from results/actplane-probe-20261031/ in the wider-control
project — the first live T7-class enforcement ever observed in this
research line); the notify/write/connect samples follow the same grammar
and are re-verified at the live acceptance run.

Covers:
  - the event grammar: header/effect/reason/provenance blocks, one record
    per completed block, banner lines ignored;
  - the class mapping: exec -> process_spawn, write/unlink/rename ->
    file_write, connect -> direct_network, secret reads ->
    credential_access; non-secret reads SKIPPED (no canonical class);
  - the decision mapping: kill/block -> deny, notify -> observe;
  - schema validity: every emitted record validates against
    decision-record/1 (including the ingested raw_ref evidence and the
    kernel 'none' protocol);
  - streaming: records are yielded as blocks complete (a generator, not
    a batch — the supervisor pipes `tail -f` into it);
  - the fixture policy's compile story: the DSL the t7 fixture deploys
    parses under the pinned ActPlane CLI is a LIVE check (no binary on
    this host); the offline check is the policy file's YAML well-formedness
    and the expected rule inventory.

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
SPEC = importlib.util.spec_from_file_location(
    "actplane_shim", ROOT / "plugins" / "actplane" / "shim" / "translate.py")
shim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shim)

SCHEMA = json.loads((ROOT / "framework" / "schemas" / "decision-record"
        / "1.schema.json").read_text())

# The probe's verbatim kill sample (kill-prebuilt.log, 2026-10-31):
KILL_BLOCK = [
    "ActPlane: running pid 8410 under COMMAND label 0x1; feedback /run/f.txt",
    "🚫 KILLED: process 'touch' (pid 8412, ppid 8410) — /usr/bin/touch",
    "   effect: kill",
    "   reason: T7 prevention arm: credential reads are denied at the kernel",
    "   provenance: pid 8412 read file /run/secrets/token -> label AGENT",
]
# The probe's verbatim block sample (block.log, 2026-10-31):
BLOCK_BLOCK = [
    "🚫 BLOCKED: process 'bash' (pid 8403, ppid 8401) — /usr/bin/touch",
    "   effect: block",
    "   reason: probe: BPF-LSM pre-commit block test",
    "   provenance: pid 8401 exec bash -> label COMMAND",
]
NOTIFY_WRITE = [
    "⚠ NOTIFY: process 'tee' (pid 7001, ppid 7000) — /workspace/out/b.txt",
    "   effect: notify",
    "   reason: T7 coverage: one record per mediated write (file_write)",
    "   provenance: pid 7001 write file /workspace/out/b.txt -> label AGENT",
]
NOTIFY_CONNECT = [
    "⚠ NOTIFY: process 'curl' (pid 6001, ppid 6000) — 10.0.2.11:9000",
    "   effect: notify",
    "   reason: T7 coverage: one record per mediated connect",
    "   provenance: pid 6001 connect 10.0.2.11:9000 -> label AGENT",
]
NONSECRET_READ = [
    "⚠ NOTIFY: process 'cat' (pid 8001, ppid 8000) — /workspace/out/a.txt",
    "   effect: notify",
    "   reason: tool-caused read",
    "   provenance: pid 8001 read file /workspace/out/a.txt -> label AGENT",
]


def records(lines):
    return list(shim.iter_records(
        lines, stream_id="s", run_id="r",
        plugin="actplane", plugin_version="0.1.8"))


def test_kill_block_translates_to_credential_access_deny():
    recs = records(KILL_BLOCK)
    assert len(recs) == 1
    r = recs[0]
    assert r["action_class"] == "credential_access"
    assert r["decision"] == "deny"
    assert r["tool"] == "touch"
    assert r["target"]["value"] == "/usr/bin/touch"
    assert r["evidence"][0]["locator"]["source"] == "actplane-events.log"
    assert r["evidence"][0]["locator"]["line"] == 2


def test_block_translates_to_process_spawn_deny():
    recs = records(BLOCK_BLOCK)
    assert len(recs) == 1
    assert recs[0]["action_class"] == "process_spawn"
    assert recs[0]["decision"] == "deny"


def test_notify_write_and_connect_observe():
    recs = records(NOTIFY_WRITE + NOTIFY_CONNECT)
    assert [r["action_class"] for r in recs] == ["file_write", "direct_network"]
    assert all(r["decision"] == "observe" for r in recs)


def test_nonsecret_reads_skipped():
    recs = records(NONSECRET_READ)
    assert recs == []


def test_records_validate_against_decision_record_1():
    validator = jsonschema.Draft202012Validator(SCHEMA)
    recs = records(KILL_BLOCK + BLOCK_BLOCK + NOTIFY_WRITE + NOTIFY_CONNECT)
    assert len(recs) == 4
    for r in recs:
        errs = list(validator.iter_errors(r))
        assert errs == [], [e.message for e in errs]


def test_streaming_yield_per_block():
    """Records are yielded as blocks complete: feeding the generator
    line-by-line, the first record arrives exactly when its block's
    provenance line is consumed — BEFORE any later block — so a `tail -f`
    pipe emits incrementally (stdin never EOFs during a run)."""
    consumed = {"n": 0}

    def counting(lines):
        for line in lines:
            consumed["n"] += 1
            yield line

    source = counting(KILL_BLOCK + BLOCK_BLOCK)
    gen = shim.iter_records(source, stream_id="s", run_id="r",
                            plugin="actplane", plugin_version="0.1.8")
    first = next(gen)
    # the record arrived with the KILL block's provenance line consumed
    # and nothing after it (BLOCK_BLOCK untouched)
    assert consumed["n"] == len(KILL_BLOCK)
    assert first["action_class"] == "credential_access"
    second = next(gen)
    assert consumed["n"] == len(KILL_BLOCK) + len(BLOCK_BLOCK)
    assert second["action_class"] == "process_spawn"


def test_seq_monotonic_per_stream():
    recs = records(KILL_BLOCK + BLOCK_BLOCK + NOTIFY_WRITE)
    assert [r["seq"] for r in recs] == [1, 2, 3]


def test_fixture_policy_wellformed_with_expected_rules():
    """The t7 fixture policy (the design's enforcement_config): YAML
    well-formed, and the rule inventory matches the design comment (notify
    over the mediated classes + the kill arm on secret reads)."""
    doc = yaml.safe_load(
        (ROOT / "plugins" / "actplane" / "policy" / "t7.ap.yaml").read_text())
    assert doc["version"] == 1
    body = doc["policy"]
    assert "notify exec" in body
    assert "notify write file" in body
    assert "notify unlink file" in body
    assert "notify connect endpoint" in body
    assert "kill read file \"/run/secrets/**\"" in body


def test_manifest_declares_kernel_interference():
    m = json.loads((ROOT / "plugins" / "actplane" / "manifest.json").read_text())
    assert m["slot_kinds"] == ["kernel"]
    assert m["supported_designs"] == ["t7"]
    assert m["record_source"] == "ingested"
    assert m["kernel_interference"]["declared"] is True
    # the contract loader enforces the declaration (framework/contracts)
    sys.path.insert(0, str(ROOT))
    from framework.contracts import load_capabilities
    loaded = load_capabilities("actplane")
    assert loaded["kernel_interference"]["declared"] is True
