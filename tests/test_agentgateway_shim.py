"""agentgateway shim tests (plugins/agentgateway/shim/translate.py).

The vendor-row fixtures carry VERBATIM field values from the live v1.5.0
capture of 2026-10-08 (retained read-only by the pre-guardscope probe at
realtime-control-coverage/code/tests/fixtures/agentgateway-t1/native.jsonl):
requestId 4 is the allowed a011 post_hook tools/call, requestId 7 the
denied a014 policy-deny probe (the live 403 in that capture's
requestFinished is the enforcement half this binding's can_enforce claim
rests on). The rows are rebuilt as Python dicts from the captured values
and serialized with json.dumps (the capture's own JSON encoding detail is
immaterial to the shim: it parses rows). The _meta-carrying row is the
same capture's ingress body with the guardscope correlation carriers
added (synthesized: the old probe's client predates them; the manifest's
echoes_meta claim stays false until the live fidelity check).

Covers:
  - the vendor row grammar (collector JSONL, dtrace Message shapes);
  - the grouping rule: one record per requestId, tools/call only
    (initialize/discovery produce no record), exactly one allow/deny
    authorizationResult (ambiguous/missing authorization is a PROBLEM,
    never a guess or a silent drop);
  - the ingress-body selection (requestState over final-request
    bodySnapshot; response bodies never used) and body agreement;
  - the field mapping: http_tool_call class, bare tool name, HTTP route
    fields from the routing table, capture-clock ts, allow/deny decision,
    unmapped policy without a descriptor, raw_ref evidence line numbers;
  - the correlation carrier echo (io.inspection/action_id + attempt ->
    mcp_meta; absent -> null + none; the JSON-RPC id is never the
    action_id);
  - the digest parity with framework/records.py parameters_digest;
  - schema validity: every emitted record validates against
    decision-record/1 (ingested records carry evidence; deny carries
    evidence);
  - the CLI policy path: --policy-file stamps the deployed config's
    sha256 as policy_hash.

Run from the repo root:  python3 -m pytest tests/test_agentgateway_shim.py -v
"""

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
SPEC = importlib.util.spec_from_file_location(
    "agentgateway_shim",
    ROOT / "plugins" / "agentgateway" / "shim" / "translate.py")
shim = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(shim)

SCHEMA = json.loads((ROOT / "framework" / "schemas" / "decision-record"
                     / "1.schema.json").read_text())

RUN_ID = "agw-t1-run-1"
STREAM_ID = f"{RUN_ID}:gateway"
SOURCE = "agentgateway-trace.jsonl"

# VERBATIM captured values (2026-10-08, live v1.5.0 run): the base64
# request bodies exactly as the dtrace events carry them, and the
# authorization rule expression.
A011_BODY_B64 = "eyJqc29ucnBjIjoiMi4wIiwiaWQiOiJhMDExIiwibWV0aG9kIjoidG9vbHMvY2FsbCIsInBhcmFtcyI6eyJuYW1lIjoicG9zdF9ob29rIiwiYXJndW1lbnRzIjp7ImJvZHkiOiJ0b29sLWNhbGwgcGF5bG9hZCJ9fX0="
A014_BODY_B64 = "eyJqc29ucnBjIjoiMi4wIiwiaWQiOiJhMDE0IiwibWV0aG9kIjoidG9vbHMvY2FsbCIsInBhcmFtcyI6eyJfbWV0YSI6e30sIm5hbWUiOiJwb3N0X2hvb2siLCJhcmd1bWVudHMiOnsiYm9keSI6InBvbGljeS1kZW55IHByb2JlIn19fQ=="
INIT_BODY_B64 = "eyJqc29ucnBjIjoiMi4wIiwiaWQiOiJpbml0IiwibWV0aG9kIjoiaW5pdGlhbGl6ZSIsInBhcmFtcyI6eyJwcm90b2NvbFZlcnNpb24iOiIyMDI1LTA2LTE4In19"
RULE_NAME = ('request.method != "POST" || json(request.body).method != '
             '"tools/call" || !json(request.body).params.name.endsWith('
             '"post_hook") || json(request.body).params.arguments.body '
             '== "tool-call payload"')


def _b64(payload) -> str:
    """The dtrace body encoding: base64 over compact JSON."""
    return base64.b64encode(
        json.dumps(payload, separators=(",", ":")).encode()).decode()


# SYNTHESIZED: the a011 ingress body with the guardscope correlation
# carriers in params._meta and the federated name prefix kept (both are
# exercised); the capture's own client predates the carriers.
A011_META_BODY_B64 = _b64({
    "jsonrpc": "2.0", "id": 1, "method": "tools/call",
    "params": {"name": "upstream__post_hook",
               "arguments": {"body": "tool-call payload"},
               "_meta": {"io.inspection/action_id": "a011",
                         "io.inspection/attempt": 0}}})
# SYNTHESIZED: requestId 7's ingress body — the upstream copy minus the
# gateway's added _meta (the capture's a014 body without _meta)
A014_INGRESS_BODY_B64 = _b64({
    "jsonrpc": "2.0", "id": "a014", "method": "tools/call",
    "params": {"name": "post_hook",
                "arguments": {"body": "policy-deny probe"}}})


def _row(received_epoch_ns, request_id, message, **extra):
    raw = {"requestId": request_id, "eventStart": None, "eventEnd": 264,
           "severity": "info", "message": message}
    raw.update(extra)
    return json.dumps({"received_epoch_ns": received_epoch_ns, "raw": raw})


# the authorizationResult of the allowed a011 post_hook tools/call
# (requestId 4; severity success in the capture)
ALLOW_RESULT_ROW = _row(
    1791476224472239301, 4,
    {"type": "authorizationResult",
     "rules": [{"name": RULE_NAME, "matched": True, "mode": "require"}],
     "result": "allow"}, severity="success")

# the ingress cel event of requestId 4 — its requestState.request.body is
# the base64 JSON-RPC tools/call of a011
ALLOW_CEL_ROW = _row(
    1791476224472149906, 4,
    {"type": "cel", "expr": RULE_NAME,
     "requestState": {"request": {
         "method": "POST", "uri": "http://gateway:8090/mcp",
         "path": "/mcp", "body": A011_BODY_B64}},
     "result": True}, eventStart=164, eventEnd=187)

# the denied a014 policy-deny probe (requestId 7) — the upstream body
# (agentgateway's added empty _meta) as a final-request bodySnapshot,
# plus its deny authorizationResult (the capture's live 403 request
# finished this group; the response rows are not used by the shim)
DENY_BODY_ROW = _row(
    1791476224472515610, 7,
    {"type": "bodySnapshot", "id": 7, "stage": "final request",
     "body": A014_BODY_B64}, eventStart=546, eventEnd=611,
    scope=["mcp upstream"])
DENY_RESULT_ROW = _row(
    1791476224636848380, 7,
    {"type": "authorizationResult",
     "rules": [{"name": RULE_NAME, "matched": False, "mode": "require"}],
     "result": "deny"}, eventEnd=258, severity="error")

# requestId 1 of the same capture: an initialize request — not a
# tools/call, so no record, and (alone) no problem either.
INIT_ROW = _row(
    1791476224375903491, 1,
    {"type": "requestSnapshot", "stage": "initial request",
     "requestState": {"request": {"body": INIT_BODY_B64}}})

META_CEL_ROW = _row(
    1791476224473149906, 5,
    {"type": "cel", "expr": "true",
     "requestState": {"request": {
         "method": "POST", "uri": "http://gateway:8090/mcp",
         "path": "/mcp", "body": A011_META_BODY_B64}},
     "result": True}, eventStart=164, eventEnd=187)
META_RESULT_ROW = _row(
    1791476224473239301, 5,
    {"type": "authorizationResult",
     "rules": [{"name": "true", "matched": True, "mode": "require"}],
     "result": "allow"}, severity="success")


def _record_for(lines, **kwargs):
    return shim.translate(lines, run_id=RUN_ID, stream_id=STREAM_ID,
                          source=SOURCE, **kwargs)


def test_one_record_per_tools_call_allow():
    records, problems = _record_for([ALLOW_CEL_ROW, ALLOW_RESULT_ROW])
    assert problems == []
    assert len(records) == 1
    rec = records[0]
    assert rec["decision"] == "allow"
    assert rec["action_class"] == "http_tool_call"
    assert rec["protocol"] == "http"
    assert rec["tool"] == "post_hook"
    assert rec["method"] == "POST" and rec["path"] == "/hook"
    assert rec["parameters"] == {"body": "tool-call payload"}
    assert rec["action_id"] is None
    assert rec["correlation_transport"] == "none"
    assert rec["attempt"] == 0
    assert rec["enforcement_point"] == {"slot_id": "gateway",
                                        "product": "agentgateway",
                                        "product_version": "v1.5.0"}
    assert rec["producer"]["record_source"] == "ingested"
    assert rec["producer"]["plugin"] == "agentgateway"
    assert rec["policy"] == {"policy_id": "unmapped",
                             "policy_version": "unmapped",
                             "policy_hash": "unmapped"}
    assert rec["source_schema"] == "agentgateway-dtrace-event/1"
    # the jsonrpc id is a vendor-native id, never the action_id
    assert rec["ids"]["jsonrpcId"] == "a011"
    assert rec["ids"]["requestId"] == 4
    # raw_ref provenance: the decision event's vendor line, plus the
    # ingress body's line when different
    assert rec["evidence"][0]["locator"]["source"] == SOURCE
    assert rec["evidence"][0]["locator"]["line"] == 2
    assert rec["evidence"][1]["locator"]["line"] == 1


def test_deny_record_and_final_request_body_fallback():
    # requestId 7 has no requestState body: the final-request bodySnapshot
    # (upstream shape, agentgateway's added empty _meta) grounds the record
    records, problems = _record_for([DENY_BODY_ROW, DENY_RESULT_ROW])
    assert problems == []
    assert len(records) == 1
    rec = records[0]
    assert rec["decision"] == "deny"
    assert rec["tool"] == "post_hook"
    assert rec["parameters"] == {"body": "policy-deny probe"}
    assert rec["action_id"] is None       # empty vendor _meta is not a carrier
    # deny records carry evidence (schema if/then; also the raw_ref)
    assert rec["evidence"][0]["locator"]["line"] == 2


def test_initialize_is_not_a_decision():
    records, problems = _record_for([INIT_ROW])
    assert records == []
    assert problems == []


def test_authorization_without_body_is_a_problem():
    # an authorizationResult with no request body cannot ground a record:
    # a problem, never a silent drop (shim guide: never silently dropped)
    records, problems = _record_for([ALLOW_RESULT_ROW])
    assert records == []
    assert len(problems) == 1
    assert "no native request body" in problems[0]


def test_ambiguous_authorization_is_a_problem():
    records, problems = _record_for(
        [ALLOW_CEL_ROW, ALLOW_RESULT_ROW, ALLOW_RESULT_ROW])
    assert records == []
    assert len(problems) == 1
    assert "ambiguous" in problems[0]


def test_unparseable_row_is_a_problem():
    records, problems = _record_for(["{not json"])
    assert records == []
    assert problems and "unparseable" in problems[0]


def test_torn_line_mid_file_does_not_discard_other_records():
    # the collector appends rows as it receives them; a torn line (a
    # collector killed mid-write, or a partial write) must be a PER-LINE
    # problem, never a whole-stream loss: the records before and after it
    # survive, and the bad line is reported
    torn = ("{\"received_epoch_ns\": 1791476224473000000, \"raw\": {\"req")
    records, problems = _record_for(
        [ALLOW_CEL_ROW, ALLOW_RESULT_ROW, torn,
         DENY_BODY_ROW, DENY_RESULT_ROW])
    assert len(records) == 2
    assert [r["decision"] for r in records] == ["allow", "deny"]
    assert len(problems) == 1 and "unparseable" in problems[0]
    # a non-dtrace line (missing raw.requestId/message) is the same class
    # of per-line problem
    records, problems = _record_for(
        ["{\"received_epoch_ns\": 1, \"raw\": {}}",
         ALLOW_CEL_ROW, ALLOW_RESULT_ROW])
    assert len(records) == 1
    assert len(problems) == 1 and "not a dtrace row" in problems[0]


def test_stats_count_skips_and_problems_never_silently():
    # initialize is a skip, not a problem — but the count is carried in
    # stats so the CLI's summary line is auditable against the
    # collector's row count (never silent)
    stats: dict = {}
    records, problems = shim.translate(
        [INIT_ROW, ALLOW_CEL_ROW, ALLOW_RESULT_ROW, "{torn"],
        run_id=RUN_ID, stream_id=STREAM_ID, source=SOURCE, stats=stats)
    assert len(records) == 1
    assert len(problems) == 1
    assert stats["groups"] == 2          # requestId 1 (init) + requestId 4
    assert stats["records"] == 1
    assert stats["skipped_not_tools_call"] == 1
    assert stats["skipped_no_body"] == 0
    assert stats["problems"] == 1         # the torn line (a skip is not a problem)


def test_correlation_carrier_echo():
    records, problems = _record_for([META_CEL_ROW, META_RESULT_ROW])
    assert problems == []
    assert len(records) == 1
    rec = records[0]
    # echoed from params._meta (carrier 1); the federated prefix stripped
    assert rec["action_id"] == "a011"
    assert rec["attempt"] == 0
    assert rec["correlation_transport"] == "mcp_meta"
    assert rec["tool"] == "post_hook"


def test_seq_monotonic_in_decision_order_and_ts_from_capture_clock():
    rows = [ALLOW_CEL_ROW, DENY_BODY_ROW, DENY_RESULT_ROW, ALLOW_RESULT_ROW,
            META_CEL_ROW, META_RESULT_ROW]
    records, problems = _record_for(rows)
    assert problems == []
    assert [r["seq"] for r in records] == [0, 1, 2]
    assert [r["ids"]["requestId"] for r in records] == [4, 5, 7]
    # ts is the authorizationResult capture clock (RFC3339 ms), in
    # decision-event order, never the file order
    assert records[0]["ts"] == "2026-10-08T16:17:04.472Z"
    assert records[1]["ts"] == "2026-10-08T16:17:04.473Z"
    assert records[2]["ts"] == "2026-10-08T16:17:04.636Z"


def test_parameters_digest_parity_with_framework():
    from framework.records import parameters_digest
    records, problems = _record_for([ALLOW_CEL_ROW, ALLOW_RESULT_ROW])
    assert problems == []
    assert records[0]["parameters_digest"] == \
        parameters_digest({"body": "tool-call payload"})


def test_records_validate_against_schema():
    rows = [ALLOW_CEL_ROW, ALLOW_RESULT_ROW, DENY_BODY_ROW, DENY_RESULT_ROW,
            META_CEL_ROW, META_RESULT_ROW]
    records, problems = _record_for(rows)
    assert problems == []
    for rec in records:
        jsonschema.validate(rec, SCHEMA)   # raises on any violation


def test_ingress_body_wins_over_upstream_body():
    # both an ingress requestState body and a final-request bodySnapshot
    # exist for the same request (the gateway adds _meta on the upstream
    # copy): the ingress (client-verbatim) body grounds the record
    ingress_for_7 = _row(
        1791476224472514000, 7,
        {"type": "requestSnapshot", "stage": "authorization",
         "requestState": {"request": {"body": A014_INGRESS_BODY_B64}}})
    records, problems = _record_for([ingress_for_7, DENY_BODY_ROW,
                                     DENY_RESULT_ROW])
    assert problems == []
    assert len(records) == 1
    assert records[0]["parameters"] == {"body": "policy-deny probe"}


def test_policy_file_stamps_deployed_config_hash(tmp_path):
    config = tmp_path / "t1-allow-all.json"
    config.write_text('{"mcp": {}}', encoding="utf-8")
    records, problems = _record_for(
        [ALLOW_CEL_ROW, ALLOW_RESULT_ROW],
        policy=shim._policy_from_file(str(config)))
    assert problems == []
    rec = records[0]
    assert rec["policy"]["policy_id"] == "t1-allow-all"
    assert rec["policy"]["policy_version"] == "1"
    assert rec["policy"]["policy_hash"] == hashlib.sha256(
        config.read_bytes()).hexdigest()


def test_cli_end_to_end(tmp_path):
    vendor = tmp_path / "agentgateway-trace.jsonl"
    vendor.write_text("\n".join(
        [INIT_ROW, ALLOW_CEL_ROW, ALLOW_RESULT_ROW]) + "\n",
        encoding="utf-8")
    out = tmp_path / "decision-records.jsonl"
    rc = shim.main(["--vendor-log", str(vendor), "--out", str(out),
                    "--run-id", RUN_ID,
                    "--source", "agentgateway-trace.jsonl"])
    assert rc == 0
    records = [json.loads(line)
               for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(records) == 1
    rec = records[0]
    assert rec["run_id"] == RUN_ID
    assert rec["stream_id"] == f"{RUN_ID}:gateway"
    jsonschema.validate(rec, SCHEMA)


def test_verbatim_capture_shape_assumptions():
    # the golden values above must decode exactly as the shim assumes:
    # base64 JSON-RPC bodies, tools/call params, the vendor's own empty
    # _meta on the upstream copy, and the deny probe's request body
    allow_body = json.loads(base64.b64decode(A011_BODY_B64).decode())
    assert allow_body["method"] == "tools/call"
    assert allow_body["params"]["name"] == "post_hook"
    assert "_meta" not in allow_body["params"]
    deny_body = json.loads(base64.b64decode(A014_BODY_B64).decode())
    assert deny_body["params"] == {"_meta": {},
                                   "name": "post_hook",
                                   "arguments": {"body": "policy-deny probe"}}
