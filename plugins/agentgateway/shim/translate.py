#!/usr/bin/env python3
"""agentgateway decision shim (plugins/agentgateway/shim/translate.py).

Translates the captured agentgateway admin /debug/trace rows (the vendor
decision stream persisted by the binding's collector,
plugins/agentgateway/collector/capture.py) into decision-record/1
(DESIGN.md 3 "Shims are not a separate tier": record_source ingested,
mandatory raw_ref provenance per record).

Vendor row grammar (the collector's JSONL, one row per dtrace SSE event;
samples below are VERBATIM rows from the live v1.5.0 capture of
2026-10-08 retained by the pre-guardscope probe):

  {"received_epoch_ns": <capture clock ns>, "raw": {"requestId": <u64>,
   "eventStart": <us|null>, "eventEnd": <us>, "severity": "...",
   "scope"?: [...], "message": {"type": ...}}}

Message types this shim consumes (crates/agentgateway/src/proxy/dtrace.rs
MessageType, camelCase serde tag); everything else is bookkeeping:

  cel                   {"expr", "requestState": {"request": {"body": ...}},
                         "result"} — one per rule evaluation; the INGRESS
                         request body (base64 JSON-RPC, verbatim)
  requestSnapshot       {"stage", "requestState": {...}} — same body shape
  bodySnapshot          {"stage": "final request", "body": ...} — the
                         UPSTREAM body (agentgateway may add its own _meta
                         and re-namespace the tool; used only as fallback)
  authorizationResult   {"rules": [{"name", "matched", "mode"}],
                         "result": "allow"|"deny"} — THE decision

Per request (one JSON-RPC HTTP request = one requestId), the shim emits at
most ONE record, and only when the request is an MCP tools/call (requests
without a decision, or non-tools/call requests such as initialize, are not
canonical decisions — the AGT-style gateway's audit entry has no
initialize rows either):

  record = <the authorizationResult event> joined with <the ingress
  tools/call body>, exactly the grouping of the pre-guardscope probe's
  normalize() (group by requestId; prefer the ingress requestState body;
  response bodies and bodyPrefix are NEVER used; exactly one allow/deny
  authorizationResult required — ambiguous or missing authorization is a
  PROBLEM, never a silently-dropped or guessed decision).

Field mapping (docs/shim-guide.md 2):
  ts                    the authorizationResult row's capture clock
                        (received_epoch_ns) — agentgateway's dtrace events
                        carry only relative event times (µs since gateway
                        start), so the collector's capture clock is the
                        wall-clock anchor; RFC3339 ms, never an ordering key
  action_class           http_tool_call: the fixture's HTTP tool calls cross
                        the gateway as MCP tools/call over streamable HTTP
  protocol/method/path   http + the tool's route from the routing table
                        (mirrors framework/reconcile.py GATEWAY_TOOL_ROUTES,
                        i.e. targets/mcp-http TOOL_ROUTES; unknown tools
                        carry no method/path, the record still reports them)
  tool                   the BARE tool name (the federated upstream__ /
                        upstream_ prefixes are stripped; with the binding's
                        single-target conditional-prefix config names pass
                        through unprefixed)
  action_id/attempt     echoed from the tools/call params._meta
                        io.inspection/* carriers when present, else null
                        (never learned from configuration; the JSON-RPC id
                        is a vendor-native id, carried in `ids`, never a
                        join key). correlation_transport: mcp_meta when
                        echoed, else none.
  decision              allow | deny from the authorizationResult
  policy                the deployed policy descriptor passed by the caller
                        (--policy-file computes the sha256 of the deployed
                        config; without it the fields are marked unmapped,
                        never guessed)
  evidence              raw_ref provenance: the vendor log line of the
                        authorizationResult row, plus the ingress-body row
                        when it is a different line — both point back at
                        the vendor log unchanged
  source_schema         agentgateway-dtrace-event/1

Usage (standalone, for the L1 golden set — docs/shim-guide.md 5):
    translate.py [--vendor-log PATH|-] [--out PATH|-]
                 [--run-id ID] [--stream-id ID] [--policy-file PATH]

Problems are printed to stderr and never silently dropped
(docs/shim-guide.md: a malformed line is a problem, never a silent drop).
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

# --- identities ---------------------------------------------------------------

PLUGIN = "agentgateway"
PLUGIN_VERSION = "0.1.0"          # plugins/agentgateway/manifest.json
PRODUCT = "agentgateway"
PRODUCT_VERSION = "v1.5.0"        # the pinned image tag (versions.env)
SLOT_ID = "gateway"
SLOT_TARGET = "http://mcp-http:8091/mcp"   # the fixture's upstream endpoint
SOURCE_SCHEMA = "agentgateway-dtrace-event/1"
DEFAULT_TRACE_NAME = "agentgateway-trace.jsonl"   # the collector's output name

# The vendor log format carries no policy identity; without the deployed
# policy descriptor the fields are marked unmapped, never guessed (the same
# convention as the v0 AuditEntry mapping, framework/records.py
# V0_UNMAPPED_POLICY).
UNMAPPED_POLICY = {"policy_id": "unmapped", "policy_version": "unmapped",
                   "policy_hash": "unmapped"}

# tool -> (method, path): mirrors framework/reconcile.py GATEWAY_TOOL_ROUTES
# and targets/mcp-http/server.py TOOL_ROUTES (post_hook/get_health/put_state
# <-> the canonical http_tool_call actions a011-a013). T1 has exactly one
# tool per canonical HTTP action; the mapping fills the record's HTTP route
# fields the vendor event never carries.
GATEWAY_TOOL_ROUTES = {
    "post_hook": ("POST", "/hook"),
    "get_health": ("GET", "/health"),
    "put_state": ("PUT", "/state"),
}

# The MCP tools/call correlation carriers (DESIGN.md 5 carrier 1).
META_ACTION_ID = "io.inspection/action_id"
META_ATTEMPT = "io.inspection/attempt"


# --- record primitives (same definitions as framework/records.py) ---------------

_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def _ulid() -> str:
    """26-char ULID: 48-bit ms timestamp + 80 random bits."""
    ms = time.time_ns() // 1_000_000
    rand = int.from_bytes(uuid.uuid4().bytes[:10], "big")
    value = (ms << 80) | rand
    out = []
    for _ in range(26):
        out.append(_CROCKFORD[value & 0x1F])
        value >>= 5
    return "".join(reversed(out))


def _rfc3339_ms(epoch_ns: int) -> str:
    dt = datetime.fromtimestamp(int(epoch_ns) / 1e9, tz=timezone.utc)
    return (dt.strftime("%Y-%m-%dT%H:%M:%S.")
            + f"{dt.microsecond // 1000:03d}Z")


def _parameters_digest(parameters: dict) -> str:
    """sha256 over canonical JSON of the (redacted) parameters — the same
    canonicalization as framework/records.py parameters_digest()."""
    return hashlib.sha256(
        json.dumps(parameters, sort_keys=True, separators=(",", ":"),
                   ensure_ascii=False).encode("utf-8")).hexdigest()


def _bare_tool(name):
    """Strip the federated target prefixes (agentgateway prefixes tool
    names with the target name when multiplexing; the binding's
    single-target config passes them through bare — both shapes accepted,
    exactly the pre-guardscope probe's bare_tool rule)."""
    if isinstance(name, str):
        for prefix in ("upstream__", "upstream_"):
            if name.startswith(prefix):
                return name[len(prefix):]
    return name


# --- vendor-row parsing ---------------------------------------------------------

class _Problem(ValueError):
    """A vendor row group cannot ground a decision (recorded, never raised)."""


def _decode_body(body):
    """The dtrace request bodies are base64-serialized bytes; plain JSON
    strings are also accepted (the pre-guardscope probe's decode_body)."""
    if not isinstance(body, str) or body == "":
        return None
    try:
        payload = json.loads(body)
    except ValueError:
        try:
            payload = json.loads(base64.b64decode(body, validate=True)
                                 .decode("utf-8"))
        except (ValueError, UnicodeDecodeError) as exc:
            raise _Problem(f"invalid native request body: {exc}") from exc
    if not isinstance(payload, dict):
        raise _Problem("native request body is not a JSON-RPC object")
    return payload


def _group_rows(lines, problems: list):
    """Parse the vendor JSONL into per-requestId groups, first-seen order.
    Yields (request_id, rows) where rows is [(line_no, row_dict), ...].

    A single torn/unparseable line is a PER-LINE problem appended to
    `problems` (never raised): the collector appends rows as it receives
    them, so one bad line must never discard the rest of the stream's
    decisions (a collector killed mid-write leaves a torn tail; the rows
    before it stay valid evidence)."""
    groups: dict = {}
    order: list = []
    for lineno, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError as exc:
            problems.append(f"line {lineno}: unparseable vendor row: {exc}")
            continue
        raw = row.get("raw")
        if not isinstance(raw, dict) or "requestId" not in raw \
                or not isinstance(raw.get("message"), dict):
            problems.append(f"line {lineno}: not a dtrace row "
                            f"(missing raw.requestId / raw.message)")
            continue
        rid = raw["requestId"]
        if rid not in groups:
            groups[rid] = []
            order.append(rid)
        groups[rid].append((lineno, row))
    for rid in order:
        yield rid, groups[rid]


def _select_tools_call(group):
    """The ingress tools/call payload of one request group, with the source
    row's line number. Returns one of:
      ("tools_call", payload, line_no)   a tools/call the decision joins
      ("not_tools_call", None, None)     the request had decodable bodies
                                        but no tools/call (initialize /
                                        discovery: not a canonical
                                        decision — skipped silently, the
                                        pre-guardscope probe's rule)
      ("no_body", None, None)            no decodable request body at all
    Raises _Problem on undecodable or inconsistent bodies."""
    calls = []           # (is_ingress, payload, line_no)
    any_body = False
    for line_no, row in group:
        msg = row["raw"]["message"]
        mtype = msg.get("type")
        # response bodies and bodyPrefix are NEVER used (the vendor's own
        # caution: a response is not the request; a prefix may be truncated)
        body = None
        if mtype in ("cel", "requestSnapshot") \
                and isinstance(msg.get("requestState"), dict):
            body = msg["requestState"].get("request", {}).get("body")
        elif mtype == "bodySnapshot" and msg.get("stage") == "final request":
            body = msg.get("body")
        if body in (None, ""):
            continue
        any_body = True
        payload = _decode_body(body)
        if payload.get("method") == "tools/call":
            calls.append((mtype in ("cel", "requestSnapshot"),
                          payload, line_no))
    if not calls:
        return (("not_tools_call", None, None) if any_body
                else ("no_body", None, None))
    # prefer an INGRESS body even when SSE rows arrive out of order
    is_ingress, payload, line_no = next(
        ((i, p, ln) for i, p, ln in calls if i), calls[0])
    # every captured body of one request must agree (a gateway re-write
    # would make the decision ambiguous — a problem, not a guess)
    for other_ingress, other, _ in calls:
        if other.get("id") != payload.get("id") \
                or _bare_tool((other.get("params") or {}).get("name")) \
                != _bare_tool((payload.get("params") or {}).get("name")):
            raise _Problem("inconsistent gateway request bodies")
        if other_ingress and other != payload:
            raise _Problem("inconsistent ingress request bodies")
    return "tools_call", payload, line_no


def _authorization(group):
    """The single allow/deny authorizationResult of one request group.
    Returns (result_row, line_no) or raises _Problem (missing or ambiguous
    authorization is never guessed)."""
    results = [(row, line_no) for line_no, row in group
               if row["raw"]["message"].get("type") == "authorizationResult"]
    valid = [(row, line_no) for row, line_no in results
             if row["raw"]["message"].get("result") in ("allow", "deny")]
    if len(results) != 1 or len(valid) != 1:
        raise _Problem("missing/ambiguous native authorization "
                       f"({len(results)} authorizationResult events)")
    return valid[0]


def _decision_detail(rules) -> str:
    parts = [f"{r.get('mode')}:{r.get('name')} matched={r.get('matched')}"
             for r in rules or []]
    return ("agentgateway mcp.policies.authorization authorizationResult; "
            "rules: " + ("; ".join(parts) if parts else "<none>"))


# --- the translation ---------------------------------------------------------

def iter_records(lines, *, run_id: str, stream_id: str | None = None,
                 plugin_version: str = PLUGIN_VERSION,
                 product_version: str = PRODUCT_VERSION,
                 policy: dict | None = None,
                 source: str = DEFAULT_TRACE_NAME,
                 stats: dict | None = None):
    """Translate vendor rows (an iterable of JSONL lines) into
    decision-record/1 records. Yields (record | None, problem | None) pairs
    so no problem is ever silently dropped: a bad group yields
    (None, problem-string), a good one (record, None). seq is per-stream
    monotonic in emission order (decision-event capture order).

    stats, when a dict is given, is filled with the audit counts (groups,
    records, skipped_not_tools_call, skipped_no_body, problems) so a caller
    that batches through translate() can still print the one-line skip
    summary the collector's row count is audited against (a skip is not a
    problem, but it is never silent either).
    """
    stream_id = stream_id or f"{run_id}:{SLOT_ID}"
    policy = dict(policy or UNMAPPED_POLICY)
    seq = 0
    stats = stats if stats is not None else {}
    stats.update({"groups": 0, "records": 0, "skipped_not_tools_call": 0,
                  "skipped_no_body": 0, "problems": 0})
    parse_problems: list[str] = []
    groups = list(_group_rows(lines, parse_problems))
    stats["groups"] = len(groups)
    stats["lines_problems"] = len(parse_problems)
    for problem in parse_problems:
        stats["problems"] += 1
        yield None, problem
    decisions = []
    for rid, group in groups:
        try:
            kind, payload, body_line = _select_tools_call(group)
            if kind == "no_body":
                # an authorization event with no decodable request body
                # (a request the gateway rejected before relaying it)
                # cannot ground a record: a problem, never a silent drop
                # (shim guide: a malformed line is a problem, never a
                # silent drop)
                if any(row["raw"]["message"].get("type")
                       == "authorizationResult" for _, row in group):
                    raise _Problem("authorization event with no native "
                                   "request body")
                stats["skipped_no_body"] += 1
                continue
            if kind == "not_tools_call":
                # initialize/discovery: not a canonical decision — skipped,
                # never silent (the stats carry the count so the caller's
                # summary line is auditable against the collector's rows;
                # the pre-guardscope probe's rule)
                stats["skipped_not_tools_call"] += 1
                continue
            params = payload.get("params")
            if not isinstance(params, dict) \
                    or not isinstance(params.get("arguments"), dict):
                raise _Problem("invalid tools/call params")
            result_row, result_line = _authorization(group)
            decisions.append((result_row, result_line, payload,
                             body_line, rid))
        except _Problem as exc:
            stats["problems"] += 1
            yield None, f"requestId {rid}: {exc}"
    decisions.sort(key=lambda d: d[0]["received_epoch_ns"])
    for result_row, result_line, payload, body_line, rid in decisions:
        params = payload["params"]
        tool = _bare_tool(params.get("name"))
        arguments = params["arguments"]
        meta = params.get("_meta") if isinstance(params.get("_meta"),
                                                 dict) else {}
        action_id = meta.get(META_ACTION_ID)
        attempt = meta.get(META_ATTEMPT)
        record = {
            "schema": 1,
            "record_id": _ulid(),
            "run_id": run_id,
            "stream_id": stream_id,
            "seq": seq,
            "ts": _rfc3339_ms(result_row["received_epoch_ns"]),
            "enforcement_point": {"slot_id": SLOT_ID, "product": PRODUCT,
                                  "product_version": product_version},
            "producer": {"plugin": PLUGIN, "plugin_version": plugin_version,
                         "record_source": "ingested"},
            "action_class": "http_tool_call",
            "protocol": "http",
            "tool": tool if isinstance(tool, str) and tool else "unknown",
            "target": {"kind": "http_url", "value": SLOT_TARGET,
                       "note": "the gateway's single MCP upstream "
                               "(the fixture's tool endpoint)"},
            "parameters_digest": _parameters_digest(arguments),
            "action_id": action_id if isinstance(action_id, str) else None,
            "attempt": attempt if isinstance(attempt, int) and attempt >= 0
            else 0,
            "correlation_transport": "mcp_meta" if action_id else "none",
            "decision": result_row["raw"]["message"]["result"],
            "policy": dict(policy),
            "decision_detail": _decision_detail(
                result_row["raw"]["message"].get("rules")),
            "parameters": arguments,
            "ids": {"requestId": rid,
                    "jsonrpcId": payload.get("id")},
            "evidence": [
                {"kind": "vendor-line",
                 "locator": {"source": source, "line": result_line,
                             "note": "the authorizationResult dtrace event "
                                     "the decision was translated from"}},
                *([{"kind": "vendor-line",
                    "locator": {"source": source, "line": body_line,
                                "note": "the ingress tools/call request body "
                                        "the decision is joined with"}}]
                  if body_line != result_line else []),
            ],
            "source_schema": SOURCE_SCHEMA,
        }
        # HTTP route fields when the routing table knows the tool
        if tool in GATEWAY_TOOL_ROUTES:
            record["method"], record["path"] = GATEWAY_TOOL_ROUTES[tool]
        seq += 1
        stats["records"] += 1
        yield record, None


def translate(lines, **kwargs) -> tuple[list[dict], list[str]]:
    """(records, problems): the batch form of iter_records — the L1 golden
    set's entry point (every problem retained, never a silent drop)."""
    records, problems = [], []
    for record, problem in iter_records(lines, **kwargs):
        if problem is not None:
            problems.append(problem)
        else:
            records.append(record)
    return records, problems


def _policy_from_file(path: str) -> dict:
    """The deployed policy descriptor from the binding's config file: the
    sha256 of the deployed artifact (the fixture fingerprint pins the same
    file; policy_id names the binding's config, version 1)."""
    digest = hashlib.sha256(Path(path).read_bytes()).hexdigest()
    return {"policy_id": "t1-allow-all", "policy_version": "1",
            "policy_hash": digest}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        description="Translate captured agentgateway /debug/trace rows "
                    "(JSONL) into decision-record/1.")
    ap.add_argument("--vendor-log", default="-",
                    help="the collector's vendor JSONL ('-' = stdin)")
    ap.add_argument("--out", default="-", help="output JSONL ('-' = stdout)")
    ap.add_argument("--run-id", default="unknown-run")
    ap.add_argument("--stream-id", default=None,
                    help="default <run_id>:gateway")
    ap.add_argument("--policy-file", default=None,
                    help="the deployed agentgateway config (its sha256 "
                         "becomes policy_hash; without it the policy "
                         "fields are marked unmapped)")
    ap.add_argument("--source", default=DEFAULT_TRACE_NAME,
                    help="the vendor log's name for the evidence locators")
    args = ap.parse_args(argv)

    lines = (sys.stdin if args.vendor_log == "-"
             else open(args.vendor_log, encoding="utf-8"))
    policy = _policy_from_file(args.policy_file) if args.policy_file else None
    out = (sys.stdout if args.out == "-"
           else open(args.out, "w", encoding="utf-8"))
    stats: dict = {}
    try:
        for record, problem in iter_records(
                lines, run_id=args.run_id, stream_id=args.stream_id,
                policy=policy, source=args.source, stats=stats):
            if problem is not None:
                print(f"translate: {problem}", file=sys.stderr)
                continue
            out.write(json.dumps(record, sort_keys=True) + "\n")
            out.flush()
    finally:
        if lines is not sys.stdin:
            lines.close()
        if out is not sys.stdout:
            out.close()
    # the skip-count summary (never silent): the counts are auditable
    # against the collector's row count — a group whose request carried no
    # tools/call body (initialize/discovery) is a skip, not a problem
    print("translate: {groups} request group(s): {records} record(s), "
          "{skipped_not_tools_call} skipped (initialize/discovery), "
          "{skipped_no_body} skipped (no decodable request body), "
          "{problems} problem(s)".format(**stats), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
