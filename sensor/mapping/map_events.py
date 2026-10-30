#!/usr/bin/env python3
"""Map raw Tracee events to the six canonical action classes (C6).

Input: Tracee NDJSON event stream (--in file or stdin; non-JSON lines such as
Tracee log messages are skipped). Output: JSONL canonical action records with
provenance to the raw event, plus a per-class summary on stderr.

Usage:
  python3 sensor/mapping/map_events.py --rules sensor/mapping/rules.yaml \
      --in tracee-events.jsonl --out mapped-actions.jsonl
  docker logs t0-tracee 2>/dev/null | python3 sensor/mapping/map_events.py --rules ...

Records carry: class, rule id, Tracee event name, timestamp, container/pid
provenance, syscall return value (Tracee `returnValue`; fallback `retval`), extracted target (path / port / argv), and the raw
event index so any mapped record can be traced back to the retained raw
stream. Unmapped records carry the same record fields with a best-effort
detail (path / port / flags / argv) so M6 reconciliation can apply
unrelated-event allowlists and debug leftovers without re-reading the raw
stream.
"""

import argparse
import base64
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import yaml

UNMAPPED = "unmapped"

# Order matters: credential_access must be tested before file_write (both
# key on security_file_open) so secret reads are not mislabeled as writes.
RULE_ORDER = [
    "credential_access",
    "http_tool_call",
    "direct_network",
    "file_write",
    "process_spawn",
    "stdio_tool_call",
]

WRITE_BITMASK = os.O_WRONLY | os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_TRUNC


def load_rules(path: str | Path) -> dict:
    rules = yaml.safe_load(Path(path).read_text())
    if not isinstance(rules.get("version"), int):
        raise ValueError(f"rules {path}: 'version' must be an int (pinned mapping version)")
    for name in RULE_ORDER:
        if name not in rules.get("classes", {}):
            raise ValueError(f"rules {path}: missing class '{name}'")
    return rules


def args_dict(event: dict) -> dict:
    """Tracee args array -> {name: value}."""
    return {a.get("name"): a.get("value") for a in event.get("args", [])}


def sockaddr_port(value) -> int | None:
    """Extract the destination port from a Tracee sockaddr argument."""
    if isinstance(value, dict):
        port = value.get("sin_port", value.get("sin6_port"))
        if isinstance(port, int):
            return port
        if isinstance(port, str):
            digits = "".join(ch for ch in port if ch.isdigit())
            return int(digits) if digits else None
    if isinstance(value, str):
        # defensive: rendered forms like "sin_port: 9001" or "9001"
        for token in value.replace(",", " ").split():
            if token.isdigit():
                return int(token)
    return None


def _flags_text(value) -> str:
    """Render open(2) flags as an uppercase flag string, whatever the mode."""
    if isinstance(value, str):
        return value.upper()
    if isinstance(value, int):  # raw int flags (unparsed output)
        names = []
        for name in ("O_RDONLY", "O_WRONLY", "O_RDWR", "O_APPEND", "O_CREAT", "O_TRUNC"):
            bit = getattr(os, name, None)
            if bit and value & bit == bit and name != "O_RDONLY":
                names.append(name)
        if value & os.O_ACCMODE == os.O_RDONLY:
            names.append("O_RDONLY")
        return "|".join(names)
    return ""


def _buf_text(value) -> str:
    """Decode a Tracee buffer argument to text, tolerating raw/base64 forms."""
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    if not isinstance(value, str):
        return str(value)
    try:
        return base64.b64decode(value, validate=True).decode("utf-8", "replace")
    except Exception:
        return value


class Mapper:
    """Stateful mapper over an ordered Tracee event stream.

    State (MCP server process registry) is keyed by (containerId, pid) and
    built from execve events as the stream is consumed, so map_event MUST be
    called for every event in original stream order. Create one Mapper per
    stream (or call reset() between streams).
    """

    def __init__(self, rules: dict, attribution_mode: str | None = None):
        self.version = rules["version"]
        self.classes = rules["classes"]
        if attribution_mode and attribution_mode not in rules.get("attribution_modes", {}):
            raise ValueError("unknown attribution mode: " + attribution_mode)
        self.attribution_mode = attribution_mode
        self.identity_fields = rules.get("attribution_modes", {}).get(attribution_mode, {}).get("identity_fields", [])
        self._server_procs: set[tuple[str | None, int]] = set()

    def reset(self) -> None:
        self._server_procs.clear()

    # -- per-class matchers ------------------------------------------------

    def _match_process_spawn(self, cfg, ev, a, raw):
        return {"target": str(a.get("pathname", a.get("filename", ""))),
                "cmd": a.get("argv")}

    def _match_port(self, cfg, ev, a, raw):
        """connect/sendto/sendmsg/net_packet_udp: classify by destination
        port lists. connect carries `addr`; sendto/sendmsg carry `dest_addr`
        (a null-dest send on a connected socket shows AF_UNSPEC and stays
        unmapped); net_packet_udp carries a parsed `dst_port`."""
        if ev == "net_packet_udp":
            port = a.get("dst_port")
            if port in cfg.get("udp_ports", []):
                return {"target_port": port, "transport": "udp",
                        "src": a.get("src"), "dst": a.get("dst")}
            return None
        sock = a.get("addr") if ev == "connect" else (a.get("dest_addr") or a.get("addr"))
        port = sockaddr_port(sock)
        if port is None:
            return None
        if ev == "connect" and port in cfg.get("tcp_ports", []):
            return {"target_port": port, "transport": "tcp"}
        if ev in ("sendto", "sendmsg") and port in cfg.get("udp_ports", []):
            return {"target_port": port, "transport": "udp"}
        return None

    def _match_http_tool_call(self, cfg, ev, a, raw):
        return self._match_port(cfg, "connect", a, raw)

    def _match_direct_network(self, cfg, ev, a, raw):
        return self._match_port(cfg, ev, a, raw)

    def _match_credential_access(self, cfg, ev, a, raw):
        path = str(a.get("pathname", ""))
        if not any(path.startswith(p) for p in cfg.get("path_prefixes", [])):
            return None
        flags = _flags_text(a.get("flags"))
        if not any(f in flags.split("|") for f in cfg.get("read_flags", [])):
            return None
        return {"target": f"file://{path}", "flags": flags}

    def _match_file_write(self, cfg, ev, a, raw):
        path = str(a.get("pathname", ""))
        if any(path.startswith(p) for p in cfg.get("exclude_path_prefixes", [])):
            return None
        flags = _flags_text(a.get("flags"))
        tokens = flags.split("|")
        if not any(f in tokens for f in cfg.get("write_flags", [])):
            return None
        return {"target": path, "flags": flags}

    def _server_key(self, raw):
        if self.attribution_mode == "csb-host-tree-v1":
            bounds = (self._active_lifetime or {}).get("bounds", [])
            if len(bounds) == 2:
                return (bounds[0], raw.get("hostProcessId"))
            entity = raw.get("processEntityId")
            return (entity, raw.get("hostProcessId")) if type(entity) is int and entity > 0 else None
        return (raw.get("containerId"), raw.get("processId"))

    def _match_stdio_tool_call(self, cfg, ev, a, raw):
        """Stateful: writes to response_fds from a registered tool-server
        process (see _update_server_registry) are tool-call events."""
        key = self._server_key(raw)
        if key in self._server_procs and a.get("fd") in cfg.get("response_fds", []):
            return {"target": "mcp://stdio", "fd": a.get("fd")}
        return None

    def _update_server_registry(self, ev, a, raw) -> None:
        """Track the MCP tool-server process from its execve argv marker or,
        reliably, its open of the server script (execve argv can be empty in
        Tracee 0.24). Runs for EVERY event before dispatch so registration
        happens even when the execve itself maps to another class."""
        cfg = self.classes.get("stdio_tool_call", {})
        key = self._server_key(raw)
        if key is None or key in self._server_procs:
            return
        if ev == "execve":
            marker = cfg.get("server_argv_marker", "")
            if marker and any(marker in str(part) for part in (a.get("argv") or [])):
                self._server_procs.add(key)
        elif ev == "security_file_open":
            script = cfg.get("server_script_path", "")
            if script and str(a.get("pathname", "")).startswith(script):
                self._server_procs.add(key)

    # -- dispatch -----------------------------------------------------------

    def map_event(self, raw: dict, index: int, lifetime: dict | None = None) -> dict | None:
        self._active_lifetime = lifetime  # csb registry follows proven PID lifetimes, not PID alone
        record = self._map_event(raw, index)
        if self.attribution_mode and record is not None:
            # Preserve raw identification (including absent/zero entity IDs)
            # without replacing processId or inferring container membership.
            record["identity"] = {k: raw[k] for k in self.identity_fields if k in raw}
            record["attribution_mode"] = self.attribution_mode
        return record

    def _map_event(self, raw: dict, index: int) -> dict | None:
        ev = raw.get("eventName", "")
        a = args_dict(raw)
        self._update_server_registry(ev, a, raw)
        for cls in RULE_ORDER:
            cfg = self.classes.get(cls, {})
            if ev not in cfg.get("events", []):
                continue
            matcher = getattr(self, f"_match_{cls}")
            detail = matcher(cfg, ev, a, raw)
            if detail is None:
                continue
            return {
                "class": cls,
                "rule": f"{cls}@v{self.version}",
                "event": ev,
                "ts": raw.get("timestamp"),
                "container": raw.get("containerId"),
                "pid": raw.get("processId"),
                "process": raw.get("processName"),
                "detail": detail,
                "provenance": {"raw_index": index, "retval": raw.get("returnValue", raw.get("retval"))},
            }
        # Unmapped records keep the full record fields (M6 reconciliation
        # needs the same fields for window/container scoping, unrelated-event
        # allowlists and leftover debugging); detail is best-effort.
        detail = {k: v for k, v in {
            "path": a.get("pathname", a.get("filename")),
            "port": self._unmapped_port(ev, a),
            "flags": _flags_text(a.get("flags")) or None,
            "argv": a.get("argv"),
        }.items() if v is not None}
        return {
            "class": UNMAPPED,
            "event": ev,
            "ts": raw.get("timestamp"),
            "container": raw.get("containerId"),
            "pid": raw.get("processId"),
            "process": raw.get("processName"),
            "detail": detail,
            "provenance": {"raw_index": index, "retval": raw.get("returnValue", raw.get("retval"))},
        }

    @staticmethod
    def _unmapped_port(ev: str, a: dict) -> int | None:
        sock = a.get("dest_addr") or a.get("addr")
        return sockaddr_port(sock) if sock is not None else a.get("dst_port")


def iter_events(stream):
    """Yield parsed Tracee events, skipping non-JSON (log/warning) lines."""
    for line in stream:
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict) and "eventName" in obj:
            yield obj


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    default_rules = Path(__file__).resolve().parent / "rules.yaml"
    ap.add_argument("--rules", default=str(default_rules))
    ap.add_argument("--in", dest="infile", default="-", help="Tracee NDJSON file or - for stdin")
    ap.add_argument("--out", dest="outfile", default="-", help="mapped-action JSONL output")
    args = ap.parse_args()

    rules = load_rules(args.rules)
    mapper = Mapper(rules)

    instream = sys.stdin if args.infile == "-" else open(args.infile, encoding="utf-8")
    outstream = sys.stdout if args.outfile == "-" else open(args.outfile, "w", encoding="utf-8")

    counts: dict[str, int] = {}
    try:
        for index, raw in enumerate(iter_events(instream)):
            record = mapper.map_event(raw, index)
            label = record["class"]
            counts[label] = counts.get(label, 0) + 1
            outstream.write(json.dumps(record, separators=(",", ":")) + "\n")
    finally:
        outstream.flush()
        if args.infile != "-":
            instream.close()
        if args.outfile != "-":
            outstream.close()

    summary = json.dumps({
        "ts": datetime.now(timezone.utc).isoformat(),
        "target": "map_events", "event": "summary",
        "mapping_version": mapper.version,
        "counts": dict(sorted(counts.items())),
    }, separators=(",", ":"))
    print(summary, file=sys.stderr, flush=True)


if __name__ == "__main__":
    main()