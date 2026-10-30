#!/usr/bin/env python3
"""Compile the canonical trace spec into the Pi replay-adapter input (C2).

Reads a canonical trace YAML (trace/traces/*.yaml) and emits a deterministic
compiled JSON trace consumed by the Pi inspection-replay extension
(harnesses/pi/adapter). The execution plan (kind + arguments) is identical in
shape to the OpenClaw one — the adapters share the replay contract — so both
harnesses execute the same action surface from the same canonical spec.

Usage (the runner writes compiled traces under the experiments workdir
-- <workdir>/cache/compile/pi/, framework/workdir.py -- never into this
source tree):
  python3 trace/compile/pi/compile.py trace/traces/baseline.yaml \
      --out <workdir>/cache/compile/pi/baseline.compiled.json
  python3 trace/compile/pi/compile.py trace/traces/baseline.yaml --check   # diff only
"""

import argparse
import hashlib
import json
import shlex
import sys
from pathlib import Path

import yaml


def spec_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def compile_action(a: dict) -> dict:
    """Canonical action -> adapter execution plan (deterministic)."""
    cls, op, args = a["class"], a["op"], a.get("args") or {}
    rec = {"id": a["id"], "class": cls, "target": a["target"], "op": op}

    if cls == "stdio_tool_call":
        # target mcp://fs@local -> MCP server "fs"; op is the tool name
        rec["kind"] = "mcp"
        rec["server"] = a["target"].removeprefix("mcp://").split("@")[0]
        rec["tool"] = op
        rec["arguments"] = dict(args)
    elif cls == "http_tool_call":
        base = a["target"].rstrip("/")
        rec["kind"] = "http"
        rec["method"] = op
        rec["url"] = base + args.get("path", "")
        if "body" in args:
            rec["body"] = args["body"]
    elif cls == "direct_network":
        host, port = a["target"].rsplit(":", 1)
        rec["kind"] = op  # tcp_connect | udp_send
        rec["host"], rec["port"] = host, int(port)
        if "payload" in args:
            rec["payload"] = args["payload"]
    elif cls == "process_spawn":
        rec["kind"] = "spawn"
        if op != "exec":
            raise ValueError(f"{a['id']}: unsupported process_spawn op {op!r}")
        if a["target"].endswith("/sh"):
            rec["cmd"] = [a["target"], "-c", args["cmd"]]
        else:
            rec["cmd"] = [a["target"]] + shlex.split(args["cmd"])
    elif cls == "file_write":
        rec["kind"] = "file_write"
        rec["path"] = a["target"]
        rec["data"] = args.get("data", "")
        rec["append"] = op == "append"
    elif cls == "credential_access":
        rec["kind"] = "credential_read"
        rec["path"] = a["target"].removeprefix("file://")
    else:
        raise ValueError(f"{a['id']}: unknown class {cls!r}")
    return rec


def compile_spec(spec_path: Path) -> dict:
    spec = yaml.safe_load(spec_path.read_text())
    return {
        "meta": {
            "source_spec": spec_path.name,
            "spec_sha256": spec_sha256(spec_path),
            "harness": "pi",
            "compiler": "pi@1",
        },
        "window": spec.get("meta", {}).get("window", {}),
        "actions": [compile_action(a) for a in spec["actions"]],
    }


def diff_compiled(spec_path: Path, compiled: dict) -> list[str]:
    """C2 acceptance: compiled trace diffs clean against the spec (id/class/
    target/op must match 1:1; execution plan keys present)."""
    spec = yaml.safe_load(spec_path.read_text())
    problems = []
    spec_actions = {a["id"]: a for a in spec["actions"]}
    compiled_ids = [a["id"] for a in compiled["actions"]]
    if compiled_ids != list(spec_actions):
        problems.append(f"action order/set mismatch: {compiled_ids}")
    for rec in compiled["actions"]:
        sa = spec_actions.get(rec["id"])
        if not sa:
            problems.append(f"{rec['id']}: not in spec")
            continue
        for field in ("class", "target", "op"):
            if rec.get(field) != sa[field]:
                problems.append(f"{rec['id']}: {field} {rec.get(field)!r} != {sa[field]!r}")
        if rec.get("kind") is None:
            problems.append(f"{rec['id']}: missing execution kind")
    if compiled["meta"]["spec_sha256"] != spec_sha256(spec_path):
        problems.append("spec_sha256 mismatch (spec changed since compile?)")
    return problems


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("spec", type=Path)
    ap.add_argument("--out", type=Path, help="compiled JSON output path")
    ap.add_argument("--check", action="store_true",
                    help="compile and diff against the spec; nonzero exit on drift")
    args = ap.parse_args()

    compiled = compile_spec(args.spec)
    problems = diff_compiled(args.spec, compiled)
    if args.check:
        if problems:
            print("\n".join(problems), file=sys.stderr)
            sys.exit(1)
        print("clean")
        return
    text = json.dumps(compiled, indent=1, sort_keys=True) + "\n"
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(text)
        print(f"wrote {args.out} ({len(compiled['actions'])} actions)")
    else:
        sys.stdout.write(text)


if __name__ == "__main__":
    main()