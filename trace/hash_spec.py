#!/usr/bin/env python3
"""SHA-256 hashing for canonical trace specs (C1).

The canonical hash is computed over a normalized form of the spec (YAML
parsed, re-serialized as sorted-key JSON with fixed separators), so the hash
is stable across cosmetic edits: key reordering, comment changes, quoting,
and indentation. Semantic changes to any action change the hash.

Usage:
  hash_spec.py [SPEC]                     print canonical hash (default: traces/baseline.yaml)
  hash_spec.py --check HASH|FILE [SPEC]   exit 0 if hash matches, 1 otherwise
  hash_spec.py --write-sidecar [SPEC]     write SPEC.sha256 ("hash  name" format)
  hash_spec.py --raw [SPEC]               hash raw file bytes instead of canonical form

The canonical hash is what goes into the run record and manifest (M6/M7);
reruns must produce identical hashes.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import yaml

DEFAULT_SPEC = Path(__file__).resolve().parent / "traces" / "baseline.yaml"


def canonical_bytes(spec_path: Path) -> bytes:
    with spec_path.open("r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return json.dumps(
        data, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(spec_path: Path) -> str:
    return sha256(canonical_bytes(spec_path))


def raw_hash(spec_path: Path) -> str:
    return sha256(spec_path.read_bytes())


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("spec", nargs="?", type=Path, default=DEFAULT_SPEC)
    parser.add_argument("--check", metavar="HASH_OR_FILE", help="verify against a hash or a .sha256 sidecar")
    parser.add_argument("--write-sidecar", action="store_true", help="write <spec>.sha256 sidecar")
    parser.add_argument("--raw", action="store_true", help="hash raw file bytes instead of the canonical form")
    args = parser.parse_args()

    if not args.spec.is_file():
        print(f"error: spec not found: {args.spec}", file=sys.stderr)
        return 2

    digest = raw_hash(args.spec) if args.raw else canonical_hash(args.spec)

    if args.check:
        expected = args.check
        sidecar = Path(expected)
        if sidecar.is_file():
            expected = sidecar.read_text().split()[0]
        if digest == expected:
            print(f"OK {digest}  {args.spec}")
            return 0
        print(f"MISMATCH: expected {expected}, got {digest} ({args.spec})", file=sys.stderr)
        return 1

    if args.write_sidecar:
        sidecar = args.spec.with_suffix(args.spec.suffix + ".sha256")
        sidecar.write_text(f"{digest}  {args.spec.name}\n")
        print(f"wrote {sidecar}")

    print(digest)
    return 0


if __name__ == "__main__":
    sys.exit(main())
