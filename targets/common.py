"""Shared helpers for the C4 side-effect targets (M2).

Every target emits one JSON log line per served action so reconciliation
(M6) can diff "what was served" against the canonical trace spec, and so
mismatch debugging has a first-class artifact.

Log writers:
  - stdout (HTTP endpoint, net-peer): captured by `docker logs`
  - stderr (MCP stdio server): stdout is the MCP protocol channel and MUST
    carry only JSON-RPC messages (MCP stdio transport rule)
  - $TARGET_LOG_DIR/<name>.log: appended when the directory exists; compose
    mounts the shared `target-logs` volume at /var/log/targets so M6 can read
    all served-action logs without scraping container output.
"""

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

TARGET_LOG_DIR = Path(os.environ.get("TARGET_LOG_DIR", "/var/log/targets"))


def log_event(target: str, event: str, stream: str = "stdout", **fields) -> None:
    """Emit one structured log line for a served action.

    `stream` selects the console writer: "stdout" (docker logs) or "stderr"
    (required for the MCP stdio server, whose stdout is protocol-only).
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "event": event,
        **fields,
    }
    line = json.dumps(record, separators=(",", ":"))
    print(line, file=sys.stdout if stream == "stdout" else sys.stderr, flush=True)
    log_file = TARGET_LOG_DIR / f"{target}.log"
    try:
        if log_file.parent.is_dir():
            with open(log_file, "a", encoding="utf-8") as f:
                f.write(line + "\n")
    except OSError:
        # Logging must never break the target: e.g. the log volume is owned by
        # another container's user in shared compose topologies.
        pass