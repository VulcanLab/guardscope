#!/bin/bash
# OpenClaw harness entrypoint (C3, M4).
# 1. Seed the C4 targets that live in-harness (credentials + workspace paths).
# 2. Drop to the node user (image default) and run the OpenClaw gateway.
# The compiled trace is NOT needed here: the driver posts it to
# POST /tools/invoke -> replay_trace at replay time.
set -euo pipefail

: "${WORKSPACE_DIR:=/workspace}"
mkdir -p "$WORKSPACE_DIR/out"
WORKSPACE_DIR="$WORKSPACE_DIR" bash /opt/inspection/setup-fs.sh

# /run/secrets needs root to create; files end up node-owned mode 0400 so the
# gateway (node user) can read them and Tracee classifies the reads.
SECRETS_DIR=/run/secrets bash /opt/inspection/seed-credentials.sh
chown node:node /run/secrets/token /run/secrets/db_password

export REPLAY_LOG_DIR="${REPLAY_LOG_DIR:-/workspace/replay}"
export TARGET_LOG_DIR="${TARGET_LOG_DIR:-/var/log/targets}"
mkdir -p "$REPLAY_LOG_DIR" "$TARGET_LOG_DIR"
# The target-logs volume is shared with root-running target services; the
# in-harness MCP server (node user) appends its served-action log there too.
chown node:node "$TARGET_LOG_DIR" 2>/dev/null || true
chown -R node:node "$REPLAY_LOG_DIR" "$WORKSPACE_DIR"

# T4/T6 mode: merge the variant config (mcp.servers registration) over the
# baked config WITHOUT clobbering the plugins-install registry state.
if [ "${T4_MODE:-}" = "1" ] || [ "${T6_MODE:-}" = "1" ]; then
  node -e '
    const fs = require("fs");
    const read = (p) => JSON.parse(fs.readFileSync(p, "utf8").replace(/^\s*\/\/.*$/gm, ""));
    const cfg = read("/home/node/.openclaw/openclaw.json");
    const variant = read("/opt/inspection-replay/openclaw-t4.json");
    cfg.mcp = { ...cfg.mcp, servers: { ...(cfg.mcp?.servers ?? {}), ...variant.mcp?.servers } };
    if (variant.tools) {
      cfg.tools = { ...cfg.tools, ...variant.tools,
        alsoAllow: [...new Set([...(cfg.tools?.alsoAllow ?? []), ...(variant.tools?.alsoAllow ?? [])])] };
    }
    fs.writeFileSync("/home/node/.openclaw/openclaw.json", JSON.stringify(cfg, null, 2) + "\n");
  '
  chown node:node /home/node/.openclaw/openclaw.json
  echo "entrypoint: T4/T6 config merged (mcp.servers registered)"
fi

cd /app
export HOME=/home/node   # setpriv drops uid but not HOME; openclaw uses ~/.openclaw
exec setpriv --reuid=1000 --regid=1000 --clear-groups \
  node openclaw.mjs gateway
