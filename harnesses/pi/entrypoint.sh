#!/bin/bash
# Pi harness entrypoint (C3, M5).
# 1. Seed the C4 targets that live in-harness (credentials + workspace paths).
# 2. Stay up: the driver execs one pi RPC process per replay run
#    (docker exec -i t0-pi pi --mode rpc --no-session -e /opt/inspection/adapter/replay.ts),
#    keeping the pi process lifetime ≈ the replay window (clean Tracee scoping).
#
# Runs as root: pi executes actions as root in this container (no privilege
# drop needed — the image default is root and no gateway user model exists).
set -euo pipefail

: "${WORKSPACE_DIR:=/workspace}"
mkdir -p "$WORKSPACE_DIR/out"
WORKSPACE_DIR="$WORKSPACE_DIR" bash /opt/inspection/setup-fs.sh

SECRETS_DIR=/run/secrets bash /opt/inspection/seed-credentials.sh

export REPLAY_LOG_DIR="${REPLAY_LOG_DIR:-/workspace/replay}"
export TARGET_LOG_DIR="${TARGET_LOG_DIR:-/var/log/targets}"
export MCP_SERVER_CMD="${MCP_SERVER_CMD:-[\"python3\",\"-u\",\"/opt/inspection/mcp-fs/server.py\"]}"
mkdir -p "$REPLAY_LOG_DIR" "$TARGET_LOG_DIR"

exec sleep infinity