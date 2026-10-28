#!/usr/bin/env bash
# Set up the workspace paths (C4) that file_write and stdio fs-tool actions
# target (/workspace/out per the baseline trace).
#
# Runs in the harness container entrypoint (M4/M5).
# Override the destination with WORKSPACE_DIR (default /workspace).
set -euo pipefail

WORKSPACE_DIR="${WORKSPACE_DIR:-/workspace}"

mkdir -p "$WORKSPACE_DIR/out"
echo "fs: workspace ready at $WORKSPACE_DIR/out"