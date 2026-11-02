# Pi harness container (C3, M5): pi coding agent + inspection replay adapter.
# Build context = experiments/mediation/ (compose sets context/dockerfile).
#
# Base image and pi package are pinned (see ../env/versions.env PI_* entries).
# No official pi image exists; the node:24-bookworm-slim + npm pattern is the
# one documented in pi's containerization.md. python3 is added for the toy MCP
# stdio server. The adapter (TypeScript) is loaded per run by the driver via
# pi -e — no build/transpile step (pi loads TS through jiti).
# Digest = node:24-bookworm-slim (linux/arm64, pulled 2026-09-10).
FROM node@sha256:2fe369e969550cde8e867afc3fe370b260140cab4a23d467074295b42163d553

RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates git ripgrep python3 \
 && rm -rf /var/lib/apt/lists/*

# Pin the pi package version; --ignore-scripts per the documented Docker pattern.
# 1.0.4 (T4): ctx-level tool pipeline for harness-native enforcement — the
# scripted provider registers via pi.registerProvider and the tool calls
# cross pi's tool_call permission chain. The adapter imports
# @earendil-works/pi-ai/compat at runtime; pi-ai is nested inside pi's
# global install, so a link into the adapter's resolution path is added below.
RUN npm install -g --ignore-scripts @earendil-works/pi-coding-agent@1.0.4 \
 && pi --version \
 && mkdir -p /opt/inspection/node_modules/@earendil-works \
 && ln -s /usr/lib/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-ai \
          /opt/inspection/node_modules/@earendil-works/pi-ai

# Toy MCP stdio servers + seed scripts (same in-harness targets as OpenClaw;
# the http-stdio server serves the http_tool_call tools as MCP tools in T4).
COPY targets/common.py /opt/inspection/mcp-fs/common.py
COPY targets/mcp-stdio/server.py /opt/inspection/mcp-fs/server.py
COPY targets/mcp-http-stdio/server.py /opt/inspection/mcp-http-stdio/server.py
COPY targets/common.py /opt/inspection/mcp-http-stdio/common.py
# The F3 delegation fixture's target-side addition (an agent hiding inside a
# local tool): a SIBLING server, additive — the toy-mcp-fs server above is
# untouched and the existing baseline runs never spawn this one. The
# replay adapter opens it only for the F3 fixture's tool-agent-performed
# actions (F3_SERVER_CMD env, default below).
COPY targets/mcp-agent/server.py /opt/inspection/mcp-agent/server.py
COPY targets/credentials/seed.sh /opt/inspection/seed-credentials.sh
COPY targets/fs/setup.sh /opt/inspection/setup-fs.sh
RUN chmod +x /opt/inspection/*.sh

# Replay adapter: loaded by the driver with pi -e /opt/inspection/adapter/replay.ts
COPY harnesses/pi/adapter /opt/inspection/adapter

# F2 delegation fixture: the child program the adapter spawns for the
# child-performed actions (trace/traces/baseline-f2*.yaml). Same python3 as
# the toy MCP server; no new packages.
COPY harnesses/pi/f2-helper.py /opt/inspection/f2-helper.py

COPY harnesses/pi/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
# The container stays up; the driver execs one pi RPC process per replay run
# (docker exec -i t0-pi pi --mode rpc --no-session -e /opt/inspection/adapter/replay.ts),
# so Tracee's window is exactly the pi process lifetime.
ENTRYPOINT ["/entrypoint.sh"]