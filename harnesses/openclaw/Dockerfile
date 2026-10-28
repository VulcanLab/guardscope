# OpenClaw harness container (C3, M4): gateway + inspection replay adapter.
# Build context = experiments/mediation/ (compose sets context/dockerfile).
#
# The plugin is installed at build time; the toy MCP server and seed scripts
# are baked into /opt/inspection. typebox is vendored from the image's pnpm
# store (cp -rL) so the adapter needs no network at build or runtime.
# Digest = ghcr.io/openclaw/openclaw:2026.9.3 (validated in the M4 smoke); also
# recorded in ../env/versions.env as OPENCLAW_IMAGE_DIGEST.
FROM ghcr.io/openclaw/openclaw@sha256:6cb72e1599b3b76e2ea3dcc2f4dd7f112247367fbecadfcdee8caa7423f4989b

USER root
COPY targets/common.py /opt/inspection/mcp-fs/common.py
COPY targets/mcp-stdio/server.py /opt/inspection/mcp-fs/server.py
# T4/T5: the http tool calls execute through the http-stdio server (direct in
# T4; MCP_GATEWAY_URL-forwarded in T5) — baked like the fs server.
COPY targets/common.py /opt/inspection/mcp-http-stdio/common.py
COPY targets/mcp-http-stdio/server.py /opt/inspection/mcp-http-stdio/server.py
COPY targets/credentials/seed.sh /opt/inspection/seed-credentials.sh
COPY targets/fs/setup.sh /opt/inspection/setup-fs.sh
RUN chmod +x /opt/inspection/*.sh

# Install the replay adapter plugin (typebox vendored from the image so the
# plugin resolves it without npm/network access).
COPY harnesses/openclaw/adapter /opt/inspection-replay
RUN mkdir -p /opt/inspection-replay/node_modules \
 && cp -rL /app/node_modules/typebox /opt/inspection-replay/node_modules/ \
 && chown -R node:node /opt/inspection-replay /opt/inspection

# Bake the harness gateway config BEFORE `plugins install` (which registers
# the plugin in this same config file).
COPY harnesses/openclaw/config/openclaw.json /home/node/.openclaw/openclaw.json
RUN chown node:node /home/node/.openclaw/openclaw.json

USER node
RUN openclaw plugins install /opt/inspection-replay --force --accept-capabilities

USER root
COPY harnesses/openclaw/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]