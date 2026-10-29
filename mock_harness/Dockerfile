# Mock harness container (the path-originator fixture; DESIGN.md 8): a plain
# python runtime the runner docker-execs the driver into (the same pattern as
# the pi harness service — the container idles, the driver runs per run).
#
# No repo files are baked in: compose mounts the repo read-only at /repo and
# the driver runs `python3 -m mock_harness.driver` with cwd /repo. The image
# only pins the runtime + the two core deps the driver and the trace tooling
# need (already core dependencies; no new ones).
#
# Version resolution (pinned 2026-10-29):
#   - base image: python:3.12-slim-bookworm — the runtime the toy MCP stdio
#     server and the trace tooling are validated on (targets/mcp-stdio runs
#     under python3.12 in the pi/openclaw harness containers).
#   - PyYAML==6.0.3, jsonschema==4.26.0 — the versions the repo's pinned
#     environment resolves today (requirements-dev.txt floors are
#     PyYAML>=6.0, jsonschema>=4.20); bump deliberately, the run manifest's
#     pinned block records what actually ran.
FROM python:3.12-slim-bookworm

RUN pip install --no-cache-dir \
      PyYAML==6.0.3 \
      jsonschema==4.26.0

WORKDIR /workspace
