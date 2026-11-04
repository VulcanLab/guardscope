# Build with `targets/` as the context (compose sets context: .., dockerfile: ...):
#   docker build -t inspection/mcp-agent-http -f mcp-agent/Dockerfile .
# The F4 delegation fixture's REMOTE tool server: runs on the EXECUTOR host
# of the two-host topology (compose/executor.yaml), not in the harness
# container — the hand-off crosses the network to reach it.
FROM python:3.12-slim

COPY mcp-agent/server.py mcp-agent/http-server.py /app/
WORKDIR /app
ENV F4_LISTEN_PORT=8091
EXPOSE 8091
CMD ["python3", "-u", "http-server.py"]
