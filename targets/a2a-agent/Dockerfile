# Build with `targets/` as the context (compose sets context: .., dockerfile: ...):
#   docker build -t inspection/a2a-agent -f a2a-agent/Dockerfile .
# The F5 delegation fixture's REMOTE agent server: runs on the EXECUTOR host
# of the two-host topology (compose/executor.yaml), not in the harness
# container — the hand-off crosses the network to reach it.
FROM python:3.12-slim

COPY a2a-agent/server.py /app/
WORKDIR /app
ENV A2A_LISTEN_PORT=8092
EXPOSE 8092
CMD ["python3", "-u", "server.py"]
