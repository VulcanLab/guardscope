# Build with `targets/` as the context (compose sets context: .., dockerfile: ...):
#   docker build -t inspection/mcp-http -f mcp-http/Dockerfile .
FROM python:3.12-slim

COPY common.py mcp-http/server.py /app/
WORKDIR /app
CMD ["python3", "-u", "server.py"]
