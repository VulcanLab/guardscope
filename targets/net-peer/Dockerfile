# Build with `targets/` as the context (compose sets context: .., dockerfile: ...):
#   docker build -t inspection/net-peer -f net-peer/Dockerfile .
FROM python:3.12-slim

COPY common.py net-peer/server.py /app/
WORKDIR /app
CMD ["python3", "-u", "server.py"]