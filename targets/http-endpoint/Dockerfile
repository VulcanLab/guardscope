# Build with `targets/` as the context (compose sets context: .., dockerfile: ...):
#   docker build -t inspection/http-endpoint -f http-endpoint/Dockerfile .
FROM python:3.12-slim

COPY common.py http-endpoint/server.py /app/
WORKDIR /app
CMD ["python3", "-u", "server.py"]