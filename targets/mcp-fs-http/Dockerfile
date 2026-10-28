# MCP-over-HTTP fs tool server (T3): the stdio tool server behind the
# gateway. Build context = ../targets (compose: context ../targets,
# dockerfile mcp-fs-http/Dockerfile). Same tool semantics and served-log
# target name ("toy-mcp-fs") as targets/mcp-stdio/server.py — see server.py.
FROM python:3.12-slim
COPY common.py /app/common.py
COPY mcp-fs-http/server.py /app/server.py
ENV TARGET_LOG_DIR=/var/log/targets FS_WORKSPACE=/workspace
VOLUME /workspace
CMD ["python3", "-u", "/app/server.py"]
