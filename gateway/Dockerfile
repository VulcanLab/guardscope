# T1 gateway service: AGT MCP Security Gateway (microsoft/agent-governance-toolkit).
#
# The enforcement engine is the published agent-os-kernel package (pinned in
# env/versions.env); this container adds only the HTTP/JSON-RPC glue in
# gateway/server.py. Built from experiments/mediation/ as context:
#   docker build -t inspection/gateway -f gateway/Dockerfile .
FROM python:3.12-slim

RUN pip install --no-cache-dir agent-os-kernel==3.7.0 pyyaml==6.0.2

COPY gateway/server.py gateway/policy.yaml gateway/policy-t3.yaml /opt/inspection/gateway/
WORKDIR /opt/inspection/gateway
ENV GATEWAY_POLICY=/opt/inspection/gateway/policy.yaml
CMD ["python3", "-u", "server.py"]
