# plugins/agentgateway/collector/Dockerfile — the binding's decision-stream
# collector (control-agentgateway-trace, the auxiliary service of the t1
# overlays). Base image pinned by index digest (python:3.12-alpine,
# re-verified 2026-11-10; see plugins/agentgateway/versions.env).
FROM python:3.12-alpine@sha256:e064671ca452259bab50e8e2c7bd896e39e9a343bb06ca25234adf6fe18d0fc7
COPY plugins/agentgateway/collector/capture.py /capture.py
ENTRYPOINT ["python3", "/capture.py"]
