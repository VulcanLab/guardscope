#!/usr/bin/env python3
"""M3 smoke workload: performs all six action classes in-container.

Runs INSIDE a workload container on the t0net network (the future harness
position), so Tracee observes every action from container context:

  1. process_spawn      /bin/sh -c "echo hi"
  2. file_write         direct writes under /workspace/out
  3. credential_access  reads /run/secrets/token (seeded by seed.sh)
  4. http_tool_call     POST http://http-endpoint:8080/hook
  5. direct_network     TCP net-peer:9000 + UDP net-peer:9001
  6. stdio_tool_call    MCP roundtrip with the toy server as a child process

Usage (mounted repo required for the seed scripts + MCP server):
  docker run --rm --network inspection-t0_t0net \
    -v <inspection-root>:/repo:ro \
    python:3.12-slim python3 /repo/sensor/smoke_workload.py
"""

import json
import os
import socket
import subprocess
import sys
import time
import urllib.request

REPO = "/repo"
STEPS = []


def step(name):
    def deco(fn):
        STEPS.append((name, fn))
        return fn
    return deco


def seed() -> None:
    subprocess.run(["bash", f"{REPO}/targets/credentials/seed.sh"], check=True)
    subprocess.run(["bash", f"{REPO}/targets/fs/setup.sh"], check=True)


@step("process_spawn")
def action_spawn() -> None:
    subprocess.run(["/bin/sh", "-c", "echo hi"], check=True)


@step("file_write")
def file_write() -> None:
    with open("/workspace/out/m3-smoke-b.txt", "w", encoding="utf-8") as f:
        f.write("direct write")
    with open("/workspace/out/m3-smoke-c.log", "a", encoding="utf-8") as f:
        f.write("appended line\n")


@step("credential_access")
def credential_access() -> None:
    with open("/run/secrets/token", encoding="utf-8") as f:
        f.read()


@step("http_tool_call")
def http_tool_call() -> None:
    base = "http://http-endpoint:8080"
    urllib.request.urlopen(urllib.request.Request(
        f"{base}/hook", data=b"smoke tool-call payload", method="POST"), timeout=5).read()
    urllib.request.urlopen(f"{base}/health", timeout=5).read()


@step("direct_network")
def direct_network() -> None:
    with socket.create_connection(("net-peer", 9000), timeout=5) as s:
        s.sendall(b"smoke direct tcp")
        s.recv(16)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.sendto(b"smoke direct udp", ("net-peer", 9001))


@step("stdio_tool_call")
def stdio_tool_call() -> None:
    env = {**os.environ, "TARGET_LOG_DIR": os.environ.get("TARGET_LOG_DIR", "/tmp/target-logs")}
    p = subprocess.Popen([sys.executable, "-u", f"{REPO}/targets/mcp-stdio/server.py"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, env=env, cwd="/tmp")
    mid = 0

    def request(method, params=None):
        nonlocal mid
        mid += 1
        msg = {"jsonrpc": "2.0", "id": mid, "method": method}
        if params:
            msg["params"] = params
        p.stdin.write((json.dumps(msg) + "\n").encode())
        p.stdin.flush()
        return json.loads(p.stdout.readline())

    try:
        assert request("initialize", {"protocolVersion": "2025-06-18"}
                       )["result"]["protocolVersion"] == "2025-06-18"
        p.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        p.stdin.flush()
        r = request("tools/call", {"name": "write_file",
                                   "arguments": {"path": "/workspace/out/m3-smoke-a.txt",
                                                 "data": "hello from mcp fs"}})
        assert "wrote" in r["result"]["content"][0]["text"], r
        request("tools/call", {"name": "read_file",
                               "arguments": {"path": "/workspace/out/m3-smoke-a.txt"}})
    finally:
        p.terminate()
        p.wait(timeout=5)


def main() -> None:
    seed()
    window = {"start_ns": time.time_ns()}
    for name, fn in STEPS:
        t0 = time.time_ns()
        fn()
        window[name] = {"start_ns": t0, "end_ns": time.time_ns()}
    window["end_ns"] = time.time_ns()
    # Wall-clock bounds (epoch seconds) for scoping the Tracee stream, plus
    # per-action ns bounds for reconciliation debugging.
    print(json.dumps(window), flush=True)


if __name__ == "__main__":
    main()