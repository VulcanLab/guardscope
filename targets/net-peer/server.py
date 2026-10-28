#!/usr/bin/env python3
"""Network peer (C4): the direct_network target.

Listens on TCP :9000 and UDP :9001 (the ports the baseline trace's
tcp_connect / udp_send actions hit) and logs one JSON line per received
connection/datagram. Dependency-free (stdlib only).
"""

import os
import socket
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import log_event

TARGET = "net-peer"
TCP_PORT = int(os.environ.get("NET_TCP_PORT", "9000"))
UDP_PORT = int(os.environ.get("NET_UDP_PORT", "9001"))


def log_recv(transport: str, data: bytes, peer: tuple) -> None:
    log_event(TARGET, "received", transport=transport,
              peer=f"{peer[0]}:{peer[1]}", data_bytes=len(data),
              payload=data.decode("utf-8", "replace"))


def tcp_loop() -> None:
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", TCP_PORT))
    srv.listen(16)
    log_event(TARGET, "start", transport="tcp", port=TCP_PORT)
    while True:
        conn, peer = srv.accept()
        with conn:
            data = conn.recv(65536)
            if data:
                log_recv("tcp", data, peer)
            conn.sendall(b"ack\n")


def udp_loop() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", UDP_PORT))
    log_event(TARGET, "start", transport="udp", port=UDP_PORT)
    while True:
        data, peer = sock.recvfrom(65536)
        log_recv("udp", data, peer)


if __name__ == "__main__":
    threads = [threading.Thread(target=tcp_loop, daemon=True),
               threading.Thread(target=udp_loop, daemon=True)]
    for t in threads:
        t.start()
    try:
        while True:
            threading.Event().wait(3600)
    except KeyboardInterrupt:
        pass