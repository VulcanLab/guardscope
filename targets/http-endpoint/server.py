#!/usr/bin/env python3
"""Logging HTTP endpoint (C4): the http_tool_call target.

Accepts the operations the baseline trace exercises (POST /hook, GET /health,
PUT /state) and logs one JSON line per request to stdout and the shared
target-logs volume. Dependency-free (stdlib only).
"""

import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from common import log_event

TARGET = "http-endpoint"
PORT = int(os.environ.get("HTTP_PORT", "8080"))
# Paths the endpoint serves; anything else gets 404 (logged all the same).
KNOWN_PATHS = {"/hook", "/health", "/state"}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _serve(self) -> None:
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        log_event(TARGET, "request", method=self.command, path=self.path,
                  body_bytes=length, body_text=body.decode("utf-8", "replace"),
                  peer=str(self.client_address[0]))
        if self.path not in KNOWN_PATHS:
            self._respond(404, b'{"error": "not found"}')
            return
        if self.path == "/health" and self.command == "GET":
            self._respond(200, b'{"status": "ok"}')
            return
        if self.command in ("POST", "PUT"):
            self._respond(200, b'{"accepted": true}')
            return
        self._respond(405, b'{"error": "method not allowed"}')

    def _respond(self, code: int, payload: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = _serve

    def log_message(self, fmt, *args):  # silence default stderr access log
        pass


if __name__ == "__main__":
    log_event(TARGET, "start", port=PORT, known_paths=sorted(KNOWN_PATHS))
    ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()