# brotli-pingback-lab

A reproducible Docker lab for **CVE-2026-111497** (out-of-bounds write in the
Google Brotli decoder) reached through **WordPress XML-RPC pingback**.

One unauthenticated `pingback.ping` call makes WordPress fetch an attacker
URL. WordPress hands the response to libcurl, libcurl decodes
`Content-Encoding: br` inside the PHP worker, and a malformed Brotli stream
kills the worker:

* **86-byte payload** — non-progressing decoder loop, worker pinned at 100% CPU
  until php-fpm kills it (`SIGTERM`, then `SIGKILL` if needed) (worker starvation).
* **~23 MB payload** — out-of-bounds write in `BrotliDecoderState`, worker dies
  with **SIGSEGV** (signal 11).

The repo ships the lab, the payload server, the pingback PoC, and the
write-up. It deliberately stops at denial of service / worker crash. **It does
not contain an RCE exploit.**

> **Authorized lab use only.** The PoC refuses targets that resolve to public
> IPs unless `--i-own-this-target` is supplied. Do not point it at systems you
> do not own or have written permission to test.

---

## TL;DR

```bash
git clone <this-repo> brotli-pingback-lab
cd brotli-pingback-lab
cp .env.example .env

make up          # build + start WordPress, MariaDB, nginx, payload server
make probe       # confirm xmlrpc.php and pingback.ping
make verify      # confirm the PHP/libcurl/Brotli stack is vulnerable

make hang        # 86-byte payload: workers hang, php-fpm kills them
make crash       # 23 MB payload: workers die with SIGSEGV
```

`make crash` expects log lines such as:

```text
WARNING: [pool www] child 42 exited on signal 11 (SIGSEGV) after 1.2 seconds from start
```

`make hang` expects:

```text
WARNING: [pool www] child 43 execution timed out (15.0 sec), terminating
WARNING: [pool www] child 43 exited on signal 15 (SIGTERM) after 15.1 seconds from start
```

---

## Architecture

```text
                    +---------------------------------------------+
                    |  Docker network: brotli-pingback-lab        |
                    |                                             |
  PoC (host)        |   +-----------+        +----------------+  |
  python3  ---------+-->|  nginx    |------->|  wordpress     |  |
  pingback.ping     |   |  :8080    |  fastcgi|  php8.3-fpm    |  |
  sourceURI=...     |   +-----------+        |  libbrotli 1.1 |  |
                    |                        +--------+-------+  |
                    |                                 |          |
                    |                     wp_safe_remote_get     |
                    |                     (Content-Encoding: br)  |
                    |                                 v          |
                    |                        +----------------+  |
                    |                        |  attacker      |  |
                    |                        |  payload srv   |  |
                    |                        |  86 B / 23 MB  |  |
                    |                        +----------------+  |
                    +---------------------------------------------+

  Optional: cloudflared --url http://attacker:8080
            -> https://<random>.trycloudflare.com
            (Quick Tunnel, no account; NOTE: it decodes br at the edge,
             so use the local attacker URL for the crash/hang)
```

The WordPress site is exposed on `http://localhost:8080`. The payload server
is exposed on `http://localhost:8081` for debugging. In tunnel mode, only the
payload server is published to the Internet.

---

## The vulnerability in 60 seconds

Brotli metablocks use three block categories: literals, insert/copy commands,
and distances. Each category has a set of block types and a block length.
When a block length reaches zero, the decoder reads a **block switch**.

In `c/dec/decode.c`, `DecodeBlockTypeAndLength()` returned `BROTLI_FALSE`
when `num_block_types <= 1`, i.e. when the stream asked for a block switch
that its own structure made impossible. The callers used `BROTLI_SAFE()`,
which treated that `FALSE` as “needs more input” (and, on the fast path,
ignored the return value). Decoding continued with an invalid internal state.

The upstream fix (commit `0ed4268a4401abcb44720963`, “Detect and report
invalid stream earlier”) introduces
`BROTLI_DECODER_ERROR_FORMAT_BLOCK_SWITCH` and propagates it through a new
`BROTLI_SAFE_WITH_STATUS()` macro, so the invalid transition is a format
error instead of undefined behaviour.

| | |
|---|---|
| CVE | [CVE-2026-111497](https://nvd.nist.gov/vuln/detail/CVE-2026-111497) |
| Type | CWE-787 out-of-bounds write, CWE-252 unchecked return value |
| Severity | 9.2 Critical (CVSS 4.0), AV:N/AC:L/PR:N/UI:N |
| Affected | Google Brotli 1.0.3 – 1.2.0 |
| Fixed | Brotli 1.0.10, 1.1.1, 1.2.1 |
| Runtime fixes | Node.js 22.23.4, 24.22.1, 26.12.1; rebuilt curl/PHP images |
| Public names | Node2Shell, HTTP2Shell |

The flaw is in the **library**, not in WordPress. Any HTTP client that
auto-decodes `Content-Encoding: br` from an untrusted peer is a potential
sink. WordPress pingback happens to be a very convenient unauthenticated
way to make a PHP process do exactly that.

More: [`docs/vulnerability.md`](docs/vulnerability.md).

---

## The WordPress chain

`wp-includes/class-wp-xmlrpc-server.php`, `pingback_ping()`:

```php
$http_api_args = array(
    'timeout'             => 10,
    'redirection'         => 0,
    'limit_response_size' => 153600, // 150 KB
    'user-agent'          => "$user_agent; verifying pingback from $remote_ip",
    ...
);
$request       = wp_safe_remote_get( $pagelinkedfrom, $http_api_args );
$remote_source = wp_remote_retrieve_body( $request );
```

1. An unauthenticated attacker POSTs `pingback.ping` to `/xmlrpc.php` with
   `sourceURI = https://attacker.example/payload.br` and
   `targetURI = https://victim.example/?p=1`.
2. WordPress validates the target, sleeps one second, then fetches the
   source URL with `wp_safe_remote_get()`.
3. WordPress's bundled Requests library uses the cURL transport. It sets
   `CURLOPT_ENCODING = ''` (`wp-includes/Requests/src/Transport/Curl.php`),
   which enables every compression encoding libcurl was built with —
   including `br` when libcurl links `libbrotlidec`.
4. libcurl sees `Content-Encoding: br` and decodes the body **inside the PHP
   worker**, before WordPress ever looks at the HTML.
5. The malformed stream triggers the decoder bug:
   * small payload → decoder makes no progress → libcurl's
     `brotli_do_write()` loop spins;
   * large payload → decoder state corruption → out-of-bounds write →
     `SIGSEGV`.

### Wait — doesn't pingback cap the response at 150 KB?

Yes, and this is the interesting part. `limit_response_size => 153600` is
mapped by WordPress to Requests' `max_bytes`
(`wp-includes/class-wp-http.php`). The cURL transport enforces it in
`stream_body()` — on **decompressed** chunks:

```php
if ( ($this->response_bytes + $data_length) > $this->response_byte_limit ) {
    $data = substr( $data, 0, $this->response_byte_limit - $this->response_bytes );
}
// ...
$this->response_bytes += strlen( $data );
return $data_length;   // note: original length, so curl does not abort
```

The 23 MB trigger produces **zero decoded bytes** until its final 127-byte
tail. The 150 KB budget is therefore untouched, and because `stream_body()`
returns the original length, curl keeps downloading and decoding. The cap
protects against classic decompression bombs (large output); it does not
protect against a zero-output memory-corruption trigger.

The 86-byte payload is obviously far below the cap. It produces no output at
all; the worker simply never returns.

More: [`docs/attack-chain.md`](docs/attack-chain.md).

---

## What the lab demonstrates

| Mode | Payload | Result | Detection |
|---|---|---|---|
| `hang` | 86 B | libcurl/Brotli decode loop never progresses; PHP worker at 100% CPU; php-fpm kills it after `request_terminate_timeout` | `execution timed out`, `SIGTERM`, 100% CPU, 502s |
| `crash` | ~23 MB | out-of-bounds write in `BrotliDecoderState`; PHP worker dies | `exited on signal 11 (SIGSEGV)`, 502 |
| `probe` | — | confirms `xmlrpc.php` and `pingback.ping` exposure | — |

With `pm.max_children = 4`, four concurrent pingbacks are enough to take the
whole pool down. The PoC sends four by default.

---

## Why no RCE?

The public research shows code execution in Node.js with deterministic heap
layout (ASLR disabled / `--predictable`). The write primitive is relative to
the Brotli ring buffer; blind remote exploitation needs an information leak
or a predictable wrap compensation. Public analyses explicitly stop at
“remote blind RCE not established” for the generic case.

This lab intentionally does not implement heap grooming, pointer leaks, or a
`free_func` hijack. The crash tail sets `pos` to a wild negative value so the
16-byte ring copy faults immediately. That is enough to prove the PHP worker
is reachable and killable through pingback, without shipping an exploit.

See [`docs/vulnerability.md`](docs/vulnerability.md#why-this-lab-stops-at-a-crash)
for the details.

---

## Repository layout

```text
.
├── docker-compose.yml           # WordPress + MariaDB + nginx + attacker (+ tunnel)
├── Makefile                     # one-command lab workflow
├── docs/
│   ├── vulnerability.md         # CVE, root cause, affected versions
│   ├── attack-chain.md          # WordPress pingback -> libcurl -> Brotli
│   ├── lab.md                   # setup, services, troubleshooting
│   ├── poc.md                   # PoC usage and expected output
│   ├── cloudflare.md            # try.cloudflare.com Quick Tunnel
│   ├── detection.md             # logs, metrics, WAF/egress rules
│   └── mitigation.md            # patching and compensating controls
├── lab/
│   ├── attacker/                # payload generator + HTTP server
│   ├── nginx/                   # reverse proxy
│   ├── php-fpm/                 # worker limits + timeout
│   └── wordpress/mu-plugins/    # lab-only `attacker` SSRF allowlist
├── poc/pingback_poc.py          # probe / hang / crash client
└── scripts/                     # vulnerability verification
```

---

## Requirements

* Docker Engine 24+ with Compose v2
* Python 3.10+ (PoC and payload generator; standard library only)
* ~1.5 GB disk for images, ~200 MB RAM for the lab
* Optional: outbound Internet for the Cloudflare Quick Tunnel

Tested on Linux x86-64. The crash tail depends on the x86-64
`BrotliDecoderState` layout of Brotli 1.1.0/1.2.0; the pinned WordPress
image supplies exactly that.

---

## Cloudflare Quick Tunnel

The payload server can be published with `try.cloudflare.com` (Quick Tunnel,
no account):

```bash
make tunnel          # starts cloudflared and prints the URL
make tunnel-url      # prints it again later
```

The tunnel exposes **only the payload server**, never the WordPress site.

> **Lab finding: Quick Tunnel decodes `Content-Encoding: br` at the edge.**
> In our tests, `/small.br` (86 B) arrived as **16 MiB of `A`** (its decoded
> body) and `/payload.br` (23 MB) arrived as **0 bytes**. The malicious Brotli
> stream never reaches WordPress, so the pingback does not crash or hang
> through a Quick Tunnel. `no-transform`, `Content-Disposition: attachment`,
> and `Accept-Encoding: br` did not change this.
>
> This is a real CDN-level mitigation and a useful result, but it means the
> tunnel is not a delivery path for the exploit. Use the local
> `http://attacker:8080` URL for `make hang` / `make crash`. If you need a
> public relay that preserves bytes, use a VPS with a public IP or a raw TCP
> tunnel you control, and verify with:
>
> ```bash
> curl --raw -H 'Accept-Encoding: br' -o /tmp/x.br \
>   -w '%{size_download}\n' https://your-relay/small.br
> # must print 86, and xxd must start with 20 00 10 41
> ```

The tunnel remains useful for demonstrating the public-URL/SSRF path and for
testing egress detections. The full details, including the observed sizes and
workarounds, are in [`docs/cloudflare.md`](docs/cloudflare.md).

---

## Docs

* [Vulnerability](docs/vulnerability.md) — CVE-2026-111497, root cause, patch
* [Attack chain](docs/attack-chain.md) — pingback → `wp_safe_remote_get` → libcurl → Brotli
* [Lab](docs/lab.md) — services, setup, troubleshooting
* [PoC](docs/poc.md) — modes, options, expected results
* [Cloudflare](docs/cloudflare.md) — Quick Tunnel walkthrough
* [Detection](docs/detection.md) — what to log and alert on
* [Mitigation](docs/mitigation.md) — patch first, then compensating controls

---

## Ethics and scope

This project is for defenders, students, and vulnerability researchers. It
was built to make a runtime-level bug visible in a realistic web stack, not
to provide a weapon.

* The PoC is rate-limited to 32 requests and refuses public targets by default.
* The payload is crash-only; there is no RCE chain.
* The lab's WordPress image is the official image plus a 10-line mu-plugin
  that allowlists the Docker-internal `attacker` hostname. Remove it in
  a public-payload mode if you want a completely stock install.
* Do not expose the WordPress container to the Internet. The payload server is
  the only service meant to be published.

See [SECURITY.md](SECURITY.md).

---

## Credits

* Google Brotli maintainers and the CVE-2026-111497 reporters
  (OpenAI Codex Security — Khai Tran and Sylvie Mayer).
* Node.js security team; the 22-byte regression input is from
  `test/parallel/test-zlib-invalid-input.js`.
* Imperva Red Team (“Node2Shell”), Red Hat (`RHSB-2026-015`), Akamai, Wiz,
  and the other public analyses.
* `TheFool-TAROT/CVE-2026-111497-brotli-pwn` and
  `dimasma0305/CVE-2026-111497-POC` for public stream-format research.
* WordPress and curl maintainers, whose source made the chain easy to follow.

## License

MIT — see [LICENSE](LICENSE).
