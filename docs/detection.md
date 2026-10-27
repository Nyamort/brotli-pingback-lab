# Detection

There is no single log line that proves CVE-2026-111497 exploitation. The
signal is a **combination** of an XML-RPC pingback, an outbound HTTP fetch to
an unusual host, and a PHP worker that dies or stops making progress while
decoding Brotli.

---

## 1. PHP-FPM

The most direct signal is a worker exit:

```text
WARNING: [pool www] child 42 exited on signal 11 (SIGSEGV) after 1.2 seconds from start
```

or, for the 86-byte hang:

```text
WARNING: [pool www] child 43 execution timed out (15.0 sec), terminating
WARNING: [pool www] child 43 exited on signal 15 (SIGTERM) after 15.1 seconds from start
```

Enable worker output capture:

```ini
catch_workers_output = yes
request_terminate_timeout = 15s
request_slowlog_timeout = 5s
slowlog = /proc/self/fd/2
```

Alert on:

* `exited on signal 11` / `SIGSEGV` in the PHP-FPM pool;
* `execution timed out` followed by `SIGTERM`/`SIGKILL`;
* a spike in worker respawns (`child ... exited on signal ...`) without a
  deploy or OOM event;
* `request_slowlog_timeout` entries pointing at `xmlrpc.php`.

A single `SIGSEGV` is not normal. On a PHP-FPM host it deserves an
investigation even if the site recovered.

---

## 2. nginx / reverse proxy

Look for `/xmlrpc.php` requests that end in 502/504 and take several seconds:

```text
203.0.113.10 - - [27/Oct/2026:12:00:01 +0000] "POST /xmlrpc.php HTTP/1.1" 502 157 "-" "WordPress/6.x; https://victim.example; verifying pingback from 203.0.113.10"
```

Useful log fields:

```nginx
log_format lab '$remote_addr - $request_time $status '
               '$upstream_status $upstream_response_time '
               '"$request" "$http_user_agent"';
access_log /var/log/nginx/access.log lab;
```

Alert on:

* `POST /xmlrpc.php` with `502`/`504` and `$request_time >= 5`;
* repeated `/xmlrpc.php` POSTs from the same source in a short window;
* `upstream timed out` in the error log while the upstream is a PHP-FPM
  pool, not a generic backend.

Rate-limit `/xmlrpc.php` at the edge; legitimate pingback traffic is low
volume.

---

## 3. WordPress

With `WP_DEBUG` and `WP_DEBUG_LOG` enabled:

```php
define( 'WP_DEBUG', true );
define( 'WP_DEBUG_LOG', true );
define( 'WP_DEBUG_DISPLAY', false );
```

Relevant signals:

* `wp_remote_get` / `WP_Error` entries for an external URL immediately
  before a worker death;
* the `xmlrpc_call` action firing for `pingback.ping` (log it in a
  must-use plugin during an investigation);
* an unusually large outbound response (23 MB) or a very long HTTP request.

The `xmlrpc_call` hook receives the method name and arguments:

```php
add_action( 'xmlrpc_call', function ( $method, $args ) {
    if ( 'pingback.ping' === $method ) {
        error_log( sprintf(
            'pingback source=%s target=%s ip=%s',
            $args[0] ?? '',
            $args[1] ?? '',
            $_SERVER['REMOTE_ADDR'] ?? ''
        ) );
    }
}, 10, 2 );
```

This is high-volume only on sites that legitimately use pingbacks; sample or
aggregate if needed.

---

## 4. Network / egress

The exploit requires the web tier to make an outbound HTTP(S) request to an
attacker-controlled host. If you have an egress proxy, firewall, or DNS
logging, alert on:

* `POST /xmlrpc.php` followed by an outbound `GET` to a host never seen
  before (especially a short-lived or newly registered domain);
* outbound HTTP responses with `Content-Encoding: br` and a body that
  decompresses to nothing or to a very small output;
* a 20+ MB outbound response to the web tier;
* PHP-FPM worker deaths correlated with the same destination.

An allowlist is more effective than a blocklist: WordPress should only reach
the payment, mail, update, and CDN endpoints it actually needs.

---

## 5. Metrics

| Metric | Why |
|---|---|
| `php_fpm_workers_active` | pinned at `pm.max_children` during a hang |
| `php_fpm_workers_idle` | drops to zero |
| `php_fpm_slow_requests` | climbs without a traffic spike |
| `process_cpu_seconds_total{service="php-fpm"}` | one or more cores at 100% |
| `nginx_http_requests_total{status="502"}` | worker kills |
| `container_restart_count` | php-fpm master restarts |
| `node_processes_state{state="zombie"}` | reaping problems after crashes |

A worker that is stuck in a C loop shows high CPU and **no** PHP-level
request log completion. A worker that segfaults shows a restart/respawn
without a PHP fatal error.

---

## 6. WAF and egress rules

Rules that help:

* rate-limit or challenge `POST /xmlrpc.php`;
* block `pingback.ping` from sources that are not known pingback peers;
* reject outbound `Content-Encoding: br` from hosts outside an allowlist
  (at the egress proxy, not at the inbound WAF);
* cap outbound response size for web-tier fetches (e.g. 1 MB) — the 23 MB
  trigger exceeds it, while the 86-byte hang does not;
* block requests to unapproved relay domains from the web tier unless
  explicitly required.

Do **not** rely on a rule that only inspects the decoded body size. The
crash payload decodes to zero bytes until the final tail; a WAF that
buffers/decompresses the response may itself be exposed to the same library
bug. Patch the inspecting proxy too.

---

## 7. Host-level signals

On Linux:

```bash
dmesg -T | grep -i -E 'segfault|traps'
journalctl -k | grep -i segfault
coredumpctl list
```

A PHP-FPM worker segfault produces a kernel line similar to:

```text
php-fpm[1234]: segfault at 0 ip 00007f... sp 00007ff... error 6 in libbrotlidec.so.1.1.0[...]
```

The `libbrotlidec` frame is a strong indicator. Correlate the timestamp with
`/xmlrpc.php` access logs.

---

## 8. False positives

* PHP extensions with their own memory bugs can segfault; check the faulting
  library.
* OOM kills produce signal 9, and `request_terminate_timeout` may produce
  signal 15 (SIGTERM) or 9 (SIGKILL); distinguish
  by the log message and the container memory metrics.
* A slow `xmlrpc.php` request can be a legitimate large pingback; the
  outbound destination and the response size are the differentiators.
* `SIGSEGV` in a worker during a deploy may be a bad extension build; compare
  with the deployment timeline.

The strongest correlation is:

```text
POST /xmlrpc.php (pingback.ping)
  + outbound GET to an unusual host
  + worker SIGSEGV in libbrotlidec
  + immediate 502 on the same request
```
