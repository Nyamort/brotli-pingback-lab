# Mitigation

The primary fix is a patched Brotli decoder. Everything else is a
compensating control.

---

## 1. Patch the library

| Component | Vulnerable | Fixed |
|---|---|---|
| Google Brotli | 1.0.3 – 1.2.0 | **1.0.10, 1.1.1, 1.2.1** |
| Node.js | 22.x < 22.23.4, 24.x < 24.22.1, 26.x < 26.12.1 | **22.23.4, 24.22.1, 26.12.1** |
| Debian/Ubuntu `libbrotli1` | distro-dependent | install the security update; check `dpkg -s libbrotli1` |
| RHEL/Alma/Rocky | distro-dependent | `dnf update brotli libbrotli` (see RHSA-2026:90449 and related) |
| curl / libcurl | built against an unpatched `libbrotlidec` | rebuild or install the vendor update |
| PHP images | base image with an unpatched lib | rebuild from an updated base |
| nginx/Envoy/Istio | linked against an unpatched lib | vendor update / rebuild |

Check a container:

```bash
docker compose exec wordpress sh -c 'dpkg -s libbrotli1 | grep ^Version'
docker compose exec wordpress php -r \
  'var_dump(curl_version()["brotli_version"]);'
```

A version like `1.1.0-2+b7` may still be vulnerable even though the upstream
version is below 1.1.1; distro revisions are not a reliable signal. The
behavioural test in `make verify` is more useful.

After patching, rebuild every layer that vendors its own copy: Node.js
bundles Brotli statically in official builds; some Python wheels vendor it;
browsers and proxies embed it. A package inventory that only looks at
`libbrotli1` misses those.

---

## 2. WordPress: remove the pingback primitive

Pingback is an unauthenticated outbound fetch. If you do not need it, remove
it.

### Disable XML-RPC entirely

```php
// wp-content/mu-plugins/disable-xmlrpc.php
add_filter( 'xmlrpc_enabled', '__return_false' );
```

And block the endpoint at the edge:

```nginx
location = /xmlrpc.php {
    deny all;
    return 403;
}
```

Some plugins, the WordPress mobile app, and Jetpack use XML-RPC. Test before
disabling.

### Disable only pingback methods

If XML-RPC is required for other methods, remove the pingback methods:

```php
add_filter( 'xmlrpc_methods', function ( $methods ) {
    unset( $methods['pingback.ping'], $methods['pingback.extensions.getPingbacks'] );
    return $methods;
} );
```

### Remove the discovery header

```php
add_filter( 'wp_headers', function ( $headers ) {
    unset( $headers['X-Pingback'] );
    return $headers;
} );
```

This is cosmetic; a determined attacker can still POST to `xmlrpc.php`.

### Egress allowlist

Even with pingback removed, other WordPress features fetch external URLs
(oEmbed, embeds, cron, updates, plugins). Restrict what the web tier can
reach:

```php
define( 'WP_HTTP_BLOCK_EXTERNAL', true );
define( 'WP_ACCESSIBLE_HOSTS', 'api.wordpress.org,downloads.wordpress.org' );
```

`WP_ACCESSIBLE_HOSTS` is a comma-separated list of allowed hosts. This is a
coarse control; it can break embeds and integrations. The stronger control is
a network egress policy or proxy allowlist.

### Do not rely on the 150 KB pingback cap

`limit_response_size => 153600` is a useful limit for classic decompression
bombs, but the crash payload decodes to zero bytes until its tail. It is not
a fix for CVE-2026-111497.

---

## 3. Disable Brotli decoding in the fetch path

If you cannot patch immediately, stop the vulnerable decoder from processing
untrusted `br` bodies.

### PHP / WordPress

Override the cURL encoding for WordPress HTTP requests:

```php
add_action( 'http_api_curl', function ( $handle, $args, $url ) {
    // Only accept gzip/deflate, never br.
    curl_setopt( $handle, CURLOPT_ENCODING, 'gzip, deflate' );
}, 10, 3 );
```

This is a temporary control with trade-offs:

* it disables Brotli for **all** WordPress HTTP requests, including
  legitimate ones;
* a server that still sends `Content-Encoding: br` may make curl return
  `CURLE_BAD_CONTENT_ENCODING`; Requests then retries without decoding and
  WordPress receives the raw compressed body, which usually fails parsing;
* it must be deployed before the vulnerable request, and attackers can use
  other plugins' HTTP clients that do not run this hook.

### Build-time

Build libcurl without Brotli:

```bash
./configure --without-brotli
# or the distro equivalent / CURL_DISABLE_BROTLI
```

Or remove the `libbrotlidec` package from the runtime image. This is drastic
and breaks legitimate `br` traffic, but it removes the attack surface.

### Proxy

At an egress proxy, reject or strip `Content-Encoding: br` from untrusted
responses. **Do not simply strip the header without decoding** — that
corrupts the body. Either:

* reject the response (5xx to the fetcher), or
* decode it in a patched proxy and re-encode as `identity`/`gzip`.

Make sure the proxy itself uses a patched Brotli library; otherwise the
crash simply moves to the proxy.

---

## 4. PHP-FPM and reverse proxy limits

These do not prevent the crash, but they bound the damage and make the
behaviour observable.

```ini
; php-fpm
request_terminate_timeout = 15s
request_slowlog_timeout = 5s
slowlog = /proc/self/fd/2
pm.max_children = 20
pm.max_requests = 500
catch_workers_output = yes
```

* `request_terminate_timeout` kills the 86-byte hang. It does not stop the
  23 MB `SIGSEGV`; the worker is already gone.
* `pm.max_children` limits blast radius but also the number of requests an
  attacker needs to exhaust the pool.
* `pm.max_requests` recycles workers and limits long-lived corruption.
* `catch_workers_output` preserves the signal in the logs.

nginx:

```nginx
fastcgi_read_timeout 30s;
client_max_body_size 8m;
```

Rate-limit `/xmlrpc.php`, cap request/response sizes in the egress proxy, and
alert on 502/504 spikes.

---

## 5. Network controls

* Put the web tier behind an egress proxy with an allowlist. WordPress has
  no legitimate reason to fetch a random VPS or an unapproved relay.
* Block outbound HTTP to IP literals and newly registered domains, if your
  environment allows it.
* Restrict inbound `/xmlrpc.php` to known pingback sources or disable it.
* Do not expose the WordPress container directly to the Internet.

These controls reduce exposure to this chain and to SSRF generally. They are
not a substitute for patching the decoder.

---

## 6. Verification

After applying fixes:

```bash
make verify
```

Expected on a patched stack:

```text
[-] NOT VULNERABLE (or the payload was not decoded): the request returned.
```

or a fast non-zero cURL error (`CURLE_BAD_CONTENT_ENCODING`) instead of a
6-second spin.

Also verify:

```bash
docker compose exec wordpress php -r \
  '$v = curl_version(); echo $v["brotli_version"], "\n";'
```

and confirm the base image digest/tag was actually rebuilt, not just
restarted.

---

## 7. Priority

1. **Patch Brotli and every runtime that embeds it.** This is the only fix
   for the memory-safety bug.
2. **Remove or restrict pingback/XML-RPC.** It is the easiest unauthenticated
   path to the decoder in WordPress.
3. **Restrict egress.** It breaks the attacker's ability to serve the
   payload, and it limits SSRF generally.
4. **Disable `br` decoding in the fetch path** if you cannot patch yet.
5. **Add worker limits and detection.** They do not prevent the crash, but
   they shorten outages and give you evidence.

---

## References

* [CVE-2026-111497 — NVD](https://nvd.nist.gov/vuln/detail/CVE-2026-111497)
* [Red Hat RHSB-2026-015](https://access.redhat.com/security/vulnerabilities/RHSB-2026-015)
* [Brotli 1.2.1 release](https://github.com/google/brotli/releases/tag/v1.2.1)
* [Node.js October 2026 security releases](https://nodejs.org/en/blog/vulnerability/october-2026-security-releases)
* [WordPress XML-RPC documentation](https://developer.wordpress.org/apis/xml-rpc/)
