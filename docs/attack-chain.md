# Attack chain: WordPress pingback → libcurl → Brotli

This document follows the exact code path used by the lab. Line numbers are
from WordPress trunk at the time of writing; older releases are similar.

---

## 1. Pingback is an unauthenticated fetch primitive

`xmlrpc.php` exposes the XML-RPC `pingback.ping` method by default. The
handler is `wp-includes/class-wp-xmlrpc-server.php::pingback_ping()`.

```php
public function pingback_ping( $args ) {
    ...
    $pagelinkedfrom = str_replace( '&amp;', '&', $args[0] ); // sourceURI
    $pagelinkedto   = str_replace( '&amp;', '&', $args[1] ); // targetURI
    ...
    // The target must be a post on this site with pings open.
    ...
    sleep( 1 );

    $http_api_args = array(
        'timeout'             => 10,
        'redirection'         => 0,
        'limit_response_size' => 153600, // 150 KB
        'user-agent'          => "$user_agent; verifying pingback from $remote_ip",
        'headers'             => array(
            'X-Pingback-Forwarded-For' => $remote_ip,
        ),
    );

    $request       = wp_safe_remote_get( $pagelinkedfrom, $http_api_args );
    $remote_source = wp_remote_retrieve_body( $request );
```

The source URL is fetched **before** WordPress checks whether it contains a
link back to the target post. That check happens later:

```php
preg_match( '|<title>([^<]*?)</title>|is', $remote_source, $matchtitle );
...
foreach ( $p as $para ) {
    if ( str_contains( $para, $pagelinkedto ) ) { ... }
}
```

So the attacker does not need a valid HTML page, a `<title>`, or a link. The
worker only has to reach the fetch and decode the body. If the decoder
crashes, the function never returns to the link check.

### Requirements for a pingback

| Requirement | Lab default |
|---|---|
| `xmlrpc.php` reachable | yes (WordPress default) |
| `pingback.ping` enabled | yes (WordPress default) |
| Target URL maps to a post | `/?p=1` (Hello World) |
| Pings open on that post | yes (default `open`) |
| Source URL fetchable by WordPress | `http://attacker:8080/...` locally, or a byte-preserving public relay |
| Source not already registered | PoC adds a unique `?cb=` parameter |

`redirection => 0` means WordPress will not follow a redirect to the payload;
the source URL itself must serve the bytes.

---

## 2. `wp_safe_remote_get()` and SSRF filtering

`wp_safe_remote_get()` sets `reject_unsafe_urls => true`. Before the request,
`wp_http_validate_url()` resolves the hostname and rejects private, loopback,
link-local, CGNAT, multicast, and other special ranges unless the
`http_request_host_is_external` filter says otherwise:

```php
if ( 127 === $parts[0] || 10 === $parts[0] || 0 === $parts[0]
    || ( 172 === $parts[0] && 16 <= $parts[1] && 31 >= $parts[1] )
    || ( 192 === $parts[0] && 168 === $parts[1] )
    ...
) {
    // reject unless http_request_host_is_external allows it
}
```

This is why a public URL is the natural delivery mechanism: a public relay
hostname resolves to a public address and passes the check. In the local lab,
the `attacker` service resolves to a private Docker address, so the lab ships
a 10-line mu-plugin that allowlists exactly that hostname:

```php
add_filter( 'http_request_host_is_external', function ( $external, $host ) {
    return 'attacker' === strtolower( $host ) ? true : $external;
}, 10, 3 );
```

The mu-plugin is a lab harness. It does not weaken general SSRF protection
and is inert when the payload is served from a public host. Remove it if you
want a completely stock WordPress container.

---

## 3. WordPress HTTP API → Requests → cURL

`wp_safe_remote_get()` delegates to `WP_Http::request()`, which uses the
bundled Requests library. `limit_response_size` becomes `max_bytes`:

```php
// wp-includes/class-wp-http.php
if ( isset( $parsed_args['limit_response_size'] ) ) {
    $options['max_bytes'] = $parsed_args['limit_response_size'];
}
```

Requests' cURL transport sets:

```php
// wp-includes/Requests/src/Transport/Curl.php
curl_setopt( $this->handle, CURLOPT_ENCODING, '' );
```

`CURLOPT_ENCODING = ''` means “advertise and accept every encoding libcurl
supports”. If libcurl was built with Brotli — Debian's `libcurl4` is — then
`br` is in that set. libcurl decodes the response **inside the process**,
before PHP sees the body.

The transport also installs a write callback:

```php
curl_setopt( $this->handle, CURLOPT_WRITEFUNCTION, [ $this, 'stream_body' ] );
```

---

## 4. The 150 KB limit is on decompressed bytes

`stream_body()` is where `max_bytes` is enforced:

```php
public function stream_body( $handle, $data ) {
    $data_length = strlen( $data );

    if ( $this->response_byte_limit ) {
        if ( $this->response_bytes === $this->response_byte_limit ) {
            return $data_length;
        }
        if ( ( $this->response_bytes + $data_length ) > $this->response_byte_limit ) {
            $limited_length = ( $this->response_byte_limit - $this->response_bytes );
            $data = substr( $data, 0, $limited_length );
        }
    }

    if ( $this->stream_handle ) {
        fwrite( $this->stream_handle, $data );
    } else {
        $this->response_data .= $data;
    }

    $this->response_bytes += strlen( $data );
    return $data_length;   // original length, not the truncated length
}
```

Three consequences:

1. The counter sees **decoded** bytes. The compressed wire size is irrelevant.
2. The function returns the **original** length even when it truncates, so
   curl does not see a short write and does not abort the transfer.
3. If the decoder produces no output, the limit is never reached.

The 23 MB crash stream produces zero decoded bytes until its last 127 bytes:
2^24 dictionary commands that emit nothing. The 150 KB cap is untouched, the
transfer continues, and the decoder reaches the vulnerable state. The 86-byte
hang payload is far below the cap and also produces no output.

This is the subtle part of the chain: the limit is a real mitigation for
classic decompression bombs (huge output), but it is not a memory-safety
boundary. It cannot stop a zero-output OOB trigger.

---

## 5. Why the payload needs a decoder-call boundary

`BrotliDecoderState` keeps an 8-byte inline buffer for input bytes that do
not complete a bit sequence. In the vulnerable version, `buffer_length` is
incremented and the buffer is written without a bounds check.

The public trigger works in two writes:

1. feed the 16 MiB metablock plus 3 padding bytes; the decoder consumes
   everything and ends with `buffer_length == 1`;
2. feed the 127-byte tail. The decoder copies it into the 8-byte inline
   buffer, overwriting `pos`, `max_backward_distance`, and `max_distance`.

Over HTTP, the two writes must land in separate `BrotliDecoderDecompressStream`
calls. That is why the lab's payload server uses a **chunked response with a
delay**:

```text
HTTP/1.1 200 OK
Content-Encoding: br
Transfer-Encoding: chunked

<23,068,693-byte chunk>     # stream + 3 pad bytes
   ... 1 second delay ...
<127-byte chunk>            # corrupted-state tail
<0-length chunk>
```

libcurl feeds each network read to the decoder. After the first chunk, the
decoder is parked with `buffer_length == 1`; the tail arrives in a new read
and triggers the overflow. If the tail is coalesced into the same read, the
decoder handles it in the same call and the overflow may not occur. This was
verified empirically: a plain `Content-Length` response with the same bytes
did not crash; the chunked response with a delay did.

The delay must be shorter than WordPress's 10-second HTTP timeout. The lab
uses 1 second on localhost. On a byte-preserving public relay, keep the delay
at 1–2 seconds and make sure the 23 MB body can be uploaded within the
remaining budget. A relay that decodes `br` cannot deliver this payload at all.

---

## 6. Impacts

### 6.1 86-byte hang → worker starvation

The 22-byte input from Node.js' regression test reaches an impossible block
switch. The vulnerable decoder returns `NEEDS_MORE_INPUT` without consuming
input. libcurl's `brotli_do_write()` loop is:

```c
while ((nbytes || r == BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT) && result == CURLE_OK) {
    ...
    r = BrotliDecoderDecompressStream(bp->br, &nbytes, &src, &dstleft, &dst, NULL);
    ...
    switch (r) {
    case BROTLI_DECODER_RESULT_NEEDS_MORE_OUTPUT:
    case BROTLI_DECODER_RESULT_NEEDS_MORE_INPUT:
        break;
    ...
    }
}
```

With `nbytes > 0` and no progress, the loop spins. In the lab, curl's
`CURLOPT_TIMEOUT` did not interrupt it (the timeout check is inside the
decode loop and depends on progress bookkeeping).

The stock php-fpm config has no `request_terminate_timeout`. PHP-FPM still
has `max_execution_time = 30`, so the worker burns CPU for up to ~30 seconds
and the child then exits with code 124. A `request_terminate_timeout = 15s`
shortens that window: the master sends `SIGTERM` (and `SIGKILL` after
`process_control_timeout` if it does not exit), logs `execution timed out`,
and respawns the worker.

The stock pool is `pm = dynamic` with `pm.max_children = 5`. Five concurrent
hangs occupy the whole pool for up to ~30 seconds. The site returns 502/504
during that window, or until the workers are restarted with `make restart`.

### 6.2 23 MB tail → OOB write → SIGSEGV

The tail sets `pos = -0x40000000` and `max_distance = 0x7fffffff`. The next
ring-buffer copy computes a destination about 1 GiB below the ring, which is
unmapped. The worker dies with signal 11; php-fpm logs:

```text
WARNING: [pool www] child 42 exited on signal 11 (SIGSEGV) after 1.2 seconds from start
```

This is a real memory-corruption crash, not a PHP exception. It is the
availability outcome of CVE-2026-111497.

---

## 7. Sequence diagram

```text
Attacker            WordPress                 libcurl/libbrotli        Payload server
   |                    |                            |                       |
   |  POST /xmlrpc.php  |                            |                       |
   |  pingback.ping     |                            |                       |
   |  sourceURI=A       |                            |                       |
   |  targetURI=T       |                            |                       |
   |------------------->|                            |                       |
   |                    | validate T, sleep 1s       |                       |
   |                    | wp_safe_remote_get(A)      |                       |
   |                    |--------------------------->|  GET A                |
   |                    |                            |---------------------->|
   |                    |                            |  200 br, chunk 1      |
   |                    |                            |<----------------------|
   |                    |                            |  decode: 0 bytes out  |
   |                    |                            |  buffer_length = 1    |
   |                    |                            |        ... delay ...  |
   |                    |                            |  chunk 2 (127 B)      |
   |                    |                            |<----------------------|
   |                    |                            |  OOB write -> SIGSEGV |
   |                    |<-- worker dies ------------|                       |
   |<-- 502 / reset ----|                            |                       |
```

---

## 8. What about Requests' retry?

Requests retries the request with `CURLOPT_ENCODING = 'none'` when curl
returns `CURLE_WRITE_ERROR` or `CURLE_BAD_CONTENT_ENCODING`:

```php
if ( curl_errno( $this->handle ) === CURLE_WRITE_ERROR
    || curl_errno( $this->handle ) === CURLE_BAD_CONTENT_ENCODING ) {
    curl_setopt( $this->handle, CURLOPT_ENCODING, 'none' );
    ...
    curl_exec( $this->handle );
}
```

This does not save a vulnerable worker:

* on a crash, the process is already gone;
* on the hang, curl never returns an error code;
* on a patched decoder, the retry fetches the raw compressed bytes, which
  WordPress then parses as HTML and rejects — a clean failure.

The retry is still worth knowing for detection: a patched site may show two
outbound requests to the same URL, the second without `Accept-Encoding`.

---

## 9. Constraints summary

| Constraint | Effect on the attack |
|---|---|
| `timeout => 10` | 23 MB must arrive within ~10 s; local lab is fine, slow relays are not |
| `redirection => 0` | no redirect to the payload; host it directly |
| `limit_response_size => 150 KB` | applies to decoded bytes; zero-output streams bypass it |
| `wp_safe_remote_get` | private IPs rejected; use a public relay or the lab allowlist |
| `pings_open` + valid post | `/?p=1` works after a default install |
| unique source URL | add a cache-buster to avoid “pingback already registered” |
| chunk boundary | the 23 MB tail must arrive in a separate decoder call |

---

## References

* WordPress `pingback_ping()`:
  `wp-includes/class-wp-xmlrpc-server.php`
* WordPress HTTP API:
  `wp-includes/class-wp-http.php`, `wp-includes/http.php`
* Requests cURL transport:
  `wp-includes/Requests/src/Transport/Curl.php`
* curl Brotli decoder:
  `lib/content_encoding.c`, `brotli_do_write()`
* Brotli fix:
  `google/brotli@0ed4268a4401abcb44720963`
