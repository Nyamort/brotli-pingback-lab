<?php
/**
 * Behavioural probe used by scripts/verify-vulnerable.sh.
 *
 * With a vulnerable libbrotlidec, the 86-byte Brotli stream from
 * CVE-2026-111497 makes libcurl's brotli write loop return
 * NEEDS_MORE_INPUT without consuming input.  The loop never makes
 * progress and this script is killed by the external `timeout`.
 *
 * With a patched decoder, the invalid block switch is reported as a
 * format error and the request returns quickly with a non-zero errno.
 */

$url = getenv( 'PROBE_URL' ) ?: 'http://attacker:8080/small.br';

$ch = curl_init( $url );
curl_setopt( $ch, CURLOPT_ENCODING, '' );
curl_setopt( $ch, CURLOPT_RETURNTRANSFER, true );
curl_setopt( $ch, CURLOPT_TIMEOUT, 3 );
curl_setopt( $ch, CURLOPT_CONNECTTIMEOUT, 2 );

$body = curl_exec( $ch );

printf(
	"errno=%d error=%s body=%d\n",
	curl_errno( $ch ),
	curl_error( $ch ),
	strlen( (string) $body )
);
