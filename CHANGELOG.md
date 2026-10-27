# Changelog

## 1.0.0 — 2026-10-27

Initial public lab.

* Docker Compose lab: official WordPress FPM image (pinned digest), MariaDB,
  nginx, payload server.
* 86-byte non-progressing Brotli stream (worker hang / SIGTERM).
* ~23 MB zero-output stream + crash tail (worker SIGSEGV).
* `pingback_poc.py` with `probe`, `hang`, and `crash` modes, safety gate, and
  Docker log correlation.
* Documentation: vulnerability, attack chain, lab, PoC, Cloudflare, detection,
  mitigation.
* Verified end-to-end on x86-64:
  * `hang`: 4 workers killed by `request_terminate_timeout` after 15 s.
  * `crash`: 4 workers exited on signal 11 (SIGSEGV) in ~2.7 s.
* Cloudflare Quick Tunnel experiment: the edge decodes `Content-Encoding: br`
  (`/small.br` → 16,777,218 bytes of `A`; `/payload.br` → 0 bytes). The tunnel
  is documented as a public-URL/SSRF demo and a CDN-level mitigation, not as a
  delivery path for the crash.
