# Changelog

## 1.0.1 — 2026-10-27

* Removed the optional public tunnel profile, Makefile targets, and
  documentation. The lab is local-only again.

## 1.0.0 — 2026-10-27

Initial public lab.

* Docker Compose lab: official WordPress FPM image (pinned digest), MariaDB,
  nginx, payload server.
* 86-byte non-progressing Brotli stream (worker hang / SIGTERM).
* ~23 MB zero-output stream + crash tail (worker SIGSEGV).
* `pingback_poc.py` with `probe`, `hang`, and `crash` modes, safety gate, and
  Docker log correlation.
* Documentation: vulnerability, attack chain, lab, PoC, detection,
  mitigation.
* Verified end-to-end on x86-64:
  * `hang`: 4 workers killed by `request_terminate_timeout` after 15 s.
  * `crash`: 4 workers exited on signal 11 (SIGSEGV) in ~2.7 s.
