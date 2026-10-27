# Changelog

## 1.0.2 — 2026-10-27

* Use the stock php-fpm `www.conf` by default (`pm = dynamic`,
  `pm.max_children = 5`, no `request_terminate_timeout`). The 23 MB crash is
  unchanged; a hang is bounded by FPM `max_execution_time` (30s, exit code
  124).
* Added `make crash-pool`, `make hang-pool`, and `make restart`.
* The aggressive 4-worker/15s configuration is now an optional example
  (`lab/php-fpm/zz-lab.example.conf`, commented-out volume).

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
