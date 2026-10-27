# Security policy

## Scope

This repository is a **laboratory** for CVE-2026-111497. It demonstrates a
worker stall and a worker `SIGSEGV` through WordPress XML-RPC pingback.

It intentionally does **not** contain:

* a remote code execution exploit;
* heap grooming, pointer leaks, or ASLR bypasses;
* a payload targeting third-party software.

## Authorized use

Use it only on the Docker lab in this repository, systems you own, or systems
for which you have explicit written authorization. The PoC refuses targets
that resolve to public IP addresses unless `--i-own-this-target` is passed.

## Reporting

For a bug in the lab, open a GitHub issue with the affected file, reproduction
steps, expected/actual behavior, and relevant logs (redact secrets). For a
sensitive report, use GitHub private vulnerability reporting.

For the upstream bug, contact the Brotli maintainers and the relevant runtime
vendors. Do not publish an exploit before coordinated disclosure.

## Safety notes

* The WordPress admin password is `admin`; the lab is local and disposable.
* Keep the payload server on the lab network. Do not expose it publicly.
* The 23 MB payload is generated at runtime and is not committed.
* The mu-plugin only allowlists the Docker-internal hostname `attacker`; it is
  not a production SSRF bypass.
