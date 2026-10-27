# Security policy

## Scope

This repository is a **laboratory** for CVE-2026-111497. It demonstrates a
denial-of-service / worker-crash outcome through WordPress XML-RPC pingback.

It intentionally does not contain:

* a remote code execution exploit;
* heap grooming, pointer leaks, or ASLR bypasses;
* a weaponized payload targeting third-party software.

The payload generator produces a stream that crashes a decoder process. That
is enough to study the bug and to test detections, and it is the limit of what
this project will publish.

## Authorized use

Use this project only on:

* the Docker lab in this repository;
* systems you own;
* systems for which you have explicit, written authorization.

The PoC refuses targets that resolve to public IP addresses unless
`--i-own-this-target` is passed. Do not remove that check to attack systems
you do not control.

## Reporting a problem in this project

If you find a bug in the lab, the PoC, or the documentation, open a GitHub
issue with:

* the affected file and version/commit;
* reproduction steps;
* expected vs actual behaviour;
* relevant logs (redact hostnames, IPs, and credentials).

If the report is sensitive (for example, it enables misuse beyond the
documented lab), use GitHub's private vulnerability reporting instead of a
public issue.

## Reporting the upstream vulnerability

CVE-2026-111497 is a Google Brotli issue. Report new findings to the Brotli
maintainers and the relevant runtime vendors. Do not open a public issue with
an exploit before coordinated disclosure.

## Safety notes

* The lab's WordPress admin password is `admin`. It is for a disposable
  local container only. Never expose the site.
* The 23 MB payload is generated at runtime and is not committed.
* The lab's mu-plugin only allowlists the Docker-internal hostname
  `attacker`; it is not a production SSRF bypass.
