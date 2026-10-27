# Contributing

This is a security lab, not a production tool. Contributions that improve
reproducibility, documentation, or defensive value are welcome.

## Before you start

* Keep the project crash-only. Do not submit RCE chains, heap grooming,
  pointer leaks, or weaponized payloads.
* Do not add a payload that targets a third-party service.
* The 23 MB payload is generated at runtime; do not commit generated `.br`
  files.

## Development

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q poc lab/attacker tests
docker compose config >/dev/null
bash -n scripts/verify-vulnerable.sh
```

End-to-end:

```bash
cp .env.example .env
make up
make probe
make verify
make hang
make crash
```

## Reporting issues

Use the GitHub issue tracker for:

* a broken lab step;
* a version/offset mismatch (the crash tail is x86-64 and
  Brotli 1.1.0/1.2.0 specific);
* a documentation error;
* a new detection or mitigation that can be validated in the lab.

For sensitive reports, use GitHub private vulnerability reporting. See
[SECURITY.md](SECURITY.md).

## Style

* Docs: English, short paragraphs, commands that can be copied.
* Python: standard library only, 4-space indent, type hints where useful.
* Shell: `bash`, `set -u`, no destructive defaults.
* Do not bump the pinned WordPress digest without running `make verify` and
  re-testing both payloads.
