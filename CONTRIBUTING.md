# Contributing

Use Python 3.11 or newer. The analyzer and tests use the standard library.

```bash
python -m unittest discover -s tests -v
```

For a parser change, include a synthetic accepted record and a malformed-input case. For a detection change, test a positive signal, a negative case, the exact window boundary, and relevant source/host/account isolation. Document changed thresholds or evidence semantics in `docs/detection.md`.

Do not commit production logs, credentials, account information, or real incident artifacts. Use documentation IPv4/IPv6 addresses and fictional accounts in fixtures. The demo generator creates records locally and performs no network activity.

Regenerate the example reports after changes that affect their output:

```bash
python tools/generate_demo.py
python -m sentinel_logwatch analyze examples/modern-auth.jsonl --strict --html docs/demo-report.html --json docs/demo-report.json
```

Keep runtime dependencies empty unless there is a documented need. Report security issues using the guidance in `SECURITY.md`.
