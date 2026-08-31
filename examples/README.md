# Sanitized example

This directory contains a synthetic `example.com` run generated entirely from fixture observations. It demonstrates the JSON/HTML report shape without contacting a target, invoking reconnaissance binaries, or calling an LLM.

- `example-report.html`: analyst-facing report
- `example-report.json`: complete machine-readable report
- `sample-evidence/`: synthetic raw execution ledger linked by the reports
- `generate_example_report.py`: deterministic generator

Regenerate it from the repository root:

```bash
uv run python examples/generate_example_report.py
```

No real assessment data belongs in this directory.
