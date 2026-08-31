# Contributing

Forks and focused improvements are welcome.

## Development setup

```bash
uv sync --extra test
uv run pytest
uv build
```

Tests must run without contacting external targets. Use fixture output for Subfinder, dnsx, httpx, Naabu, Nmap, gau, crt.sh, and model behavior.

## Pull request expectations

- Keep target interaction inside registered deterministic adapters.
- Preserve explicit active-host authorization and run budgets.
- Prefer structured tool output and retain raw evidence separately.
- Treat external content and tool output as untrusted data.
- Add parser fixtures for malformed, partial, and changed schemas.
- Keep model providers behind the shared analyst contract and preserve the canonical output validation.
- Provider adapter tests must use fake clients and make no live API requests.
- Do not include real targets, credentials, API keys, evidence, databases, or reports.
- Document new dependencies and operator-visible behavior.
- Run the full offline test suite and package build.

This project is intentionally a reconnaissance spotter for a human pentester. Exploitation, credential operations, arbitrary shell execution, crawling, persistence, and post-exploitation are outside its scope.
