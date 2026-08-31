# react-recon

`react-recon` is a bounded reconnaissance and target-prioritization CLI for authorized security assessments. It combines deterministic collection and normalization with a separate evidence-grounded LLM analyst that produces a concise queue for a human pentester.

```text
root FQDN
   |
   +--> crt.sh ---------+
   +--> Subfinder ------+--> DNS verification --> HTTP probing
   +--> gau ------------+                           |
                                                    +--> normalized evidence
                                                               |
authorized active mode --> Naabu --> observed ports --> Nmap --+
                                                               |
                                                               +--> LLM targeting brief
```

The model does not receive a shell, choose arbitrary commands, or create evidence. Collection, scope enforcement, parsing, deduplication, state transitions, and report facts remain deterministic. The provider-agnostic LLM layer is used after collection for prioritization and synthesis; OpenAI and Anthropic are supported.

This project does not perform vulnerability exploitation, credential attacks, crawling, post-exploitation, or persistence.

## Status

This is an alpha-quality practitioner tool. The parser and controller paths are fixture-tested, but external tool behavior can change between releases. Review scope, versions, evidence, and analyst conclusions before using the output in an assessment.

## Prerequisites

- macOS, Linux, or Windows through WSL2
- Python 3.11 or newer
- [`uv`](https://docs.astral.sh/uv/) for installation and execution
- A current supported Go toolchain if installing host binaries from source
- Subfinder, dnsx, httpx, and gau for passive collection
- Naabu for active port discovery
- Nmap or Docker for active service fingerprinting
- An OpenAI or Anthropic API key only when running `react-recon analyze`

See [Installation](docs/INSTALLATION.md) for exact macOS/Linux commands and the locally tested tool versions.

## Quick start

```bash
git clone https://github.com/KonTr3versy/react-recon.git
cd react-recon
uv sync --extra openai --extra test
uv run react-recon preflight
```

Create local configuration without placing a key in source control:

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env`, then load it into the current shell:

```bash
set -a
source .env
set +a
```

Choose `REACT_RECON_AI_PROVIDER=openai` with `OPENAI_API_KEY`, or `REACT_RECON_AI_PROVIDER=anthropic` with `ANTHROPIC_API_KEY`. The key is not needed for collection or report rendering. See [Model providers](docs/MODEL_PROVIDERS.md).

## Basic usage

Passive collection:

```bash
uv run react-recon run --root-fqdn example.com --mode passive
```

Authorized active collection requires an explicit allowlist:

```bash
uv run react-recon run \
  --root-fqdn example.com \
  --mode active \
  --authorized-host www.example.com \
  --authorized-host vpn.example.com
```

Analyze and report a completed run:

```bash
uv run react-recon analyze RUN_ID --provider openai --model gpt-5.6-luna --max-targets 8
uv run react-recon analyze RUN_ID --provider anthropic --model claude-sonnet-5 --max-targets 8
uv run react-recon report RUN_ID --format html
uv run react-recon report RUN_ID --format json
```

Resume an interrupted run or rebuild normalized state from preserved evidence:

```bash
uv run react-recon resume RUN_ID
uv run react-recon reprocess RUN_ID
```

`reprocess` makes no target or third-party network requests. It applies the current parsers to saved JSONL evidence, atomically rebuilds normalized observations/assets, and marks older analyses stale.

See [Usage](docs/USAGE.md) for scope semantics, budgets, state files, reports, troubleshooting, and a complete operator workflow.

## Collection workflow

The default controller attempts the complete passive baseline in a fixed order:

1. crt.sh certificate-transparency names
2. Subfinder passive subdomain discovery
3. gau passive URL candidates
4. dnsx verification of discovered hosts
5. httpx verification and metadata collection for DNS-resolved hosts

Active mode then runs Naabu against explicitly authorized hosts. Only normalized host/port pairs observed open are handed to Nmap. Analysis is allowed after every required collection stage has succeeded, failed after bounded retries, or been recorded as not applicable. Failures remain visible as coverage gaps and are never presented as negative security findings.

## Output and data handling

- `react-recon.db`: SQLite run, task, observation, coverage, and analysis state
- `evidence/RUN_ID/`: append-only raw JSONL execution evidence
- `reports/RUN_ID.json`: complete machine-readable report
- `reports/RUN_ID.html`: concise analyst-facing targeting brief

These paths are ignored by Git because they may contain client-sensitive data. Do not override those exclusions to publish real assessment artifacts. A sanitized example is available in [`examples/`](examples/README.md).

## Development

```bash
uv sync --extra all-models --extra test
uv run pytest
uv build
```

The test suite uses fixtures and does not contact external targets. Pull requests should preserve that offline property. See [Contributing](CONTRIBUTING.md).

## Security and authorization

Use this tool only where you have explicit authorization and an established scope. Active mode is intentionally restricted to exact `--authorized-host` values. Read [Security](SECURITY.md) before operating or modifying the execution boundary.

## License

[MIT](LICENSE)

## Research basis

The initial architecture was informed by AppSec Santa's [AI Pentesting Agents 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026) and then narrowed into a single-agent reconnaissance workflow with deterministic execution and human-reviewed analysis.
