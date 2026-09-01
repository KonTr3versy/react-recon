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
authorized active mode --> bounded AlterX --> DNS --> HTTP -----+
                                  |                              |
                                  +--> verified eligible hosts --> Naabu --> observed ports --> Nmap
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
- Go 1.25 or newer when installing the pinned host binaries from source or
  using the Kali bootstrap installer
- Subfinder, dnsx, httpx, and gau for passive collection
- AlterX and Naabu for active expansion and port discovery
- Nmap or Docker for active service fingerprinting
- An OpenAI or Anthropic API key for the default end-to-end `react-recon run` workflow or the standalone `analyze` command

See [Installation](docs/INSTALLATION.md) for exact macOS/Linux commands and the locally tested tool versions.

Kali users can bootstrap the validated toolchain from a cloned repository:

```bash
./scripts/install-kali.sh --provider openai
```

Add `--configure` to opt into a masked model/API-key setup prompt. Without it,
the installer never requests credentials and collection remains fully usable.

## Quick start

```bash
git clone https://github.com/KonTr3versy/react-recon.git
cd react-recon
uv sync --extra openai --extra test
uv run react-recon preflight
```

Create local configuration without placing a key in source control:

```bash
uv run react-recon init
cp .env.example .env
chmod 600 .env
```

`init` creates `.env.example` only when that template is absent. A cloned
repository already includes the template, so the command will report that it
exists; copy it to the untracked `.env` file before adding credentials.

Edit `.env`, then load it into the current shell:

```bash
set -a
source .env
set +a
```

Choose `REACT_RECON_AI_PROVIDER=openai` with `OPENAI_API_KEY`, or `REACT_RECON_AI_PROVIDER=anthropic` with `ANTHROPIC_API_KEY`. The key is not needed for collection or report rendering. See [Model providers](docs/MODEL_PROVIDERS.md).

## Basic usage

`run` performs collection, LLM analysis, and both report exports in one command.
Reports are written beneath `reports/<domain>-<run-date>/`.

Passive assessment:

```bash
uv run react-recon run --root-fqdn example.com --mode passive
```

Active mode treats the configured root FQDN and its descendants as the
authorized boundary. `--authorized-host` is optional and adds an exact target
outside that boundary; it does not bypass DNS verification. HTTP validation
accepts globally routable answers or explicitly authorized private addresses.
Naabu and Nmap require every
public or private destination to be explicitly named with
`--authorized-network`:

```bash
uv run react-recon run \
  --root-fqdn example.com \
  --mode active \
  --authorized-network 203.0.113.0/24
```

Example output:

```text
reports/example.com-2026-08-31/run-abc123def456.html
reports/example.com-2026-08-31/run-abc123def456.json
```

The standalone commands remain available when recovering, reanalyzing with a
different model, or rendering another copy of an existing run:

```bash
uv run react-recon analyze RUN_ID --provider openai --model gpt-5.6-luna --max-targets 8
uv run react-recon analyze RUN_ID --provider anthropic --model claude-sonnet-5 --max-targets 8
uv run react-recon report RUN_ID --format html
uv run react-recon report RUN_ID --format json
uv run react-recon report RUN_ID --format html --output reports/custom-report.html
```

Use `--output` to choose the exact destination for a standalone report render.

To intentionally collect evidence without contacting a model or generating
reports:

```bash
uv run react-recon run --root-fqdn example.com --mode passive --collection-only
```

Resume an interrupted run or rebuild normalized state from preserved evidence:

```bash
uv run react-recon resume RUN_ID
uv run react-recon reprocess RUN_ID
```

`resume` continues the persisted collection loop and prints the run ID when
collection stops or completes. It does not automatically rerun LLM analysis or
render new reports; use the standalone `analyze` and `report` commands above
after recovering an interrupted run.

`reprocess` makes no target or third-party network requests. It applies the current parsers to saved JSONL evidence, atomically rebuilds normalized observations/assets, and marks older analyses stale.

See [Usage](docs/USAGE.md) for scope semantics, budgets, state files, reports, troubleshooting, and a complete operator workflow.

## Collection workflow

The controller attempts the workflow in a fixed, resumable order:

1. crt.sh certificate-transparency names
2. Subfinder passive subdomain discovery
3. gau passive URL candidates
4. dnsx verification of discovered hosts
5. httpx verification of both HTTP and HTTPS plus status, redirect, title,
   technology, TLS, server, content metadata, favicon/JARM, and response hash
   collection for DNS-resolved hosts

Active mode then performs one bounded AlterX expansion using the discovered
in-scope names, verifies only the new candidates with dnsx and httpx, and runs
Naabu against DNS-verified eligible hosts. Hosts identified as CDN-backed or
aliased by CNAME to infrastructure outside the configured boundary are excluded
from port scans unless the hostname was explicitly added with
`--authorized-host`. Even explicit hosts must resolve during the run. Only
normalized host/port pairs observed open are handed to Nmap.

Every destination-touching stage uses the hostname/IP tuples produced by dnsx.
Bindings expire after one hour by default. httpx receives a per-host IP
allowlist, Naabu scans the approved IPs rather than
re-resolving hostnames, and Nmap fingerprints the exact IP/port tuples returned
by Naabu. A host with a private, loopback, link-local, reserved, or mixed
authorized/unauthorized answer set is excluded unless its network was named
with `--authorized-network`. Active port and service stages always require that
explicit network authorization, including for public IPs.

Analysis begins after every required stage has succeeded, exhausted bounded
retries, or been recorded as not applicable. Failures remain visible as
coverage gaps and are never presented as negative security findings. If model
analysis fails, collection evidence and both reports are still written; the
command returns a non-zero status and the reports identify the failed analysis
attempt.

The analyst input and reports distinguish passive candidates, DNS-resolved
hosts, failed HTTP probes, and confirmed responding web endpoints. Successful
2xx responses, access-controlled 401/403/407 responses, and 3xx redirects are
prioritized ahead of DNS-only candidates; other 4xx/5xx responses remain
evidence that an HTTP service answered without being treated as vulnerabilities.
At the end of a passive run, the analyst also produces a short
`Recommended for active follow-up` queue. Each entry identifies an observed
hostname, an exact observed URL when available, the specific objective for a
later active run, confidence, and supporting evidence. This queue is omitted
from active-mode analysis and never treats an unverified passive name as live.

## Output and data handling

- `react-recon.db`: SQLite run, task, observation, coverage, and analysis state
- `evidence/RUN_ID/`: append-only raw JSONL execution evidence
- `reports/<domain>-<run-date>/RUN_ID.json`: complete machine-readable report
- `reports/<domain>-<run-date>/RUN_ID.html`: concise analyst-facing targeting brief

These paths are ignored by Git because they may contain client-sensitive data. Do not override those exclusions to publish real assessment artifacts. A sanitized example is available in [`examples/`](examples/README.md).

New databases, evidence files, and reports are created owner-only (`600`), and
evidence/report directories are private (`700`). Per-process output, total raw
serialized evidence, and normalized count/byte ceilings fail closed when
exceeded.

Migrate recognized artifacts created by an older release with:

```bash
uv run react-recon harden-artifacts
```

## Development

```bash
uv sync --extra all-models --extra test
uv run pytest
uv build
```

The test suite uses fixtures and does not contact external targets. Pull requests should preserve that offline property. See [Contributing](CONTRIBUTING.md).

## Security and authorization

Use this tool only where you have explicit authorization and an established
scope. Selecting active mode is an operator assertion that the root FQDN and
its descendants are authorized for DNS and HTTP probing. Bounded TCP probing
also requires explicit destination CIDRs through `--authorized-network`; exact
additional hostnames must be named with `--authorized-host`. Read
[Security](SECURITY.md) before operating or modifying the execution boundary.

## License

[MIT](LICENSE)

## Research basis

The initial architecture was informed by AppSec Santa's [AI Pentesting Agents 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026) and then narrowed into a single-agent reconnaissance workflow with deterministic execution and human-reviewed analysis.
