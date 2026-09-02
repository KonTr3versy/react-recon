# react-recon

`react-recon` is a bounded reconnaissance and target-prioritization CLI for authorized security assessments. It combines deterministic collection and normalization with a tightly scoped ReAct planning step and an evidence-grounded LLM analyst that produces a concise queue for a human pentester.

```text
root FQDN
   |
   +--> crt.sh ---------+
   +--> Subfinder ------+--> DNS verification --> HTTP probing
   +--> gau ------------+                           |
                                                    +--> normalized evidence
                                                               |
authorized active mode --> candidate action catalog --> LLM selects typed action IDs (max 3)
                                     |                         |
                                     +--> deterministic executor + progress check
                                                               |
                                     deterministic coverage fallback
                                                               |
                                     AlterX --> DNS --> HTTP --> Naabu --> observed ports --> Nmap
                                                               |
                                                               +--> LLM targeting brief + reports
```

The model does not receive a shell, raw command arguments, local paths, or authority to create evidence. In active hybrid mode it may select from opaque candidate IDs tied to existing typed tools; the controller reconstructs and validates every hostname/IP/port argument from SQLite. Passive collection, scope enforcement, parsing, deduplication, progress evaluation, deterministic fallback, and report facts remain deterministic. OpenAI and Anthropic are supported through the same structured-output boundary.

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
- An OpenAI or Anthropic API key for active hybrid planning and the default end-to-end analyst brief

See [Installation](docs/INSTALLATION.md) for exact macOS/Linux commands and the locally tested tool versions.

Kali users can bootstrap the validated toolchain from a cloned repository:

```bash
./scripts/install-kali.sh --provider openai
```

Add `--configure` to opt into a masked model/API-key setup prompt. Without it,
the installer never requests credentials and deterministic collection remains
fully usable.

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

Choose `REACT_RECON_AI_PROVIDER=openai` with `OPENAI_API_KEY`, or `REACT_RECON_AI_PROVIDER=anthropic` with `ANTHROPIC_API_KEY`. A key is not needed for deterministic collection or standalone report rendering; active hybrid planning and LLM analysis require it. See [Model providers](docs/MODEL_PROVIDERS.md).

## Copy/paste operator commands

The normal `run` command performs collection, LLM analysis, and both report
exports in one command. Run these examples from the repository root after
loading `.env`. Replace the example values with the approved engagement scope
before execution.

Runs print immediate collector lifecycle and adaptive pacing updates to stderr.
Each external collector has a fixed wall-clock timeout and runs in its own
process group, which is terminated on timeout or operator cancellation. The
final completion summary remains clean JSON on stdout.

Start every operator session with:

```bash
set -a
source .env
set +a
uv run react-recon preflight
```

### Passive mode: end-to-end

Change only the `DOMAIN` value, then copy and paste the complete block:

```bash
DOMAIN="target.example"

uv run react-recon run \
  --root-fqdn "$DOMAIN" \
  --mode passive
```

This runs crt.sh, Subfinder, gau, dnsx, and httpx; analyzes the normalized
results; recommends strong candidates for a later active run; and writes the
matching HTML and JSON reports beneath `reports/<domain>-<run-date>/`.

### Active mode: hybrid ReAct planning and full coverage

Change only the `DOMAIN` value, then copy and paste the complete block:

```bash
DOMAIN="target.example"

uv run react-recon run \
  --root-fqdn "$DOMAIN" \
  --mode active \
  --planning-mode hybrid \
  --max-adaptive-actions 3
```

Active mode first completes the passive baseline. The configured model may
then review fresh DNS addresses, HTTP response priority, status codes, and
technology signals before selecting up to three validated typed actions. For a
port-discovery action, the controller resolves the selected opaque candidate ID
back to its current hostname/IP binding and passes only those IPs to Naabu.
Deterministic target-aware fallback completes remaining AlterX, dnsx, httpx,
Naabu, and Nmap coverage.

Fresh globally routable A/AAAA answers under the authorized hostname boundary
are eligible automatically. `--authorized-network` is optional: when supplied,
it becomes a strict destination restriction and also permits matching private
or otherwise non-global addresses. Repeat it for multiple approved networks:

```bash
DOMAIN="target.example"
AUTHORIZED_PUBLIC_CIDR="192.0.2.0/24"
AUTHORIZED_INTERNAL_CIDR="198.51.100.0/24"

uv run react-recon run \
  --root-fqdn "$DOMAIN" \
  --mode active \
  --authorized-network "$AUTHORIZED_PUBLIC_CIDR" \
  --authorized-network "$AUTHORIZED_INTERNAL_CIDR"
```

Active mode treats the root FQDN and its descendants as the authorized hostname
boundary. `--authorized-host` optionally adds one exact hostname outside that
boundary; it does not authorize descendants or bypass DNS verification:

```bash
DOMAIN="target.example"
EXACT_HOST="vpn.separately-authorized.example"

uv run react-recon run \
  --root-fqdn "$DOMAIN" \
  --mode active \
  --authorized-host "$EXACT_HOST"
```

HTTP validation accepts globally routable answers or explicitly authorized
private addresses. Naabu and Nmap automatically accept fresh globally routable
answers for in-scope hosts. Private, loopback, link-local, multicast, reserved,
and unspecified destinations remain ineligible unless an approved IP/CIDR is
named with `--authorized-network`. All active hosts still need fresh dnsx
evidence from the run.

To disable model-directed collection while preserving the fixed active
workflow, use:

```bash
DOMAIN="target.example"

uv run react-recon run \
  --root-fqdn "$DOMAIN" \
  --mode active \
  --planning-mode deterministic \
  --max-adaptive-actions 0
```

The final analyst brief still uses the configured model. Add
`--collection-only` when the intended result is deterministic collection only,
with no model analysis or automatic report generation.

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

The controller always attempts the passive baseline in a fixed, resumable order:

1. crt.sh certificate-transparency names
2. Subfinder passive subdomain discovery
3. gau passive URL candidates
4. dnsx verification of discovered hosts
5. httpx verification of both HTTP and HTTPS plus status, redirect, title,
   technology, TLS, server, content metadata, favicon/JARM, and response hash
   collection for DNS-resolved hosts

Active hybrid mode then builds a bounded catalog of eligible typed actions. The
model may select up to three opaque candidate IDs for DNS/HTTP recovery,
permutation work, port discovery, or fingerprinting. A deterministic progress
evaluator stops the adaptive portion after two no-progress/failing actions,
provider/decision failure, explicit finish, or budget exhaustion. Deterministic
fallback performs the remaining AlterX, dnsx, httpx, Naabu, and Nmap coverage;
provider failure never prevents collection from continuing.

Hosts identified as CDN-backed or
aliased by CNAME to infrastructure outside the configured boundary are excluded
from port scans unless the hostname was explicitly added with
`--authorized-host`. Even explicit hosts must resolve during the run. Only
normalized host/port pairs observed open are handed to Nmap.

Every destination-touching stage uses the hostname/IP tuples produced by dnsx.
Bindings expire after one hour by default. httpx receives a per-host IP
allowlist, Naabu scans the approved IPs rather than
re-resolving hostnames, and Nmap fingerprints the exact IP/port tuples returned
by Naabu. Fresh globally routable answers are eligible automatically. A host
with a private, loopback, link-local, multicast, reserved, unspecified, or
mixed eligible/ineligible answer set is excluded unless every intended
non-global destination is covered by `--authorized-network`. When one or more
networks are supplied, they strictly restrict active port and service targets.

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

- `react-recon.db`: SQLite run, task, adaptive decision/progress, observation, coverage, and analysis state
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
its descendants are authorized for DNS, HTTP, and bounded TCP probing of fresh
globally routable DNS answers. Exact additional hostnames must be named with
`--authorized-host`. Use `--authorized-network` to restrict public destinations
or permit approved private/non-global destinations. Read
[Security](SECURITY.md) before operating or modifying the execution boundary.

## License

[MIT](LICENSE)

## Research basis

The initial architecture was informed by AppSec Santa's [AI Pentesting Agents 2026](https://appsecsanta.com/research/ai-pentesting-agents-2026) and then narrowed into a single-agent reconnaissance workflow with deterministic execution and human-reviewed analysis.
