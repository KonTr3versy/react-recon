# Operator usage

## Preflight

```bash
uv run react-recon preflight
```

Confirm the expected collectors are found before starting. Passive collection requires Subfinder, dnsx, httpx, and gau; crt.sh is built in. Active collection additionally requires Naabu and either Nmap or Docker.

## Passive workflow

```bash
uv run react-recon run \
  --root-fqdn example.com \
  --mode passive \
  --max-assets 500 \
  --max-tool-calls 25 \
  --max-duration-seconds 1800 \
  --rate-limit 10 \
  --concurrency 2
```

The command prints a run ID. Passive URL candidates are recorded but not fetched automatically.

## Authorized active workflow

Active mode does not treat every discovered subdomain as authorized. Each active target must be supplied explicitly:

```bash
uv run react-recon run \
  --root-fqdn example.com \
  --mode active \
  --authorized-host www.example.com \
  --authorized-host vpn.example.com \
  --rate-limit 5 \
  --concurrency 2
```

The workflow performs the passive baseline, probes eligible HTTP hosts, runs Naabu only for the exact active allowlist, and feeds only observed open ports into Nmap service fingerprinting.

## Analysis

```bash
uv run react-recon analyze RUN_ID \
  --provider openai \
  --model gpt-5.6-luna \
  --max-targets 8
```

The equivalent Anthropic command is:

```bash
uv run react-recon analyze RUN_ID \
  --provider anthropic \
  --model claude-sonnet-5 \
  --max-targets 8
```

The model receives normalized facts, fact identifiers, coverage, and deterministic target profiles—not arbitrary shell access. Its claims must reference known fact IDs and unsupported security claims are rejected.

The selected model API is an external data processor. Confirm your engagement permits sending normalized reconnaissance metadata to that provider before running this command. Collection and deterministic reports remain available without it. See [Model providers](MODEL_PROVIDERS.md) for configuration and precedence.

## Reports

```bash
uv run react-recon report RUN_ID --format html
uv run react-recon report RUN_ID --format json
```

The HTML report is optimized for analyst decisions. JSON contains the full machine-readable ledger and will normally be much larger.

## Resume and reprocess

Resume uses the original scope and budgets stored in SQLite:

```bash
uv run react-recon resume RUN_ID
```

Reprocess applies current parsers to existing raw evidence without network traffic:

```bash
uv run react-recon reprocess RUN_ID
```

Reprocessing marks completed analyses stale. Run `analyze` again before rendering a new analyst brief.

For a non-default database or evidence directory:

```bash
export REACT_RECON_DATABASE=/path/to/react-recon.db
export REACT_RECON_EVIDENCE_DIR=/path/to/evidence
```

## Interpreting states

- `success`: the tool completed and its output was parsed; it may still contain zero observations.
- `failed`: execution or collection failed; this is a coverage gap, not a negative finding.
- `skipped`: policy or state prevented execution, such as no eligible hosts.
- `not_applicable`: no valid downstream targets existed for that stage.
- `incomplete`: some expected targets were not attempted.

## Data retention

Each run may contain client-sensitive hostnames, IP addresses, URLs, service data, and model analysis. Keep the database, evidence, and reports in the engagement's approved storage location. These paths are ignored by Git by default.
