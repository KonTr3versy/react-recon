# Operator usage

## Preflight

```bash
uv run react-recon preflight
```

Confirm the expected collectors are found before starting. Passive collection
requires Subfinder, dnsx, httpx, and gau; crt.sh is built in. Active collection
additionally requires AlterX, Naabu, and either Nmap or Docker. Preflight prints
the resolved path and version when available.

## One-command workflow

The normal `run` command performs collection, model analysis, and HTML/JSON
report generation. Both reports are written to a dated domain directory such
as `reports/example.com-2026-08-31/`.

### Passive assessment

```bash
uv run react-recon run \
  --root-fqdn example.com \
  --mode passive \
  --max-assets 500 \
  --max-tool-calls 25 \
  --max-duration-seconds 1800 \
  --max-output-bytes 16777216 \
  --max-evidence-bytes 67108864 \
  --max-observations 20000 \
  --max-observation-bytes 262144 \
  --max-normalized-bytes 33554432 \
  --max-dns-binding-age-seconds 3600 \
  --rate-limit 10 \
  --concurrency 2
```

Globally routable A/AAAA answers are eligible for HTTP validation by default.
Active Naabu and Nmap stages require explicit destination authorization for
every public or private IP; repeat the option for disjoint networks:

```bash
uv run react-recon run \
  --root-fqdn corp.example.com \
  --mode active \
  --authorized-network 10.20.0.0/16 \
  --authorized-network 172.20.40.0/24
```

`--authorized-network` authorizes destinations, not hostnames. A destination
still needs an in-scope hostname and fresh dnsx evidence from the current run.
Bindings older than one hour fail closed by default; adjust
`--max-dns-binding-age-seconds` only when the assessment requires a different
freshness window.

The command prints a JSON completion summary containing the run ID, analysis
ID, report directory, and both report paths. Passive URL candidates are
recorded but not fetched automatically.

httpx probes both HTTP and HTTPS for every DNS-resolved in-scope hostname. The
report places confirmed responding endpoints in a dedicated inventory and
orders successful 2xx, access-controlled 401/403/407, and redirecting 3xx
responses ahead of lower-signal HTTP responses and DNS-only candidates.

The passive analyst brief includes a separate **Recommended for active
follow-up** queue. It is intentionally short and evidence-backed: hostname,
exact observed URL when one exists, why active validation is useful, the active
objective, confidence, and evidence references. A hostname-only recommendation
means the name is worth further validation; it is not a claim that a live
service was observed.

### Authorized active assessment

Active mode treats the root FQDN and its descendants as the authorized domain
boundary. Additional exact hostnames outside that boundary may be supplied with
`--authorized-host`:

```bash
uv run react-recon run \
  --root-fqdn example.com \
  --mode active \
  --authorized-network 203.0.113.0/24 \
  --max-permutations 2000 \
  --dns-rate-limit 50 \
  --rate-limit 5 \
  --concurrency 2
```

The active workflow is intentionally linear:

1. Complete passive discovery, dnsx verification, and httpx probing.
2. Run one bounded AlterX pass over discovered in-scope names.
3. Send only new permutation candidates through dnsx and then httpx.
4. Build the Naabu target set from DNS-verified in-scope hosts whose addresses
   are covered by `--authorized-network`.
5. Exclude inferred CDN hosts and hostnames CNAME'd outside the domain boundary,
   unless that hostname was explicitly authorized.
6. Send only host/port pairs observed open by Naabu to Nmap version-light
   fingerprinting.

The HTTP and port stages do not trust a hostname alone. httpx is constrained to
the approved dnsx address set, Naabu receives those IPs directly, and Nmap uses
the exact IP/port tuples observed by Naabu. Mixed answer sets fail closed.

An explicitly authorized hostname still needs DNS evidence from the run before
it is port scanned. `--max-permutations`, the run-wide tool-call and duration
budgets, dnsx rate limits, and tool retries bound the expansion.

Provider and model can be selected in the same command when they are not set in
`.env`:

```bash
uv run react-recon run \
  --root-fqdn example.com \
  --mode passive \
  --provider openai \
  --model gpt-5.6-luna \
  --max-targets 8
```

Use `--reports-dir PATH` to change the report parent directory. Use
`--collection-only` only when you deliberately want to stop after collection.

## Standalone recovery and rerender commands

The following commands are retained for interrupted runs, reanalysis with a
different model, and custom report rendering. They are not required for a
normal assessment.

### Analysis

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

### Reports

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

The tool-call count is also durable. Restarting `resume` cannot reset the
original run's execution budget or repeat stages that already produced an
execution ledger record.

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

A run with an exhausted/repeated collector failure ends as
`completed_with_gaps` after the remaining safe stages are attempted. If model
analysis then fails, the normal command still writes HTML and JSON reports and
returns exit code `2`; the reports preserve the collection evidence and name
the failed analysis attempt.

## Data retention

Each run may contain client-sensitive hostnames, IP addresses, URLs, service data, and model analysis. Keep the database, evidence, and reports in the engagement's approved storage location. These paths are ignored by Git by default.

The default execution budgets cap each collector stream at 16 MiB, the exact
serialized JSONL evidence set at 64 MiB, normalized observations at 20,000,
each normalized observation at 256 KiB, and total normalized JSON at 32 MiB.
Exceeding a ceiling records a failed collection stage instead of treating
partial output as a successful negative result. New SQLite databases, JSONL
evidence, and reports are mode `600`; newly created evidence and dated report
directories are mode `700`.

Migrate recognized databases, evidence, reports, and `.env` files created by an
older release with:

```bash
uv run react-recon harden-artifacts
```

The normal `run` workflow also applies this migration to its configured output
roots before opening or writing assessment data.
