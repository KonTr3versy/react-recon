# Model providers

The reconnaissance controller is provider-independent. In an active run using the default `hybrid` planning mode, the selected provider may prioritize up to three existing typed collection actions after the deterministic passive baseline. The same provider/model pair is then used for the final analyst brief.

Both adapters use the same provider-neutral structured-output interface and strict JSON Schemas. Planning output may reference only opaque candidate IDs from the current catalog. The controller maps accepted IDs back to SQLite-derived targets, rejects all unknown or mixed-tool IDs, and never accepts model-generated hosts, ports, commands, flags, or paths. Final-analysis output passes through deterministic host, fact-ID, target-count, rank, and unsupported-claim validation before it is saved.

## Configuration precedence

Provider selection:

1. `--provider`
2. `REACT_RECON_AI_PROVIDER`
3. `openai`

Model selection:

1. `--model`
2. `REACT_RECON_AI_MODEL`
3. Legacy provider variable: `OPENAI_MODEL` or `ANTHROPIC_MODEL`
4. Provider default

Current defaults:

| Provider | Default model | Credential |
| --- | --- | --- |
| OpenAI | `gpt-5.6-luna` | `OPENAI_API_KEY` |
| Anthropic | `claude-sonnet-5` | `ANTHROPIC_API_KEY` |

Specify a model explicitly in repeatable assessment workflows so a future default change cannot alter the selected model.

## OpenAI

Install:

```bash
uv sync --extra openai
```

Configure and run:

```bash
export REACT_RECON_AI_PROVIDER=openai
export REACT_RECON_AI_MODEL=gpt-5.6-luna
export OPENAI_API_KEY="..."

uv run react-recon run \
  --root-fqdn example.com \
  --mode active
```

The adapter uses the [Responses API](https://platform.openai.com/docs/api-reference/responses) with `store=False` and strict JSON Schema output.

## Anthropic

Install:

```bash
uv sync --extra anthropic
```

Configure and run:

```bash
export REACT_RECON_AI_PROVIDER=anthropic
export REACT_RECON_AI_MODEL=claude-sonnet-5
export ANTHROPIC_API_KEY="..."

uv run react-recon run \
  --root-fqdn example.com \
  --mode active
```

The adapter uses the [Messages API](https://platform.claude.com/docs/en/api/python/messages/create) and [`output_config.format` structured output](https://platform.claude.com/docs/en/build-with-claude/structured-outputs). The Anthropic SDK transforms unsupported schema constraints for constrained decoding; react-recon independently enforces the complete contract afterward.

## Installing both

```bash
uv sync --extra all-models
```

Installing both providers does not send data to either one. An active hybrid `run` contacts the selected provider for bounded planning and final analysis; a passive `run` contacts it only for final analysis. Standalone `analyze` also contacts the selected provider. Use `--planning-mode deterministic --collection-only` for collection without a model API request.

## Planning data boundary

The active planner receives the root FQDN, remaining budgets, short coverage-gap labels, previous adaptive outcomes, and at most 50 compact action cards. Cards may contain authorized hostnames, response classifications, status codes, deterministic signal labels, and an observed open port. They do not contain raw tool output, evidence paths, API keys, arbitrary local files, or executable command arguments.

Provider or schema failure records an adaptive stop event and immediately hands control to deterministic fallback. It does not prevent the remaining authorized collection stages from running. A failure during the later analyst brief still produces both reports with the failed analysis attempt identified.

An active hybrid run makes at most three planning requests, followed by one
separate final-analysis request. A planner may finish early, so the actual
number can be lower. Provider usage and cost therefore depend on the selected
model, catalog size, and whether the planner stops before its action limit.

## Adding another provider

A structured provider transport must expose:

```text
provider: string
model: string
generate(instructions, payload, schema, schema_name, description, max_tokens) -> object
```

The transport is responsible only for translating the canonical structured request and response. It must not perform reconnaissance, mutate run evidence, weaken candidate/fact validation, or add provider-specific fields to the report contracts.
