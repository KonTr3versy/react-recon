# Model providers

The reconnaissance controller is model-independent. Model providers are used only by the post-run `analyze` command and cannot invoke collection tools or create evidence.

Both adapters receive the same normalized profiles and JSON Schema. Their output passes through the same deterministic host, fact-ID, target-count, rank, and unsupported-claim validation before it is saved.

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

uv run react-recon analyze RUN_ID --max-targets 8
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

uv run react-recon analyze RUN_ID --max-targets 8
```

The adapter uses the [Messages API](https://platform.claude.com/docs/en/api/python/messages/create) and [`output_config.format` structured output](https://platform.claude.com/docs/en/build-with-claude/structured-outputs). The Anthropic SDK transforms unsupported schema constraints for constrained decoding; react-recon independently enforces the complete contract afterward.

## Installing both

```bash
uv sync --extra all-models
```

Installing both providers does not send data to either one. Only an explicit `analyze` command contacts the selected provider.

## Adding another provider

A provider must expose:

```text
provider: string
model: string
analyze(payload, max_targets) -> object
```

The adapter is responsible only for translating the canonical request and structured response. It must not perform reconnaissance, mutate run evidence, weaken validation, or add provider-specific fields to the report contract.
