from __future__ import annotations

import json
import os
from typing import Any, Dict, Optional, Protocol, Tuple


DEFAULT_MODELS = {
    "openai": "gpt-5.6-luna",
    "anthropic": "claude-sonnet-5",
}


class StructuredModel(Protocol):
    """Small provider-neutral boundary for strict JSON generation."""

    provider: str
    model: str

    def generate(
        self,
        *,
        instructions: str,
        payload: Dict[str, Any],
        schema: Dict[str, Any],
        schema_name: str,
        description: str,
        max_tokens: int = 8192,
    ) -> Dict[str, Any]: ...


def resolve_provider_model(
    provider: Optional[str] = None, model: Optional[str] = None
) -> Tuple[str, str]:
    selected = (
        provider or os.environ.get("REACT_RECON_AI_PROVIDER", "openai")
    ).strip().lower()
    if selected not in DEFAULT_MODELS:
        raise ValueError(
            f"unknown AI provider: {selected}; expected openai or anthropic"
        )
    if model:
        return selected, model
    shared = os.environ.get("REACT_RECON_AI_MODEL")
    if shared:
        return selected, shared
    legacy_name = "OPENAI_MODEL" if selected == "openai" else "ANTHROPIC_MODEL"
    return selected, os.environ.get(legacy_name, DEFAULT_MODELS[selected])


def redact_provider_error(error: BaseException) -> str:
    """Bound provider errors and remove configured credentials if echoed."""
    message = str(error)
    for name in ("OPENAI_API_KEY", "ANTHROPIC_API_KEY"):
        value = os.environ.get(name)
        if value:
            message = message.replace(value, "[REDACTED]")
    return message[:1000]


class OpenAIStructuredModel:
    provider = "openai"

    def __init__(self, model: Optional[str] = None, client: Any = None) -> None:
        _, self.model = resolve_provider_model(self.provider, model)
        self.client = client

    def generate(
        self,
        *,
        instructions: str,
        payload: Dict[str, Any],
        schema: Dict[str, Any],
        schema_name: str,
        description: str,
        max_tokens: int = 8192,
    ) -> Dict[str, Any]:
        # Lazy loading keeps deterministic and fixture-backed runs independent
        # of the OpenAI SDK and credentials.
        if self.client is None:
            try:
                from openai import OpenAI
            except ImportError as exc:
                raise RuntimeError(
                    "OpenAI SDK is required; install with: uv sync --extra openai"
                ) from exc
            self.client = OpenAI()
        response = self.client.responses.create(
            model=self.model,
            store=False,
            instructions=instructions,
            input=json.dumps(payload, sort_keys=True),
            text={
                "format": {
                    "type": "json_schema",
                    "name": schema_name,
                    "description": description,
                    "strict": True,
                    "schema": schema,
                },
                "verbosity": "low",
            },
        )
        if not response.output_text:
            raise RuntimeError("model returned no structured output")
        return json.loads(response.output_text)


class AnthropicStructuredModel:
    provider = "anthropic"

    def __init__(self, model: Optional[str] = None, client: Any = None) -> None:
        _, self.model = resolve_provider_model(self.provider, model)
        self.client = client

    def generate(
        self,
        *,
        instructions: str,
        payload: Dict[str, Any],
        schema: Dict[str, Any],
        schema_name: str,
        description: str,
        max_tokens: int = 8192,
    ) -> Dict[str, Any]:
        try:
            from anthropic import Anthropic, transform_schema
        except ImportError as exc:
            raise RuntimeError(
                "Anthropic SDK is required; install with: uv sync --extra anthropic"
            ) from exc
        if self.client is None:
            self.client = Anthropic()
        # The SDK removes constraints unsupported by Anthropic's decoder. The
        # controller still validates IDs, tools, bounds, and output types.
        transformed = transform_schema(schema)
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=instructions,
            messages=[
                {
                    "role": "user",
                    "content": json.dumps(payload, sort_keys=True),
                }
            ],
            output_config={
                "format": {"type": "json_schema", "schema": transformed}
            },
        )
        text_blocks = [
            block.text
            for block in response.content
            if getattr(block, "type", None) == "text"
        ]
        if not text_blocks:
            raise RuntimeError("model returned no structured output")
        return json.loads("".join(text_blocks))


def build_structured_model(
    provider: Optional[str] = None,
    model: Optional[str] = None,
    *,
    client: Any = None,
) -> StructuredModel:
    selected, resolved_model = resolve_provider_model(provider, model)
    if selected == "openai":
        return OpenAIStructuredModel(resolved_model, client=client)
    return AnthropicStructuredModel(resolved_model, client=client)
