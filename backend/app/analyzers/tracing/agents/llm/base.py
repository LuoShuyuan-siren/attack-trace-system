"""Provider-neutral LLM configuration and errors."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class LLMSettings:
    provider: str
    api_key: str
    model: str
    base_url: str
    timeout: float = 30.0
    max_retries: int = 2
    max_input_bytes: int = 131_072


class LLMAdapterError(RuntimeError):
    """Safe, provider-neutral error surfaced to the agent fallback layer."""


class LLMAuthenticationError(LLMAdapterError):
    pass


class LLMRateLimitError(LLMAdapterError):
    pass


class LLMServerError(LLMAdapterError):
    pass


class LLMResponseError(LLMAdapterError):
    pass


class LLMContextSizeError(LLMAdapterError):
    pass
