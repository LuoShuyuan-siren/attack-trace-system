"""Environment-driven LLM client factory."""

from __future__ import annotations

import logging
import os

from app.analyzers.tracing.agents.base_agent import LLMClient
from app.analyzers.tracing.agents.llm.base import LLMSettings
from app.analyzers.tracing.agents.llm.deepseek_client import DeepSeekClient
from app.analyzers.tracing.agents.llm.real_client import RealLLMClient

logger = logging.getLogger(__name__)
DEFAULT_BASE_URL = "https://api.openai.com/v1"


def create_llm_client(env: dict[str, str] | None = None) -> LLMClient | None:
    values = os.environ if env is None else env
    if values.get("LLM_ENABLED", "false").strip().lower() not in {"1", "true", "yes", "on"}:
        return None
    provider = values.get("LLM_PROVIDER", "").strip()
    api_key = values.get("LLM_API_KEY", "").strip()
    model = values.get("LLM_MODEL", "").strip()
    if not provider or not api_key or not model:
        logger.warning(
            "llm_disabled reason=incomplete_configuration provider_set=%s model_set=%s key_set=%s",
            bool(provider), bool(model), bool(api_key),
        )
        return None
    if provider not in {"openai_compatible", "deepseek"}:
        logger.warning("llm_disabled reason=unsupported_provider provider=%s", provider)
        return None
    try:
        timeout = max(0.1, float(values.get("LLM_TIMEOUT", "30")))
        retries = min(5, max(0, int(values.get("LLM_MAX_RETRIES", "2"))))
    except ValueError:
        logger.warning("llm_disabled reason=invalid_numeric_configuration")
        return None
    default_base_url = (
        "https://api.deepseek.com" if provider == "deepseek" else DEFAULT_BASE_URL
    )
    settings = LLMSettings(
        provider=provider, api_key=api_key, model=model,
        base_url=values.get("LLM_BASE_URL", default_base_url).strip() or default_base_url,
        timeout=timeout, max_retries=retries,
    )
    return DeepSeekClient(settings) if provider == "deepseek" else RealLLMClient(settings)
