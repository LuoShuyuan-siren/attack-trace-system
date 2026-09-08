"""OpenAI-compatible structured-output adapter using the Python standard library."""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Callable, TypeVar
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from pydantic import BaseModel, ValidationError

from app.analyzers.tracing.agents.llm.base import (
    LLMAdapterError,
    LLMAuthenticationError,
    LLMContextSizeError,
    LLMRateLimitError,
    LLMResponseError,
    LLMServerError,
    LLMSettings,
)

T = TypeVar("T", bound=BaseModel)
Transport = Callable[[str, dict[str, str], bytes, float], tuple[int, dict[str, str], bytes]]
logger = logging.getLogger(__name__)


def urllib_transport(
    url: str, headers: dict[str, str], body: bytes, timeout: float
) -> tuple[int, dict[str, str], bytes]:
    request = Request(url, data=body, headers=headers, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:
            return response.status, dict(response.headers.items()), response.read()
    except HTTPError as exc:
        return exc.code, dict(exc.headers.items()) if exc.headers else {}, exc.read()
    except (TimeoutError, URLError) as exc:
        raise LLMAdapterError(f"transport failure: {type(exc).__name__}") from exc


class RealLLMClient:
    def __init__(
        self,
        settings: LLMSettings,
        *,
        transport: Transport = urllib_transport,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        self.settings = settings
        self.transport = transport
        self.sleeper = sleeper

    def generate_structured(
        self,
        *,
        system_prompt: str,
        input_data: dict[str, Any],
        response_model: type[T],
    ) -> dict[str, Any]:
        input_json = json.dumps(input_data, ensure_ascii=False, separators=(",", ":"))
        if len(input_json.encode("utf-8")) > self.settings.max_input_bytes:
            raise LLMContextSizeError("structured input exceeds configured size limit")
        payload = self._build_payload(system_prompt, input_json, response_model)
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        url = self._endpoint()
        headers = {
            "Authorization": f"Bearer {self.settings.api_key}",
            "Content-Type": "application/json",
        }
        started = time.perf_counter()
        for attempt in range(self.settings.max_retries + 1):
            try:
                status, response_headers, raw = self.transport(
                    url, headers, body, self.settings.timeout
                )
                request_id = response_headers.get("x-request-id", "")
                if status in {401, 403}:
                    raise LLMAuthenticationError(f"authentication failed with HTTP {status}")
                if status == 429:
                    error: LLMAdapterError = LLMRateLimitError("rate limited with HTTP 429")
                elif 500 <= status <= 599:
                    error = LLMServerError(f"provider failed with HTTP {status}")
                elif not 200 <= status <= 299:
                    raise LLMAdapterError(f"provider returned HTTP {status}")
                else:
                    result = self._parse(raw, response_model)
                    self._log(True, request_id, started, attempt, "")
                    return result
                if attempt >= self.settings.max_retries:
                    raise error
                self.sleeper(min(2**attempt, 8))
            except LLMAuthenticationError:
                self._log(False, "", started, attempt, "authentication")
                raise
            except (LLMRateLimitError, LLMServerError):
                self._log(False, "", started, attempt, "retry_exhausted")
                raise
            except LLMAdapterError:
                self._log(False, "", started, attempt, "adapter_error")
                raise
            except Exception as exc:
                self._log(False, "", started, attempt, type(exc).__name__)
                raise LLMAdapterError(f"provider SDK/transport exception: {type(exc).__name__}") from exc
        raise LLMAdapterError("unreachable retry state")

    def _endpoint(self) -> str:
        return f"{self.settings.base_url.rstrip('/')}/chat/completions"

    def _build_payload(
        self,
        system_prompt: str, input_json: str, response_model: type[T]
    ) -> dict[str, Any]:
        return {
            "model": self.settings.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": input_json},
            ],
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": response_model.__name__,
                    "strict": True,
                    "schema": response_model.model_json_schema(),
                },
            },
        }

    @staticmethod
    def _parse(raw: bytes, response_model: type[T]) -> dict[str, Any]:
        if not raw:
            raise LLMResponseError("provider returned an empty response")
        try:
            envelope = json.loads(raw.decode("utf-8"))
            content = envelope["choices"][0]["message"]["content"]
            value = json.loads(content) if isinstance(content, str) else content
            validated = response_model.model_validate(value)
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise LLMResponseError("provider returned invalid structured JSON") from exc
        except ValidationError as exc:
            raise LLMResponseError("provider response failed schema validation") from exc
        return validated.model_dump(mode="json")

    def _log(
        self, success: bool, request_id: str, started: float, retry_count: int, error_type: str
    ) -> None:
        logger.info(
            "llm_request provider=%s model=%s request_id=%s latency_ms=%d retries=%d success=%s error_type=%s",
            self.settings.provider,
            self.settings.model,
            request_id,
            int((time.perf_counter() - started) * 1000),
            retry_count,
            success,
            error_type,
        )
