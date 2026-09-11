"""DeepSeek Responses API adapter with strict JSON Schema output."""

from __future__ import annotations

import json
from typing import Any, TypeVar

from pydantic import BaseModel, ValidationError

from app.analyzers.tracing.agents.llm.base import LLMResponseError
from app.analyzers.tracing.agents.llm.real_client import RealLLMClient

T = TypeVar("T", bound=BaseModel)


class DeepSeekClient(RealLLMClient):
    def _endpoint(self) -> str:
        return f"{self.settings.base_url.rstrip('/')}/responses"

    def _build_payload(
        self, system_prompt: str, input_json: str, response_model: type[T]
    ) -> dict[str, Any]:
        return {
            "model": self.settings.model,
            "instructions": system_prompt,
            "input": input_json,
            "text": {
                "format": {
                    "type": "json_schema",
                    "name": response_model.__name__,
                    "schema": response_model.model_json_schema(),
                }
            },
            "stream": False,
        }

    @staticmethod
    def _parse(raw: bytes, response_model: type[T]) -> dict[str, Any]:
        if not raw:
            raise LLMResponseError("provider returned an empty response")
        try:
            envelope = json.loads(raw.decode("utf-8"))
            if envelope.get("status") != "completed":
                raise LLMResponseError("DeepSeek response did not complete")
            texts = [
                part["text"]
                for item in envelope.get("output", [])
                if item.get("type") == "message"
                for part in item.get("content", [])
                if part.get("type") == "output_text" and part.get("text")
            ]
            if not texts:
                raise LLMResponseError("DeepSeek returned no output_text")
            validated = response_model.model_validate(json.loads(texts[-1]))
        except LLMResponseError:
            raise
        except (UnicodeDecodeError, json.JSONDecodeError, KeyError, TypeError) as exc:
            raise LLMResponseError("provider returned invalid structured JSON") from exc
        except ValidationError as exc:
            raise LLMResponseError("provider response failed schema validation") from exc
        return validated.model_dump(mode="json")
