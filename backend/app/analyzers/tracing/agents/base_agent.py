"""LLM abstraction and common agent validation."""

from __future__ import annotations

from typing import Any, Protocol, TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


class LLMClient(Protocol):
    def generate_structured(
        self,
        *,
        system_prompt: str,
        input_data: dict[str, Any],
        response_model: type[T],
    ) -> dict[str, Any]: ...


class AgentValidationError(ValueError):
    pass


def validate_subset(values: list[str], allowed: set[str], label: str) -> None:
    unknown = set(values).difference(allowed)
    if unknown:
        raise AgentValidationError(f"{label} contains unknown values: {sorted(unknown)}")
