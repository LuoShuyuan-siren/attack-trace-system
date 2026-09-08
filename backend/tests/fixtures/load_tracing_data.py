import json
from pathlib import Path
from typing import TypeVar

from pydantic import BaseModel, ValidationError

from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent

T = TypeVar("T", bound=BaseModel)


def _load(path: Path, model: type[T]) -> list[T]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"{path}: cannot read valid JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise ValueError(f"{path}: expected a top-level JSON array")
    results = []
    for index, item in enumerate(payload):
        try:
            results.append(model.model_validate(item))
        except ValidationError as exc:
            raise ValueError(f"{path}: invalid item at index {index}: {exc}") from exc
    return results


def load_events(path: str | Path) -> list[NormalizedEvent]:
    return _load(Path(path), NormalizedEvent)


def load_detections(path: str | Path) -> list[DetectionResult]:
    return _load(Path(path), DetectionResult)
