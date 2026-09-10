from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Detection:
    detection_id: str
    timestamp: str
    analyzer: str = "generic_analyzer"
    detection_type: str = "suspicious_behavior"
    title: str = ""
    description: str | None = None
    severity: str = "medium"
    confidence: float = 0.8
    related_event_ids: list[str] = field(default_factory=list)
    related_entity_ids: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    attack_technique_id: str | None = None
    tags: list[str] = field(default_factory=list)


def detection(
    detection_id: str = "det-1",
    timestamp: str = "2026-09-08T10:00:00Z",
    **overrides: Any,
) -> Detection:
    values: dict[str, Any] = {
        "detection_id": detection_id,
        "timestamp": timestamp,
    }
    values.update(overrides)
    return Detection(**values)
