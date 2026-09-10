"""Internal rule result used by host-behavior analyzers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass(slots=True)
class RuleMatch:
    rule_id: str
    title: str
    description: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    confidence: float
    related_event_ids: list[str]
    related_entity_ids: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)
    detection_type: Literal[
        "anomaly",
        "suspicious_behavior",
        "malicious_behavior",
        "policy_violation",
    ] = "suspicious_behavior"
