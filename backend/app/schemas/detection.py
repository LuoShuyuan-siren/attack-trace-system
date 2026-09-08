from datetime import datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


DetectionType = Literal[
    "anomaly",
    "suspicious_behavior",
    "malicious_behavior",
    "policy_violation",
]


SeverityLevel = Literal[
    "info",
    "low",
    "medium",
    "high",
    "critical",
]


class DetectionResult(BaseModel):
    """统一安全检测结果"""

    detection_id: str = Field(
        default_factory=lambda: f"det-{uuid4()}"
    )

    timestamp: datetime

    analyzer: str

    detection_type: DetectionType

    title: str

    description: str | None = None

    severity: SeverityLevel = "medium"

    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

    related_event_ids: list[str] = Field(default_factory=list)

    related_entity_ids: list[str] = Field(default_factory=list)

    evidence: dict[str, Any] = Field(default_factory=dict)

    attack_technique_id: str | None = None

    tags: list[str] = Field(default_factory=list)