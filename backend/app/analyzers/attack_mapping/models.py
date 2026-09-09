"""Member 6 local data models.

These types are intentionally independent from the shared ``schemas/`` module.
The mapper consumes any object that provides the fields declared by the project
API for ``DetectionResult``, so it can be wired to the real Pydantic schema
without changing the public contract.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol


class DetectionResultLike(Protocol):
    detection_id: str
    timestamp: str | datetime
    analyzer: str
    detection_type: str
    title: str
    description: str | None
    severity: str
    confidence: float
    related_event_ids: list[str]
    related_entity_ids: list[str]
    evidence: dict[str, Any]
    attack_technique_id: str | None
    tags: list[str]


@dataclass(frozen=True)
class TacticRef:
    tactic_id: str
    tactic_name: str
    stage: str


@dataclass(frozen=True)
class TechniqueRef:
    technique_id: str
    technique_name: str


@dataclass(frozen=True)
class RuleMatch:
    rule_id: str
    technique_id: str
    tactic_ids: tuple[str, ...] = ()
    ttp_tags: tuple[str, ...] = ()
    confidence_adjustment: float = 0.0


@dataclass(frozen=True)
class AttackMappingResult:
    detection_id: str
    timestamp: str
    analyzer: str
    technique_id: str
    technique_name: str
    tactics: tuple[TacticRef, ...] = ()
    mapping_source: str = "none"
    matched_rule_ids: tuple[str, ...] = ()
    ttp_tags: tuple[str, ...] = ()
    confidence: float = 0.0
    related_entity_ids: tuple[str, ...] = ()
    evidence: dict[str, Any] = field(default_factory=dict)
    notes: tuple[str, ...] = ()

    @property
    def primary_tactic_id(self) -> str:
        return self.tactics[0].tactic_id if self.tactics else ""

    @property
    def primary_tactic_name(self) -> str:
        return self.tactics[0].tactic_name if self.tactics else ""

    @property
    def stages(self) -> tuple[str, ...]:
        return tuple(tactic.stage for tactic in self.tactics)

    @property
    def hosts(self) -> tuple[str, ...]:
        return tuple(
            entity.split(":", 1)[1]
            for entity in self.related_entity_ids
            if entity.startswith("host:")
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "detection_id": self.detection_id,
            "timestamp": self.timestamp,
            "analyzer": self.analyzer,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactics": [
                {
                    "tactic_id": tactic.tactic_id,
                    "tactic_name": tactic.tactic_name,
                    "stage": tactic.stage,
                }
                for tactic in self.tactics
            ],
            "mapping_source": self.mapping_source,
            "matched_rule_ids": list(self.matched_rule_ids),
            "ttp_tags": list(self.ttp_tags),
            "confidence": self.confidence,
            "related_entity_ids": list(self.related_entity_ids),
            "evidence": self.evidence,
            "notes": list(self.notes),
        }


@dataclass(frozen=True)
class AttackStage:
    stage: str
    tactic_id: str
    tactic_name: str
    detection_id: str
    technique_id: str
    technique_name: str
    timestamp: str
    host: str | None
    confidence: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "stage": self.stage,
            "tactic_id": self.tactic_id,
            "tactic_name": self.tactic_name,
            "detection_id": self.detection_id,
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "timestamp": self.timestamp,
            "host": self.host,
            "confidence": self.confidence,
        }


@dataclass(frozen=True)
class TTPProfile:
    technique_ids: tuple[str, ...]
    tactic_ids: tuple[str, ...]
    tags: tuple[str, ...]
    confidence: float
    stage_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_ids": list(self.technique_ids),
            "tactic_ids": list(self.tactic_ids),
            "tags": list(self.tags),
            "confidence": self.confidence,
            "stage_count": self.stage_count,
        }
