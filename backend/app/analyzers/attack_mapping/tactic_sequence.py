"""Build an ordered attack-stage timeline from mapped detections."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Iterable

from .mapper import AttackMapper
from .models import AttackMappingResult, AttackStage, DetectionResultLike


def map_and_build_stages(
    detections: Iterable[DetectionResultLike],
    mapper: AttackMapper | None = None,
    *,
    deduplicate: bool = True,
) -> list[AttackStage]:
    effective_mapper = mapper or AttackMapper()
    return build_attack_stages(
        effective_mapper.map_many(detections),
        deduplicate=deduplicate,
    )


def build_attack_stages(
    mappings: Iterable[AttackMappingResult],
    *,
    deduplicate: bool = True,
) -> list[AttackStage]:
    ordered = sorted(mappings, key=lambda mapping: _timestamp_sort_key(mapping.timestamp))
    stages: list[AttackStage] = []

    for mapping in ordered:
        host = mapping.hosts[0] if mapping.hosts else None
        for tactic in mapping.tactics:
            stage = AttackStage(
                stage=tactic.stage,
                tactic_id=tactic.tactic_id,
                tactic_name=tactic.tactic_name,
                detection_id=mapping.detection_id,
                technique_id=mapping.technique_id,
                technique_name=mapping.technique_name,
                timestamp=mapping.timestamp,
                host=host,
                confidence=mapping.confidence,
            )
            if deduplicate and _is_duplicate_stage(stages, stage):
                continue
            stages.append(stage)

    return stages


def _is_duplicate_stage(
    stages: list[AttackStage],
    stage: AttackStage,
) -> bool:
    if not stages:
        return False
    previous = stages[-1]
    return (
        previous.stage == stage.stage
        and previous.technique_id == stage.technique_id
        and previous.host == stage.host
    )


def _timestamp_sort_key(value: str | datetime) -> float:
    parsed = _parse_timestamp(value)
    if parsed is not None:
        return parsed.timestamp()
    return float("inf")


def _parse_timestamp(value: str | datetime) -> datetime | None:
    if not value:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(normalized)
    except ValueError:
        return None
