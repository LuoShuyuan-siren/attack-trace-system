"""Map DetectionResult-compatible objects to ATT&CK techniques and tactics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from .models import (
    AttackMappingResult,
    DetectionResultLike,
    RuleMatch,
    TacticRef,
)
from .registry import (
    TACTICS,
    TECHNIQUES,
    stage_for_tactic,
    tactic_name,
    technique_name,
)
from .rules import MappingRule, build_default_rules, match_detection


@dataclass(frozen=True)
class AttackMapper:
    rules: tuple[MappingRule, ...] = ()

    def __post_init__(self) -> None:
        if not self.rules:
            object.__setattr__(self, "rules", build_default_rules())

    def map_many(
        self,
        detections: Iterable[DetectionResultLike],
    ) -> list[AttackMappingResult]:
        return [self.map_one(detection) for detection in detections]

    def map_one(self, detection: DetectionResultLike) -> AttackMappingResult:
        timestamp = _normalize_timestamp(detection.timestamp)
        technique_id = _clean_technique_id(detection.attack_technique_id)
        matched_rules: list[RuleMatch] = []
        source = "none"
        notes: list[str] = []

        if technique_id in TECHNIQUES:
            source = "explicit"
            ttp_tags: tuple[str, ...] = ("explicit",)
        else:
            technique_id = ""
            matched_rules = match_detection(detection, self.rules)
            if matched_rules:
                best = matched_rules[0]
                technique_id = best.technique_id
                source = "rule"
                ttp_tags = best.ttp_tags
            else:
                ttp_tags = ()
                notes.append("no_matching_rule")

        tactic_ids = _resolve_tactic_ids(technique_id, matched_rules)
        tactics = _build_tactic_refs(tactic_ids)
        confidence = _bounded_confidence(
            detection.confidence,
            matched_rules[0].confidence_adjustment if matched_rules else 0.0,
        )

        if not technique_id:
            technique_id = "unknown"
            technique_name_value = "Unknown"
        else:
            technique_name_value = technique_name(technique_id)

        return AttackMappingResult(
            detection_id=detection.detection_id,
            timestamp=timestamp,
            analyzer=detection.analyzer,
            technique_id=technique_id,
            technique_name=technique_name_value,
            tactics=tactics,
            mapping_source=source,
            matched_rule_ids=tuple(match.rule_id for match in matched_rules),
            ttp_tags=tuple(dict.fromkeys((*ttp_tags, *tactics_stages(tactics)))),
            confidence=confidence,
            related_entity_ids=tuple(detection.related_entity_ids),
            evidence=dict(detection.evidence),
            notes=tuple(notes),
        )


def _clean_technique_id(value: str | None) -> str:
    if not value:
        return ""
    value = value.strip().upper()
    return value if value in TECHNIQUES else ""


def _normalize_timestamp(value: str | datetime) -> str:
    if isinstance(value, datetime):
        normalized = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return normalized.isoformat()
    return str(value)


def _resolve_tactic_ids(
    technique_id: str,
    matched_rules: list[RuleMatch],
) -> tuple[str, ...]:
    candidate_ids: tuple[str, ...] = ()
    if technique_id in TECHNIQUES:
        candidate_ids = TECHNIQUES[technique_id][1]
    if matched_rules and matched_rules[0].tactic_ids:
        candidate_ids = matched_rules[0].tactic_ids
    return tuple(dict.fromkeys(candidate_ids))


def _build_tactic_refs(tactic_ids: tuple[str, ...]) -> tuple[TacticRef, ...]:
    refs: list[TacticRef] = []
    for tactic_id in tactic_ids:
        if tactic_id not in TACTICS:
            continue
        refs.append(
            TacticRef(
                tactic_id=tactic_id,
                tactic_name=tactic_name(tactic_id),
                stage=stage_for_tactic(tactic_id),
            )
        )
    return tuple(refs)


def _bounded_confidence(base: float, adjustment: float) -> float:
    try:
        value = float(base) + float(adjustment)
    except (TypeError, ValueError):
        value = 0.0
    return round(max(0.0, min(1.0, value)), 4)


def tactics_stages(tactics: tuple[TacticRef, ...]) -> tuple[str, ...]:
    return tuple(tactic.stage for tactic in tactics)
