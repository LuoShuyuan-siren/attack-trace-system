"""Aggregate mapped detections into a compact TTP profile."""

from __future__ import annotations

from collections import Counter
from typing import Iterable

from .models import AttackMappingResult, TTPProfile
from .registry import TACTICS


TACTIC_ORDER = (
    "TA0001",
    "TA0002",
    "TA0003",
    "TA0004",
    "TA0005",
    "TA0006",
    "TA0007",
    "TA0008",
    "TA0009",
    "TA0010",
    "TA0011",
    "TA0040",
)


def build_ttp_profile(
    mappings: Iterable[AttackMappingResult],
) -> TTPProfile:
    technique_counter: Counter[str] = Counter()
    tactic_counter: Counter[str] = Counter()
    tag_counter: Counter[str] = Counter()
    confidence_sum = 0.0
    confidence_count = 0

    for mapping in mappings:
        if mapping.technique_id != "unknown":
            technique_counter[mapping.technique_id] += 1
        for tactic in mapping.tactics:
            tactic_counter[tactic.tactic_id] += 1
        for tag in mapping.ttp_tags:
            tag_counter[tag] += 1
        confidence_sum += mapping.confidence
        confidence_count += 1

    ordered_techniques = tuple(
        technique_id
        for technique_id, _ in technique_counter.most_common()
        if technique_id != "unknown"
    )
    ordered_tactics = tuple(
        tactic_id
        for tactic_id in sorted(
            tactic_counter,
            key=lambda tactic_id: _tactic_order(tactic_id),
        )
    )
    ordered_tags = tuple(tag for tag, _ in tag_counter.most_common())
    average_confidence = round(confidence_sum / confidence_count, 4) if confidence_count else 0.0

    return TTPProfile(
        technique_ids=ordered_techniques,
        tactic_ids=ordered_tactics,
        tags=ordered_tags,
        confidence=average_confidence,
        stage_count=len(ordered_tactics),
    )


def _tactic_order(tactic_id: str) -> int:
    if tactic_id in TACTIC_ORDER:
        return TACTIC_ORDER.index(tactic_id)
    if tactic_id in TACTICS:
        return len(TACTIC_ORDER)
    return len(TACTIC_ORDER) + 1
