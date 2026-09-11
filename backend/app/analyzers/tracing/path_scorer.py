"""候选攻击路径的可解释综合评分。"""

from __future__ import annotations

from statistics import fmean

from app.analyzers.tracing.normalization import utc_datetime
from app.schemas.attack_graph import AttackEdge


STAGE_ORDER = {
    "initial_access": 0,
    "spawn": 1,
    "execute": 1,
    "privilege_escalation": 2,
    "lateral_movement": 3,
    "c2_communication": 4,
    "data_exfiltration": 5,
}
WEIGHTS = {
    "edge_confidence": 0.25,
    "evidence_completeness": 0.20,
    "temporal_continuity": 0.15,
    "entity_continuity": 0.15,
    "attack_sequence": 0.15,
    "stage_coverage": 0.10,
}


def score_edge_confidence(edges: list[AttackEdge]) -> float:
    return fmean(edge.confidence for edge in edges) if edges else 0.0


def score_evidence_completeness(edges: list[AttackEdge]) -> float:
    if not edges:
        return 0.0
    scores = []
    for edge in edges:
        score = 0.2 if edge.timestamp else 0.0
        score += 0.4 if edge.related_event_ids or edge.related_detection_ids else 0.0
        score += 0.2 if edge.attack_technique_id else 0.0
        score += 0.2 if edge.attributes else 0.0
        scores.append(score)
    return fmean(scores)


def score_temporal_continuity(edges: list[AttackEdge]) -> float:
    if len(edges) < 2:
        return 1.0
    scores = []
    for previous, current in zip(edges, edges[1:]):
        if previous.timestamp is None or current.timestamp is None:
            scores.append(0.5)
            continue
        seconds = (utc_datetime(current.timestamp) - utc_datetime(previous.timestamp)).total_seconds()
        if seconds < 0:
            scores.append(0.0)
        elif seconds <= 1800:
            scores.append(1.0)
        else:
            scores.append(max(0.0, 1.0 - (seconds - 1800) / 12600))
    return fmean(scores)


def score_entity_continuity(edges: list[AttackEdge]) -> float:
    if len(edges) < 2:
        return 1.0
    return fmean(
        1.0 if previous.target == current.source else 0.0
        for previous, current in zip(edges, edges[1:])
    )


def score_attack_sequence(edges: list[AttackEdge]) -> float:
    stages = [STAGE_ORDER[edge.relation] for edge in edges if edge.relation in STAGE_ORDER]
    if len(stages) < 2:
        return 1.0 if stages else 0.0
    return fmean(1.0 if current >= previous else 0.0 for previous, current in zip(stages, stages[1:]))


def score_stage_coverage(edges: list[AttackEdge]) -> float:
    stages = {STAGE_ORDER[edge.relation] for edge in edges if edge.relation in STAGE_ORDER}
    return len(stages) / 6


def calculate_path_score(edges: list[AttackEdge]) -> tuple[float, dict[str, float]]:
    breakdown = {
        "edge_confidence": score_edge_confidence(edges),
        "evidence_completeness": score_evidence_completeness(edges),
        "temporal_continuity": score_temporal_continuity(edges),
        "entity_continuity": score_entity_continuity(edges),
        "attack_sequence": score_attack_sequence(edges),
        "stage_coverage": score_stage_coverage(edges),
    }
    rounded = {name: round(value, 4) for name, value in breakdown.items()}
    total = sum(breakdown[name] * WEIGHTS[name] for name in WEIGHTS)
    return round(max(0.0, min(1.0, total)), 4), rounded
