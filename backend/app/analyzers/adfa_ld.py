"""Course-level evaluator for raw ADFA-LD syscall sequences."""

from __future__ import annotations

from dataclasses import dataclass
from math import log1p, sqrt
from pathlib import Path
from statistics import mean, pstdev

from app.schemas.detection import DetectionResult


@dataclass(frozen=True)
class AdfaSample:
    path: Path
    label: str
    syscalls: tuple[int, ...]


@dataclass(frozen=True)
class AdfaBaseline:
    feature_mean: tuple[float, ...]
    feature_std: tuple[float, ...]


def load_sample(path: Path, label: str | None = None) -> AdfaSample:
    try:
        values = tuple(int(value) for value in path.read_text(encoding="utf-8").split())
    except (OSError, ValueError) as exc:
        raise ValueError(f"ADFA-LD 样本无法读取: {path}") from exc
    if not values:
        raise ValueError(f"ADFA-LD 样本为空: {path}")
    return AdfaSample(path=path, label=label or path.parent.name, syscalls=values)


def extract_features(sample: AdfaSample, vocabulary: tuple[int, ...]) -> tuple[float, ...]:
    counts = {value: 0 for value in vocabulary}
    for syscall in sample.syscalls:
        if syscall in counts:
            counts[syscall] += 1
    total = len(sample.syscalls)
    histogram = [count / total for count in counts.values()]
    transitions = sum(
        left != right
        for left, right in zip(sample.syscalls, sample.syscalls[1:])
    ) / max(1, total - 1)
    return tuple([*histogram, log1p(total), len(set(sample.syscalls)) / total, transitions])


def build_baseline(samples: list[AdfaSample], vocabulary: tuple[int, ...]) -> AdfaBaseline:
    if not samples:
        raise ValueError("至少需要一个正常 ADFA-LD 样本")
    vectors = [extract_features(sample, vocabulary) for sample in samples]
    width = len(vectors[0])
    return AdfaBaseline(
        feature_mean=tuple(mean(vector[index] for vector in vectors) for index in range(width)),
        feature_std=tuple(pstdev(vector[index] for vector in vectors) for index in range(width)),
    )


def anomaly_score(sample: AdfaSample, baseline: AdfaBaseline, vocabulary: tuple[int, ...]) -> float:
    vector = extract_features(sample, vocabulary)
    z_scores = [
        abs(value - expected) / max(deviation, 0.001)
        for value, expected, deviation in zip(vector, baseline.feature_mean, baseline.feature_std)
    ]
    return sum(sorted(z_scores, reverse=True)[:5]) / min(5, len(z_scores))


def severity_for_score(score: float, threshold: float) -> str:
    """Convert a threshold-relative anomaly score into the shared severity levels."""
    ratio = score / max(threshold, 0.001)
    if ratio >= 2.0:
        return "critical"
    if ratio >= 1.5:
        return "high"
    if ratio >= 1.2:
        return "medium"
    return "low"


def build_detection(
    sample: AdfaSample,
    score: float,
    threshold: float,
    event_ids: list[str],
) -> DetectionResult:
    return DetectionResult(
        detection_id=f"det-adfa-{sample.path.parent.name}-{sample.path.stem}",
        timestamp="2026-01-01T00:00:00Z",
        analyzer="adfa_ld_sequence_analyzer",
        detection_type="anomaly",
        title="ADFA-LD syscall sequence anomaly",
        description=(
            f"The syscall sequence differs from the normal ADFA-LD baseline "
            f"(score={score:.3f}, threshold={threshold:.3f})."
        ),
        severity=severity_for_score(score, threshold),
        confidence=min(0.99, max(0.5, score / max(threshold * 2, 1.0))),
        related_event_ids=event_ids,
        related_entity_ids=[
            f"host:{sample.label}",
            f"process:{sample.label}:1000",
        ],
        evidence={
            "dataset": "ADFA-LD",
            "sample": str(sample.path),
            "label": sample.label,
            "sequence_length": len(sample.syscalls),
            "anomaly_score": round(score, 4),
            "threshold": threshold,
            "matched_conditions": ["sequence_baseline_deviation"],
        },
        tags=["adfa-ld", "sequence-anomaly", "host_behavior"],
    )


def choose_threshold(scores: list[float], percentile: float = 0.99) -> float:
    if not scores:
        return 0.0
    ordered = sorted(scores)
    index = min(len(ordered) - 1, max(0, int(len(ordered) * percentile)))
    return max(1.0, ordered[index])