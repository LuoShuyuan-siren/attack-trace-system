"""Evaluate ADFA-LD through the project's detection and tracing pipeline."""

from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.analyzers.adfa_ld import (
    AdfaSample,
    anomaly_score,
    build_baseline,
    build_detection,
    choose_threshold,
    load_sample,
)
from app.analyzers.tracing import AttackTraceService
from app.services.attack_mapping_service import map_detections
from app.schemas.event import HostInfo, NormalizedEvent, SubjectInfo


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ADFA-LD syscall sequences")
    parser.add_argument("--dataset", default="ADFA-LD")
    parser.add_argument("--output", default="backend/examples/adfa_ld_evaluation.json")
    parser.add_argument("--max-normal", type=int, default=0)
    parser.add_argument("--max-attack", type=int, default=0)
    args = parser.parse_args()

    result, _events, _detections, _mappings = evaluate_dataset(
        Path(args.dataset),
        max_normal=args.max_normal,
        max_attack=args.max_attack,
    )
    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps(result, ensure_ascii=False, indent=2))


def evaluate_dataset(
    root: Path,
    *,
    max_normal: int = 0,
    max_attack: int = 0,
) -> tuple[dict[str, object], list[NormalizedEvent], list, list]:
    normal_paths = sorted((root / "Training_Data_Master").glob("*.txt"))
    attack_paths = sorted((root / "Attack_Data_Master").glob("*/*.txt"))
    if max_normal:
        normal_paths = normal_paths[:max_normal]
    if max_attack:
        attack_paths = attack_paths[:max_attack]

    normal = [load_sample(path, "normal") for path in normal_paths]
    attacks = [load_sample(path) for path in attack_paths]
    vocabulary = tuple(sorted({syscall for sample in normal for syscall in sample.syscalls}))
    baseline = build_baseline(normal, vocabulary)
    normal_scores = [anomaly_score(sample, baseline, vocabulary) for sample in normal]
    threshold = choose_threshold(normal_scores)

    attack_scores = [anomaly_score(sample, baseline, vocabulary) for sample in attacks]
    detections = [
        build_detection(
            sample,
            score,
            threshold,
            [f"adfa-{index}-{position}" for position in range(len(sample.syscalls))],
        )
        for index, (sample, score) in enumerate(zip(attacks, attack_scores))
        if score >= threshold
    ]

    _apply_dataset_context_mapping(detections)
    mappings = map_detections(detections)

    trace = AttackTraceService().analyze(
        _events_for_detections(detections),
        detections,
        graph_id="adfa-ld-evaluation",
    )
    by_label: dict[str, dict[str, int]] = {}
    for sample, score in zip(attacks, attack_scores):
        item = by_label.setdefault(sample.label, {"samples": 0, "detected": 0})
        item["samples"] += 1
        item["detected"] += int(score >= threshold)

    result = {
        "dataset": "ADFA-LD",
        "normal_samples": len(normal),
        "attack_samples": len(attacks),
        "syscall_vocabulary_size": len(vocabulary),
        "normal_score_max": round(max(normal_scores, default=0.0), 4),
        "threshold": round(threshold, 4),
        "normal_alert_count": sum(score >= threshold for score in normal_scores),
        "false_positive_rate": round(
            sum(score >= threshold for score in normal_scores) / max(1, len(normal_scores)),
            4,
        ),
        "detected_attack_samples": len(detections),
        "detection_rate": round(len(detections) / max(1, len(attacks)), 4),
        "by_attack_label": by_label,
        "detection_count": len(detections),
        "mapped_detection_count": sum(mapping.technique_id != "unknown" for mapping in mappings),
        "attack_techniques": sorted({mapping.technique_id for mapping in mappings if mapping.technique_id != "unknown"}),
        "attack_graph": {
            "nodes": len(trace["graph"].nodes),
            "edges": len(trace["graph"].edges),
            "stages": len(trace["stages"]),
            "paths": len(trace["paths"]),
        },
        "note": (
            "ADFA-LD samples are evaluated independently; categories are not combined into one attack chain. "
            "ATT&CK mappings use dataset-category context for course reporting and are not detection evidence."
        ),
    }
    return result, _events_for_detections(detections), detections, mappings


def _events_for_detections(detections) -> list[NormalizedEvent]:
    events: list[NormalizedEvent] = []
    for index, detection in enumerate(detections):
        timestamp = datetime.now(timezone.utc) + timedelta(milliseconds=index)
        events.append(NormalizedEvent(
            event_id=detection.related_event_ids[0],
            timestamp=timestamp,
            source_type="host_behavior",
            source="adfa-ld",
            host=HostInfo(hostname=str(detection.evidence.get("label", "adfa"))),
            event_type="system_call_sequence",
            subject=SubjectInfo(type="process", name="adfa-sequence", pid=index),
            action="sequence_anomaly",
            raw_data=detection.evidence,
            severity=detection.severity,
            tags=["adfa-ld"],
        ))
    return events


def _apply_dataset_context_mapping(detections) -> None:
    """Attach category context only after anomaly detection has fired."""
    techniques = {
        "Adduser": "T1136.001",
        "Hydra_FTP": "T1110.002",
        "Hydra_SSH": "T1110.001",
        "Java_Meterpreter": "T1219",
        "Meterpreter": "T1219",
        "Web_Shell": "T1505.003",
    }
    for detection in detections:
        label = str(detection.evidence.get("label", ""))
        category = "_".join(label.split("_")[:-1])
        technique_id = techniques.get(category)
        if technique_id:
            detection.attack_technique_id = technique_id
            detection.evidence["dataset_context_technique"] = technique_id


if __name__ == "__main__":
    main()