"""Evaluate ADFA-LD through the project's detection and tracing pipeline."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

from dotenv import load_dotenv

load_dotenv(PROJECT_ROOT / "backend" / ".env")

from app.analyzers.adfa_ld import (
    AdfaSample,
    anomaly_score,
    build_baseline,
    build_detection,
    choose_threshold,
    load_sample,
)
from app.analyzers.tracing import AttackTraceService
from app.analyzers.tracing.agents import TraceAgentOrchestrator
from app.analyzers.tracing.agents.llm import create_llm_client
from app.services.attack_mapping_service import map_detections
from app.schemas.event import HostInfo, NormalizedEvent, SubjectInfo


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate ADFA-LD syscall sequences")
    parser.add_argument("--dataset", default="ADFA-LD")
    parser.add_argument("--output", default="backend/examples/adfa_ld_evaluation.json")
    parser.add_argument("--max-normal", type=int, default=0)
    parser.add_argument("--max-attack", type=int, default=0)
    parser.add_argument("--llm-top-k", type=int, default=5)
    parser.add_argument("--llm-max-edges", type=int, default=100)
    parser.add_argument("--llm-max-nodes", type=int, default=100)
    parser.add_argument(
        "--use-llm",
        action="store_true",
        help="Use the configured LLM to review the aggregated attack graph.",
    )
    args = parser.parse_args()

    result, _events, _detections, _mappings = evaluate_dataset(
        Path(args.dataset),
        max_normal=args.max_normal,
        max_attack=args.max_attack,
        use_llm=args.use_llm,
        llm_top_k=args.llm_top_k,
        llm_max_edges=args.llm_max_edges,
        llm_max_nodes=args.llm_max_nodes,
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
    use_llm: bool = False,
    llm_top_k: int = 5,
    llm_max_edges: int = 100,
    llm_max_nodes: int = 100,
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

    events = _events_for_detections(detections)
    llm_analysis: dict[str, object] = {}
    if use_llm:
        llm = create_llm_client()
        if llm is None:
            raise RuntimeError("LLM 配置不完整，无法执行 ADFA 大模型分析")
        agent_result = TraceAgentOrchestrator(
            llm=llm,
            enabled=True,
            top_k_paths=max(1, llm_top_k),
            max_edges=max(1, llm_max_edges),
            max_nodes=max(1, llm_max_nodes),
        ).analyze(
            events, detections, graph_id="adfa-ld-evaluation"
        )
        trace = agent_result["trace"]
        llm_analysis = {
            "agent_status": agent_result["agent_status"],
            "agent_analysis": agent_result["agent_analysis"],
        }
    else:
        trace = AttackTraceService().analyze(
            events, detections, graph_id="adfa-ld-evaluation"
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
        **llm_analysis,
        "note": (
            "ADFA-LD samples are evaluated independently; categories are not combined into one attack chain. "
            "ATT&CK mappings use dataset-category context for course reporting and are not detection evidence."
        ),
    }
    return result, events, detections, mappings


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