"""Map Member 5 traffic DetectionResult records to ATT&CK technique IDs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.schemas.detection import DetectionResult

from app.analyzers.attack_mapping.registry import (
    TACTICS,
    stage_for_tactic,
    tactic_name,
    tactics_for_technique,
    technique_name,
)


EXAMPLES_DIR = Path(__file__).resolve().parent
INPUT_FILE = EXAMPLES_DIR / "member5_traffic_sample_data.json"
MAPPED_DETECTIONS_FILE = EXAMPLES_DIR / "member5_traffic_mapped_detections.json"
MAPPED_PACKAGE_FILE = EXAMPLES_DIR / "member5_traffic_mapped_package.json"
SUMMARY_FILE = EXAMPLES_DIR / "member5_traffic_mapping_summary.json"


def main() -> None:
    source = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
    raw_detections = source["detection_results"]
    mapped_detections = [map_detection(item) for item in raw_detections]
    package = {
        "normalized_events": source.get("normalized_events", []),
        "detection_results": [item.model_dump(mode="json") for item in mapped_detections],
    }
    mapped_null_techniques = sum(
        1
        for item, detection in zip(raw_detections, mapped_detections)
        if item.get("attack_technique_id") is None
    )
    preserved_existing_techniques = sum(
        1 for item in raw_detections if item.get("attack_technique_id") is not None
    )
    summary = {
        "total_detections": len(mapped_detections),
        "mapped_null_techniques": mapped_null_techniques,
        "preserved_existing_techniques": preserved_existing_techniques,
        "mappings": [
            {
                "detection_id": detection.detection_id,
                "analyzer": detection.analyzer,
                "title": detection.title,
                "technique_id": detection.attack_technique_id,
                "technique_name": technique_name(detection.attack_technique_id),
                "tactics": [
                    {
                        "tactic_id": tactic_id,
                        "tactic_name": tactic_name(tactic_id),
                        "stage": stage_for_tactic(tactic_id),
                    }
                    for tactic_id in tactics_for_technique(detection.attack_technique_id)
                ],
            }
            for detection in mapped_detections
        ],
    }

    MAPPED_DETECTIONS_FILE.write_text(
        json.dumps(
            [item.model_dump(mode="json") for item in mapped_detections],
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    MAPPED_PACKAGE_FILE.write_text(
        json.dumps(package, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    SUMMARY_FILE.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(
        f"total={len(mapped_detections)} "
        f"mapped={summary['mapped_null_techniques']} "
        f"preserved={summary['preserved_existing_techniques']}"
    )


def map_detection(item: dict[str, Any]) -> DetectionResult:
    technique_id = resolve_technique_id(item)
    mapping_tags = _mapping_tags(technique_id)
    original_tags = list(item.get("tags", []))

    return DetectionResult(
        detection_id=item["detection_id"],
        timestamp=item["timestamp"],
        analyzer=item["analyzer"],
        detection_type=item["detection_type"],
        title=item["title"],
        description=item["description"],
        severity=item["severity"],
        confidence=item["confidence"],
        related_event_ids=item.get("related_event_ids", []),
        related_entity_ids=item.get("related_entity_ids", []),
        evidence=item.get("evidence", {}),
        attack_technique_id=technique_id,
        tags=_deduplicate(original_tags + mapping_tags),
    )


def resolve_technique_id(item: dict[str, Any]) -> str:
    existing = item.get("attack_technique_id")
    if existing:
        return existing

    tags = set(item.get("tags", []))
    if "uncommon_port" in tags:
        return "T1046"
    if "dns" in tags:
        return "T1071.004"
    if "icmp" in tags:
        return "T1095"
    if "http" in tags or "connection" in tags:
        return "T1071.001"
    return "unknown"


def _mapping_tags(technique_id: str) -> list[str]:
    if technique_id == "unknown":
        return ["attack_technique:unknown"]

    tags = [f"attack_technique:{technique_id}"]
    for tactic_id in tactics_for_technique(technique_id):
        if tactic_id not in TACTICS:
            continue
        tags.extend(
            [
                f"attack_tactic:{tactic_id}",
                f"attack_stage:{stage_for_tactic(tactic_id)}",
            ]
        )
    return tags


def _deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


if __name__ == "__main__":
    main()
