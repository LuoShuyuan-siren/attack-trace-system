"""Map Member 4 real host-behavior detections to ATT&CK technique IDs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.analyzers.attack_mapping.registry import (
    TACTICS,
    stage_for_tactic,
    tactic_name,
    tactics_for_technique,
    technique_name,
)
from app.schemas.detection import DetectionResult


EXAMPLES_DIR = Path(__file__).resolve().parent
INPUT_FILE = EXAMPLES_DIR / "member4_host_behavior_real_detections.json"
SUMMARY_FILE = EXAMPLES_DIR / "member4_host_behavior_real_summary.json"
OUTPUT_FILE = EXAMPLES_DIR / "member4_host_behavior_real_mapped.json"
MAPPING_SUMMARY_FILE = EXAMPLES_DIR / "member4_host_behavior_real_mapping_summary.json"


def main() -> None:
    raw_detections = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
    raw_summary = json.loads(SUMMARY_FILE.read_text(encoding="utf-8"))
    expected = raw_summary["attack_mapping"]["expected_technique_by_detection_id"]

    mapped = [
        map_detection(item, expected.get(item["detection_id"]))
        for item in raw_detections
    ]
    mapping_summary = {
        detection.detection_id: {
            "rule_id": detection.evidence.get("rule_id"),
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
        for detection in mapped
    }

    OUTPUT_FILE.write_text(
        json.dumps(
            [detection.model_dump(mode="json") for detection in mapped],
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )
    MAPPING_SUMMARY_FILE.write_text(
        json.dumps(mapping_summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"mapped={len(mapped)} techniques={len(mapping_summary)}")


def map_detection(item: dict[str, Any], technique_id: str | None) -> DetectionResult:
    if technique_id is None:
        technique_id = infer_technique(item)
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
        related_event_ids=item["related_event_ids"],
        related_entity_ids=item["related_entity_ids"],
        evidence=item["evidence"],
        attack_technique_id=technique_id,
        tags=list(dict.fromkeys(original_tags + mapping_tags)),
    )


def infer_technique(item: dict[str, Any]) -> str:
    rule_id = item.get("evidence", {}).get("rule_id")
    if rule_id == "HB-PROC-005":
        return "T1003.008"
    if rule_id == "HB-PROC-006":
        return "T1552.004"
    if rule_id == "HB-SYSCALL-003":
        process_name = str(item.get("evidence", {}).get("process_name", "")).lower()
        return "T1068" if process_name == "su" else "T1548.003"
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


if __name__ == "__main__":
    main()
