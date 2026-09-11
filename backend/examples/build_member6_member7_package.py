"""Build the Member 6 -> Member 7 detection package."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.analyzers.attack_mapping import (
    AttackMapper,
    AttackMappingResult,
    build_ttp_profile,
    map_and_build_stages,
)
from app.analyzers.attack_mapping.sample_data import build_sample_scenarios
from app.schemas.detection import DetectionResult


EXAMPLES_DIR = Path(__file__).resolve().parent
DETECTIONS_FILE = EXAMPLES_DIR / "member6_for_member7_detections.json"
PACKAGE_FILE = EXAMPLES_DIR / "member6_for_member7_package.json"
SUMMARY_FILE = EXAMPLES_DIR / "member6_for_member7_summary.json"


def main() -> None:
    scenarios = build_sample_scenarios()
    mapper = AttackMapper()
    mappings = mapper.map_many([scenario.detection for scenario in scenarios])
    mapped_detections = [
        _with_mapping(scenario.detection, mapping)
        for scenario, mapping in zip(scenarios, mappings)
    ]
    stages = map_and_build_stages(
        [scenario.detection for scenario in scenarios],
        mapper,
    )
    profile = build_ttp_profile(mappings)

    detections_json = [item.model_dump(mode="json") for item in mapped_detections]
    package = {
        "normalized_events": [
            scenario.event.model_dump(mode="json") for scenario in scenarios
        ],
        "detection_results": detections_json,
        "mapping_results": [mapping.to_dict() for mapping in mappings],
        "stages": [stage.to_dict() for stage in stages],
        "ttp_profile": profile.to_dict(),
    }
    summary = {
        "total_detections": len(mapped_detections),
        "attack_detections": sum(
            1
            for item in mapped_detections
            if item.attack_technique_id is not None
        ),
        "normal_detections": sum(
            1
            for item in mapped_detections
            if item.attack_technique_id is None
        ),
        "technique_ids": list(profile.technique_ids),
        "tactic_ids": list(profile.tactic_ids),
    }

    DETECTIONS_FILE.write_text(
        json.dumps(detections_json, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    PACKAGE_FILE.write_text(
        json.dumps(package, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    SUMMARY_FILE.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(
        f"detections={summary['total_detections']} "
        f"attack={summary['attack_detections']} "
        f"normal={summary['normal_detections']}"
    )


def _with_mapping(
    detection: DetectionResult,
    mapping: AttackMappingResult,
) -> DetectionResult:
    mapped_tags = list(detection.tags)
    technique_id = None if mapping.technique_id == "unknown" else mapping.technique_id

    if technique_id is not None:
        mapped_tags.append(f"attack_technique:{technique_id}")
        for tactic in mapping.tactics:
            mapped_tags.extend(
                [
                    f"attack_tactic:{tactic.tactic_id}",
                    f"attack_stage:{tactic.stage}",
                ]
            )

    return detection.model_copy(
        update={
            "attack_technique_id": technique_id,
            "tags": list(dict.fromkeys(mapped_tags)),
        }
    )


if __name__ == "__main__":
    main()
