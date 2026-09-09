"""Generate member 6 sample outputs for integration with member 7."""

from __future__ import annotations

import json
from pathlib import Path

from app.analyzers.attack_mapping import (
    AttackMapper,
    build_ttp_profile,
    map_and_build_stages,
)
from app.analyzers.attack_mapping.sample_data import build_sample_scenarios


OUTPUT_DIR = Path(__file__).resolve().parent


def main() -> None:
    scenarios = build_sample_scenarios()
    detections = [scenario.detection for scenario in scenarios]
    events = [scenario.event for scenario in scenarios]
    mapper = AttackMapper()
    mappings = mapper.map_many(detections)
    stages = map_and_build_stages(detections, mapper)
    profile = build_ttp_profile(mappings)

    write_json(
        OUTPUT_DIR / "member6_sample_events.json",
        [event.model_dump(mode="json") for event in events],
    )
    write_json(
        OUTPUT_DIR / "member6_sample_detections.json",
        [detection.model_dump(mode="json") for detection in detections],
    )
    write_json(
        OUTPUT_DIR / "member6_mapping_results.json",
        {
            "mappings": [mapping.to_dict() for mapping in mappings],
            "stages": [stage.to_dict() for stage in stages],
            "ttp_profile": profile.to_dict(),
        },
    )

    print(f"scenarios={len(scenarios)} mappings={len(mappings)} stages={len(stages)}")
    print(f"techniques={len(profile.technique_ids)} tactics={len(profile.tactic_ids)}")


def write_json(path: Path, payload: object) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    main()
