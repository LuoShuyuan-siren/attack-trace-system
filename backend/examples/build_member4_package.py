"""Build a member7-ready package from Member 4 events and mapped detections."""

from __future__ import annotations

import json
from pathlib import Path

from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


EXAMPLES_DIR = Path(__file__).resolve().parent
EVENTS_FILE = EXAMPLES_DIR / "member4_host_behavior_events.json"
DETECTIONS_FILE = EXAMPLES_DIR / "member4_host_behavior_mapped.json"
PACKAGE_FILE = EXAMPLES_DIR / "member4_host_behavior_package.json"


def main() -> None:
    raw_events = json.loads(EVENTS_FILE.read_text(encoding="utf-8"))
    raw_detections = json.loads(DETECTIONS_FILE.read_text(encoding="utf-8"))

    events = [NormalizedEvent.model_validate(item) for item in raw_events]
    detections = [DetectionResult.model_validate(item) for item in raw_detections]
    event_ids = {event.event_id for event in events}
    missing_related_ids = sorted(
        {
            related_id
            for detection in detections
            for related_id in detection.related_event_ids
        }
        - event_ids
    )

    package = {
        "normalized_events": [event.model_dump(mode="json") for event in events],
        "detection_results": [
            detection.model_dump(mode="json") for detection in detections
        ],
        "coverage": {
            "total_events": len(events),
            "total_detections": len(detections),
            "missing_related_event_ids": missing_related_ids,
        },
    }

    PACKAGE_FILE.write_text(
        json.dumps(package, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    print(
        f"events={len(events)} detections={len(detections)} "
        f"missing_related={len(missing_related_ids)}"
    )


if __name__ == "__main__":
    main()
