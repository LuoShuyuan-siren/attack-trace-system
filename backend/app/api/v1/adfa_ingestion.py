from pathlib import Path
import sys

from fastapi import APIRouter

from app.services.attack_mapping_service import map_detections
from app.services.runtime_store import (
    ATTACK_MAPPINGS,
    DETECTIONS,
    EVENTS,
    TASKS,
    persist_runtime_state,
)

router = APIRouter()


@router.post("/adfa-ld")
def ingest_adfa_ld() -> dict[str, object]:
    """Load ADFA-LD results into the same runtime collections as other sources."""
    repo_root = Path(__file__).resolve().parents[4]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))
    from scripts.evaluate_adfa_ld import evaluate_dataset

    result, events, detections, _mappings = evaluate_dataset(
        repo_root / "ADFA-LD"
    )
    existing_event_ids = {event.event_id for event in EVENTS}
    event_by_id = {event.event_id: event for event in events}
    EVENTS[:] = [
        event_by_id.get(event.event_id, event)
        for event in EVENTS
    ]
    EVENTS.extend(event for event in events if event.event_id not in existing_event_ids)
    new_events = [event for event in events if event.event_id not in existing_event_ids]
    existing_detection_ids = {detection.detection_id for detection in DETECTIONS}
    detection_by_id = {detection.detection_id: detection for detection in detections}
    DETECTIONS[:] = [
        detection_by_id.get(detection.detection_id, detection)
        for detection in DETECTIONS
    ]
    DETECTIONS.extend(
        detection for detection in detections
        if detection.detection_id not in existing_detection_ids
    )
    new_detections = [
        detection for detection in detections
        if detection.detection_id not in existing_detection_ids
    ]
    mappings = map_detections(new_detections)
    for detection, mapping in zip(new_detections, mappings):
        if mapping.technique_id != "unknown":
            detection.attack_technique_id = mapping.technique_id
    ATTACK_MAPPINGS.extend(mappings)
    persist_runtime_state()
    task_id = "task-adfa-ld"
    TASKS[task_id] = {
        "task_id": task_id,
        "name": "ADFA-LD 数据集分析",
        "status": "success",
        "progress": 100,
        "event_count": len(new_events),
        "detection_count": len(new_detections),
        "attack_mapping_count": len(mappings),
        "event_ids": [event.event_id for event in events],
        "detection_ids": [detection.detection_id for detection in detections],
        "mapping_ids": [mapping.detection_id for mapping in mappings],
    }
    return {
        "task_id": task_id,
        "status": "success",
        "message": "ADFA-LD 已加载到统一分析工作区",
        "event_count": len(new_events),
        "detection_count": len(new_detections),
        "attack_mapping_count": len(mappings),
        "evaluation": result,
    }