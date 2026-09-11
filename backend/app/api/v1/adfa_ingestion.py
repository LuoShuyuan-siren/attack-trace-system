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
    new_events = [event for event in events if event.event_id not in existing_event_ids]
    existing_detection_ids = {detection.detection_id for detection in DETECTIONS}
    new_detections = [
        detection for detection in detections if detection.detection_id not in existing_detection_ids
    ]
    mappings = map_detections(new_detections)
    for detection, mapping in zip(new_detections, mappings):
        if mapping.technique_id != "unknown":
            detection.attack_technique_id = mapping.technique_id
    EVENTS.extend(new_events)
    DETECTIONS.extend(new_detections)
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