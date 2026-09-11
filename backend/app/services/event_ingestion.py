from __future__ import annotations

from datetime import datetime, timezone

from app.services.analyzer_dispatcher import analyze_events
from app.services.attack_mapping_service import map_detections
from app.services.forensics_enrichment import align_event_times
from app.services.runtime_store import (
    ATTACK_MAPPINGS,
    DETECTIONS,
    EVENTS,
    INGESTION_DIAGNOSTICS,
    persist_runtime_state,
)
from app.schemas.event import NormalizedEvent


def ingest_events(events: list[NormalizedEvent]) -> dict[str, int]:
    """Store and analyze events received from an online collector."""

    events = align_event_times(events)
    unique_events: list[NormalizedEvent] = []
    known_ids = {event.event_id for event in EVENTS}
    for event in events:
        if event.event_id in known_ids:
            continue
        known_ids.add(event.event_id)
        unique_events.append(event)

    INGESTION_DIAGNOSTICS["batch_count"] += 1
    INGESTION_DIAGNOSTICS["received_event_count"] += len(events)
    INGESTION_DIAGNOSTICS["duplicate_event_count"] += len(events) - len(unique_events)
    INGESTION_DIAGNOSTICS["last_ingest_at"] = datetime.now(timezone.utc).isoformat()

    if not unique_events:
        return {"event_count": 0, "detection_count": 0, "attack_mapping_count": 0}

    EVENTS.extend(unique_events)
    INGESTION_DIAGNOSTICS["accepted_event_count"] += len(unique_events)
    INGESTION_DIAGNOSTICS["last_event_timestamp"] = max(
        event.timestamp for event in unique_events
    ).isoformat()
    for event in unique_events:
        source_type = event.source_type
        by_source = INGESTION_DIAGNOSTICS["by_source_type"]
        by_source[source_type] = by_source.get(source_type, 0) + 1
    detections: list = []
    new_event_ids = {event.event_id for event in unique_events}
    existing_detection_keys = {
        _detection_key(detection) for detection in DETECTIONS
    }
    for source_type in {event.source_type for event in unique_events}:
        # Include prior events as correlation context, but only persist results
        # whose evidence references at least one event from this ingestion.
        source_events = [
            event for event in EVENTS if event.source_type == source_type
        ]
        for detection in analyze_events(source_type, source_events):
            if not set(detection.related_event_ids).intersection(new_event_ids):
                continue
            key = _detection_key(detection)
            if key in existing_detection_keys:
                continue
            existing_detection_keys.add(key)
            detections.append(detection)

    mappings = map_detections(detections)
    mapping_by_detection_id = {mapping.detection_id: mapping for mapping in mappings}
    for detection in detections:
        mapping = mapping_by_detection_id.get(detection.detection_id)
        if mapping and mapping.technique_id != "unknown":
            detection.attack_technique_id = mapping.technique_id

    DETECTIONS.extend(detections)
    ATTACK_MAPPINGS.extend(mappings)
    INGESTION_DIAGNOSTICS["detection_count"] += len(detections)
    persist_runtime_state()
    return {
        "event_count": len(unique_events),
        "detection_count": len(detections),
        "attack_mapping_count": len(mappings),
    }


def _detection_key(detection) -> tuple[str, str, tuple[str, ...]]:
    return (
        detection.analyzer,
        detection.title,
        tuple(sorted(detection.related_event_ids)),
    )
