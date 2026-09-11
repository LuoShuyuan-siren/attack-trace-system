from app.schemas.detection import DetectionResult
from app.schemas.event import HostInfo, NormalizedEvent
from app.services.attack_mapping_service import map_detections
from app.services.persistent_store import SQLiteRuntimeStore


def test_sqlite_runtime_store_round_trips_evidence(tmp_path) -> None:
    event = NormalizedEvent(
        timestamp="2026-09-11T10:00:00Z",
        source_type="host_behavior",
        source="test",
        host=HostInfo(hostname="HOST01"),
        event_type="process_create",
        action="execute",
    )
    detection = DetectionResult(
        timestamp=event.timestamp,
        analyzer="test",
        detection_type="malicious_behavior",
        title="test detection",
        related_event_ids=[event.event_id],
        attack_technique_id="T1059.001",
    )
    mapping = map_detections([detection])[0]
    store = SQLiteRuntimeStore(tmp_path / "runtime.db")

    store.save([event], [detection], [mapping])
    events, detections, mappings = store.load()

    assert events[0].event_id == event.event_id
    assert detections[0].detection_id == detection.detection_id
    assert mappings[0].technique_id == mapping.technique_id
    assert mappings[0].tactics == mapping.tactics
