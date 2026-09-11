from app.schemas.event import HostInfo, NormalizedEvent, SubjectInfo
from app.services.event_ingestion import ingest_events
from app.services.runtime_store import ATTACK_MAPPINGS, DETECTIONS, EVENTS


def _syscall(event_id: str, timestamp: str, syscall: str) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="host_behavior",
        source="ebpf",
        host=HostInfo(hostname="LINUX-01", os="linux"),
        event_type="system_call",
        subject=SubjectInfo(type="process", name="loader", pid=42),
        action=syscall,
        raw_data={"syscall_name": syscall, "arguments": {}, "result": 0},
    )


def test_incremental_ingestion_keeps_cross_batch_memfd_sequence() -> None:
    EVENTS.clear()
    DETECTIONS.clear()
    ATTACK_MAPPINGS.clear()

    first = ingest_events([_syscall("evt-memfd", "2026-09-11T10:00:00Z", "memfd_create")])
    second = ingest_events([_syscall("evt-exec", "2026-09-11T10:00:05Z", "execve")])

    assert first["detection_count"] == 0
    assert second["detection_count"] >= 1
    assert any(
        set(detection.related_event_ids) == {"evt-memfd", "evt-exec"}
        for detection in DETECTIONS
    )
