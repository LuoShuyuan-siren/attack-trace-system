from pathlib import Path

from app.collectors.agent import CollectorAgent
from app.schemas.event import NormalizedEvent
from app.services.event_ingestion import ingest_events
from app.services.runtime_store import (
    ATTACK_MAPPINGS,
    DETECTIONS,
    EVENTS,
    INGESTION_DIAGNOSTICS,
)


def _reset() -> None:
    EVENTS.clear()
    DETECTIONS.clear()
    ATTACK_MAPPINGS.clear()
    INGESTION_DIAGNOSTICS.update({
        "batch_count": 0,
        "received_event_count": 0,
        "accepted_event_count": 0,
        "duplicate_event_count": 0,
        "detection_count": 0,
        "last_ingest_at": None,
        "last_event_timestamp": None,
        "by_source_type": {},
    })


def test_ingestion_health_counts_duplicates() -> None:
    _reset()
    event = NormalizedEvent(
        timestamp="2026-09-11T10:00:00Z",
        source_type="host_behavior",
        source="test",
        event_type="process_snapshot",
        action="observe_process",
    )

    ingest_events([event])
    ingest_events([event])

    assert INGESTION_DIAGNOSTICS["batch_count"] == 2
    assert INGESTION_DIAGNOSTICS["accepted_event_count"] == 1
    assert INGESTION_DIAGNOSTICS["duplicate_event_count"] == 1
    assert INGESTION_DIAGNOSTICS["by_source_type"] == {"host_behavior": 1}


def test_collector_health_reports_cache_state(tmp_path: Path) -> None:
    agent = CollectorAgent(cache_path=tmp_path / "events.jsonl", enable_clock_calibration=False)

    health = agent.health()

    assert health["agent_id"]
    assert health["cache_exists"] is False
    assert health["send_failure_count"] == 0
