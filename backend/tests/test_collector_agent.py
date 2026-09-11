from pathlib import Path

from app.collectors.agent import CollectorAgent
from app.schemas.event import NormalizedEvent
from app.services.event_ingestion import ingest_events
from app.services.runtime_store import ATTACK_MAPPINGS, DETECTIONS, EVENTS


def test_collector_emits_normalized_process_events(tmp_path: Path) -> None:
    agent = CollectorAgent(cache_path=tmp_path / "events.jsonl")

    events = agent.collect_once()

    assert events
    assert all(isinstance(event, NormalizedEvent) for event in events)
    assert all(event.source == "collector_agent" for event in events)
    assert any(event.event_type == "process_snapshot" for event in events)


def test_ingestion_deduplicates_agent_events() -> None:
    EVENTS.clear()
    DETECTIONS.clear()
    ATTACK_MAPPINGS.clear()
    event = NormalizedEvent(
        timestamp="2026-09-11T10:00:00Z",
        source_type="host_behavior",
        source="collector_agent",
        event_type="process_snapshot",
        action="observe_process",
        raw_data={"pid": 42, "process_name": "bash", "ppid": 1},
    )

    first = ingest_events([event])
    second = ingest_events([event])

    assert first["event_count"] == 1
    assert second["event_count"] == 0
    assert len(EVENTS) == 1
