import json
from pathlib import Path

import pytest

from app.analyzers.tracing import AttackTraceService
from scripts.check_tracing_integration import correlation_diagnostics, load_inputs


ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "backend" / "tests" / "fixtures" / "real_integration"


def test_checker_reads_wrapped_input_and_reports_reference_integrity(tmp_path):
    bundle = tmp_path / "bundle.json"
    bundle.write_text(json.dumps({
        "summary": {"total_events": 2},
        "normalized_events": [{
            "event_id": "evt-1", "timestamp": "2026-09-08T10:00:00Z",
            "source_type": "network_traffic", "source": "zeek",
            "host": {}, "event_type": "network_connection",
            "network": {"src_ip": "10.0.0.1", "dst_ip": "10.0.0.2"},
            "action": "connect",
        }],
        "detection_results": [{
            "detection_id": "det-1", "timestamp": "2026-09-08T10:00:01Z",
            "analyzer": "test", "detection_type": "anomaly", "title": "test",
            "related_event_ids": ["evt-1", "evt-missing"],
            "related_entity_ids": ["ip:10.0.0.1", "host:missing"],
        }],
    }), encoding="utf-8")

    loaded = load_inputs([str(bundle)], [str(bundle)])
    diagnostics = correlation_diagnostics(loaded)

    assert diagnostics["schema_valid"] is True
    assert diagnostics["total_events"] == 1
    assert diagnostics["total_detections"] == 1
    assert diagnostics["valid_event_reference_count"] == 1
    assert diagnostics["missing_event_reference_count"] == 1
    assert diagnostics["valid_entity_reference_count"] == 1
    assert diagnostics["missing_entity_reference_count"] == 1
    assert diagnostics["correlation_ready"] == "low"
    assert any("summary.total_events=2, actual=1" in note for note in loaded.file_notes)


def test_checker_keeps_schema_and_readiness_separate(tmp_path):
    events = tmp_path / "events.json"
    events.write_text(json.dumps([{
        "event_id": "evt-1", "timestamp": "2026-09-08T10:00:00Z",
        "source_type": "host_log", "source": "windows_security",
        "host": {"hostname": "PC01"}, "event_type": "user_login",
        "subject": {"type": "user", "user": "alice"}, "action": "login",
    }]), encoding="utf-8")

    diagnostics = correlation_diagnostics(load_inputs([str(events)], []))

    assert diagnostics["schema_valid"] is True
    assert diagnostics["events_without_host_ip"] == 1
    assert diagnostics["correlation_ready"] == "medium"


def test_member6_real_fixture_is_stable_and_has_no_dangling_edges():
    events = [
        FIXTURES / "windows" / "for_yidan_member2(1).json",
        FIXTURES / "linux" / "linux_tc003_normalized_events(1).json",
        FIXTURES / "host_behavior" / "host_behavior_events.json",
        FIXTURES / "network" / "original" / "sample_data(1).json",
    ]
    detections = [
        FIXTURES / "attack_mapping" / "member6_for_member7_detections(1).json"
    ]
    missing = [path for path in [*events, *detections] if not path.exists()]
    if missing:
        pytest.skip("local real-integration fixtures are not part of the code delivery")
    loaded = load_inputs(list(map(str, events)), list(map(str, detections)))
    diagnostics = correlation_diagnostics(loaded)

    assert len(loaded.events) == 88
    assert len(loaded.detections) == 14
    assert diagnostics["schema_valid"] is True
    assert diagnostics["missing_event_reference_count"] == 14
    assert diagnostics["missing_entity_reference_count"] == 27

    first_service = AttackTraceService()
    first = first_service.analyze(loaded.events, loaded.detections)
    second = AttackTraceService().analyze(loaded.events, loaded.detections)

    assert first == second
    node_ids = {node.node_id for node in first["graph"].nodes}
    assert all(
        edge.source in node_ids and edge.target in node_ids
        for edge in first["graph"].edges
    )
    assert all(node.node_id.strip() and ":" in node.node_id for node in first["graph"].nodes)
