import json

import pytest

from tests.fixtures.load_tracing_data import load_detections, load_events


def test_fixture_loader_validates_public_models(tmp_path):
    events = tmp_path / "events.json"
    events.write_text(json.dumps([{
        "event_id": "evt-1", "timestamp": "2026-09-08T10:00:00Z",
        "source_type": "host_log", "source": "windows_security",
        "host": {"hostname": "WEB01"}, "event_type": "user_login",
        "action": "login",
    }]), encoding="utf-8")
    assert load_events(events)[0].event_id == "evt-1"

    detections = tmp_path / "detections.json"
    detections.write_text(json.dumps([{
        "detection_id": "det-1", "timestamp": "2026-09-08T10:00:00Z",
        "analyzer": "test", "detection_type": "anomaly", "title": "test",
    }]), encoding="utf-8")
    assert load_detections(detections)[0].detection_id == "det-1"


def test_fixture_loader_reports_item_index(tmp_path):
    path = tmp_path / "bad.json"
    path.write_text('[{"source_type":"bad"}]', encoding="utf-8")
    with pytest.raises(ValueError, match=r"bad.json: invalid item at index 0"):
        load_events(path)
