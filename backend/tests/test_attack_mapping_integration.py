from datetime import datetime, timezone

from app.schemas.detection import DetectionResult
from app.services.attack_trace_pipeline import (
    build_pipeline_result,
    deduplicate_detections,
)


def detection(
    detection_id: str,
    analyzer: str,
    related_event_ids: list[str],
    attack_technique_id: str | None = None,
) -> DetectionResult:
    return DetectionResult(
        detection_id=detection_id,
        timestamp=datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc),
        analyzer=analyzer,
        detection_type="suspicious_behavior",
        title="sample detection",
        confidence=0.8,
        related_event_ids=related_event_ids,
        evidence={"src_ip": "192.168.1.10"},
        attack_technique_id=attack_technique_id,
        tags=["test"],
    )


def test_deduplicate_detections_removes_same_event_group():
    first = detection("det-1", "dns_analyzer", ["evt-1", "evt-2"])
    duplicate = detection("det-2", "dns_analyzer", ["evt-1", "evt-2"])
    different = detection("det-3", "http_analyzer", ["evt-3"])

    result = deduplicate_detections([duplicate, first, different])

    assert [item.detection_id for item in result] == ["det-1", "det-3"]


def test_build_pipeline_result_maps_and_orders_stages():
    first = detection(
        "det-1",
        "exploit_analyzer",
        ["evt-1"],
        attack_technique_id="T1190",
    )
    second = detection(
        "det-2",
        "dns_analyzer",
        ["evt-2"],
        attack_technique_id="T1071.004",
    )

    result = build_pipeline_result([], [second, first])

    assert [item.detection_id for item in result.detections] == ["det-1", "det-2"]
    assert [stage.stage for stage in result.stages] == [
        "initial_access",
        "command_and_control",
    ]
    assert result.ttp_profile.tactic_ids == ("TA0001", "TA0011")
