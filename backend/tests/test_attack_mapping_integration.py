from datetime import datetime, timezone

from app.analyzers.attack_mapping import AttackMapper
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
    timestamp: datetime | None = None,
) -> DetectionResult:
    return DetectionResult(
        detection_id=detection_id,
        timestamp=timestamp
        or datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc),
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


def test_time_window_deduplication_keeps_different_buckets():
    first_time = datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc)
    second_time = datetime(2026, 9, 10, 10, 10, tzinfo=timezone.utc)
    first = detection(
        "det-1",
        "dns_analyzer",
        ["evt-1", "evt-2"],
        timestamp=first_time,
    )
    later = detection(
        "det-2",
        "dns_analyzer",
        ["evt-1", "evt-2"],
        timestamp=second_time,
    )

    result = deduplicate_detections(
        [first, later],
        time_window_seconds=60,
    )

    assert [item.detection_id for item in result] == ["det-1", "det-2"]


def test_member4_rule_ids_are_mapped_by_attack_mapper():
    mapper = AttackMapper()
    credential_database = DetectionResult(
        detection_id="det-cred-db",
        timestamp=datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc),
        analyzer="host_behavior_analyzer",
        detection_type="suspicious_behavior",
        title="Credential database referenced by command",
        confidence=0.8,
        evidence={"rule_id": "HB-PROC-005"},
        tags=["HB-PROC-005"],
    )
    credential_search = DetectionResult(
        detection_id="det-cred-search",
        timestamp=datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc),
        analyzer="host_behavior_analyzer",
        detection_type="suspicious_behavior",
        title="Credential material search command",
        confidence=0.8,
        evidence={"rule_id": "HB-PROC-006"},
        tags=["HB-PROC-006"],
    )

    first = mapper.map_one(credential_database)
    second = mapper.map_one(credential_search)

    assert first.technique_id == "T1003.008"
    assert second.technique_id == "T1552.004"


def test_icmp_tunnel_and_uncommon_port_mapping():
    mapper = AttackMapper()
    icmp = DetectionResult(
        detection_id="det-icmp",
        timestamp=datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc),
        analyzer="icmp_analyzer",
        detection_type="suspicious_behavior",
        title="ICMP tunnel",
        confidence=0.8,
        attack_technique_id="T1571.004",
        tags=["icmp", "icmp_tunnel", "covert_channel"],
    )
    uncommon = DetectionResult(
        detection_id="det-uncommon",
        timestamp=datetime(2026, 9, 10, 10, 0, tzinfo=timezone.utc),
        analyzer="connection_analyzer",
        detection_type="anomaly",
        title="Uncommon port communication",
        confidence=0.5,
        tags=["connection", "uncommon_port"],
    )

    assert mapper.map_one(icmp).technique_id == "T1095"
    assert mapper.map_one(uncommon).technique_id == "T1571"
