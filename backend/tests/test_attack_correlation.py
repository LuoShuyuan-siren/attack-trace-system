from datetime import timedelta

from app.analyzers.tracing import AttackTraceService, TemporalCorrelator
from app.schemas.detection import DetectionResult
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent


def network_event(
    event_id: str,
    timestamp: str,
    hostname: str,
    host_ip: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="network_traffic",
        source="zeek",
        host=HostInfo(hostname=hostname, ip=host_ip),
        event_type="network_connection",
        network=NetworkInfo(src_ip=src_ip, dst_ip=dst_ip, dst_port=dst_port),
        action="connect",
    )


def login_event(
    event_id: str,
    timestamp: str,
    hostname: str,
    host_ip: str,
    src_ip: str,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="host_log",
        source="windows_security",
        host=HostInfo(hostname=hostname, ip=host_ip),
        event_type="user_login",
        network=NetworkInfo(src_ip=src_ip, dst_ip=host_ip),
        action="login",
        tags=["successful"],
    )


def detection(
    detection_id: str,
    timestamp: str,
    source: str,
    target: str,
    relation: str,
) -> DetectionResult:
    return DetectionResult(
        detection_id=detection_id,
        timestamp=timestamp,
        analyzer="test_attack_analyzer",
        detection_type="malicious_behavior",
        title=relation,
        severity="high",
        confidence=0.9,
        related_entity_ids=[source, target],
        tags=[relation],
    )


def test_correlates_connection_and_login_across_hosts() -> None:
    events = [
        network_event(
            "evt-smb", "2026-09-08T10:20:00Z", "WEB01", "10.0.0.10",
            "10.0.0.10", "10.0.0.20", 445,
        ),
        login_event(
            "evt-login", "2026-09-08T10:21:00Z", "PC01", "10.0.0.20", "10.0.0.10"
        ),
    ]

    result = AttackTraceService().analyze(reversed(events))
    lateral_edges = [
        edge for edge in result["graph"].edges if edge.relation == "lateral_movement"
    ]

    assert len(lateral_edges) == 1
    assert lateral_edges[0].source == "host:WEB01"
    assert lateral_edges[0].target == "host:PC01"
    assert lateral_edges[0].attack_technique_id == "T1021.002"
    assert lateral_edges[0].related_event_ids == ["evt-smb", "evt-login"]
    assert lateral_edges[0].confidence == 0.9


def test_does_not_correlate_events_outside_window() -> None:
    events = [
        network_event(
            "evt-ssh", "2026-09-08T10:00:00Z", "WEB01", "10.0.0.10",
            "10.0.0.10", "10.0.0.20", 22,
        ),
        login_event(
            "evt-login", "2026-09-08T10:10:01Z", "DB01", "10.0.0.20", "10.0.0.10"
        ),
    ]

    service = AttackTraceService()
    service.correlator = TemporalCorrelator(window=timedelta(minutes=5))
    result = service.analyze(events)

    assert not any(
        edge.relation == "lateral_movement" for edge in result["graph"].edges
    )


def test_reconstructs_and_ranks_complete_attack_path() -> None:
    detections = [
        detection(
            "det-entry", "2026-09-08T10:00:00Z",
            "ip:203.0.113.8", "host:WEB01", "initial_access",
        ),
        detection(
            "det-exec", "2026-09-08T10:02:00Z",
            "host:WEB01", "process:WEB01:3152", "execute",
        ),
        detection(
            "det-lateral", "2026-09-08T10:05:00Z",
            "process:WEB01:3152", "host:PC01", "lateral_movement",
        ),
        detection(
            "det-c2", "2026-09-08T10:08:00Z",
            "host:PC01", "ip:198.51.100.25", "c2_communication",
        ),
        detection(
            "det-exfil", "2026-09-08T10:10:00Z",
            "ip:198.51.100.25", "domain:drop.example", "data_exfiltration",
        ),
    ]

    result = AttackTraceService().analyze([], reversed(detections))

    assert len(result["stages"]) == 5
    assert result["paths"][0]["relations"] == [
        "initial_access",
        "execute",
        "lateral_movement",
        "c2_communication",
        "data_exfiltration",
    ]
    assert result["paths"][0]["nodes"][0] == "ip:203.0.113.8"
    assert result["paths"][0]["nodes"][-1] == "domain:drop.example"
    assert result["paths"][0]["confidence"] == 0.5905
