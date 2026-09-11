from app.analyzers.tracing import AttackTraceService
from app.schemas.detection import DetectionResult
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent, ObjectInfo, SubjectInfo


def make_event(event_id, source_type, source, hostname, ip, event_type, action, **values):
    return NormalizedEvent(
        event_id=event_id,
        timestamp=values.pop("timestamp", "2026-09-08T10:00:00Z"),
        source_type=source_type,
        source=source,
        host=HostInfo(hostname=hostname, ip=ip, os=values.pop("os", None)),
        event_type=event_type,
        action=action,
        **values,
    )


def test_windows_host_log_with_missing_optional_fields():
    event = make_event(
        "evt-win", "host_log", "windows_security", "WIN01", "10.0.0.10",
        "user_logout", "logout", os="windows",
    )
    result = AttackTraceService().analyze([event])
    assert [node.node_id for node in result["graph"].nodes] == ["host:WIN01"]
    assert result["paths"] == []


def test_linux_auth_log_and_process_execution():
    login = make_event(
        "evt-linux-login", "host_log", "linux_auth", "LINUX01", "10.0.0.20",
        "user_login", "login", os="linux",
        subject=SubjectInfo(type="user", name="root", user="root"),
    )
    process = make_event(
        "evt-linux-exec", "host_behavior", "linux_auditd", "LINUX01", "10.0.0.20",
        "process_create", "create_process", os="linux", timestamp="2026-09-08T10:01:00Z",
        subject=SubjectInfo(type="process", name="bash", pid=42, user="root"),
    )
    graph = AttackTraceService().analyze([process, login], [])["graph"]
    assert any(
        edge.attributes.get("correlation_rule") == "login_followed_by_execution"
        for edge in graph.edges
    )


def test_host_behavior_and_detection_are_fused():
    behavior = make_event(
        "evt-behavior", "host_behavior", "ebpf", "LINUX01", "10.0.0.20",
        "file_read", "read_file",
        subject=SubjectInfo(type="process", name="tar", pid=52),
        object=ObjectInfo(type="file", name="shadow", path="/etc/shadow"),
    )
    detection = DetectionResult(
        detection_id="det-behavior", timestamp=behavior.timestamp, analyzer="sensitive_file",
        detection_type="suspicious_behavior", title="Sensitive file read", confidence=0.88,
        related_event_ids=[behavior.event_id],
        related_entity_ids=["process:LINUX01:52", "file:LINUX01:/etc/shadow"],
        attack_technique_id="T1003.008", tags=["credential_access"],
    )
    graph = AttackTraceService().analyze([behavior], [detection])["graph"]
    assert any(edge.related_detection_ids == ["det-behavior"] for edge in graph.edges)


def test_mixed_windows_linux_remote_movement():
    connection = make_event(
        "evt-win-ssh", "network_traffic", "zeek", "WIN01", "10.0.0.10",
        "network_connection", "connect", os="windows",
        network=NetworkInfo(src_ip="10.0.0.10", dst_ip="10.0.0.20", dst_port=22),
    )
    login = make_event(
        "evt-linux-auth", "host_log", "linux_auth", "LINUX01", "10.0.0.20",
        "authenticate", "authenticate", os="linux", timestamp="2026-09-08T10:01:00Z",
        network=NetworkInfo(src_ip="10.0.0.10", dst_ip="10.0.0.20"), tags=["successful"],
    )
    graph = AttackTraceService().analyze([login, connection])["graph"]
    edge = next(edge for edge in graph.edges if edge.relation == "lateral_movement")
    assert (edge.source, edge.target, edge.attack_technique_id) == (
        "host:WIN01", "host:LINUX01", "T1021.004"
    )


def test_ipv6_network_event():
    event = make_event(
        "evt-ipv6", "network_traffic", "zeek", "IPV6HOST", "2001:db8::10",
        "network_connection", "connect",
        network=NetworkInfo(src_ip="2001:db8::10", dst_ip="2001:4860:4860::8888", dst_port=443),
    )
    graph = AttackTraceService().analyze([event])["graph"]
    node_ids = {node.node_id for node in graph.nodes}
    assert "ip:2001:db8::10" in node_ids
    assert "ip:2001:4860:4860::8888" in node_ids


def test_duplicate_ids_are_deduplicated_and_reported():
    event = make_event(
        "evt-duplicate", "host_log", "windows_security", "WIN01", "10.0.0.10",
        "user_logout", "logout",
    )
    detection = DetectionResult(
        detection_id="det-duplicate", timestamp=event.timestamp, analyzer="test",
        detection_type="anomaly", title="duplicate",
    )
    service = AttackTraceService()
    service.analyze([event, event.model_copy(deep=True)], [detection, detection.model_copy(deep=True)])
    assert service.last_diagnostics["duplicate_events"] == 1
    assert service.last_diagnostics["duplicate_detections"] == 1


def test_malformed_constructed_event_is_skipped_without_breaking_valid_input():
    malformed = NormalizedEvent.model_construct(
        event_id="evt-bad", timestamp=None, source_type="host_log", source="bad",
        host=None, event_type="user_login", action="login",
    )
    valid = make_event(
        "evt-good", "host_log", "windows_security", "WIN01", "10.0.0.10",
        "user_logout", "logout",
    )
    service = AttackTraceService()
    result = service.analyze([malformed, valid])
    assert {node.node_id for node in result["graph"].nodes} == {"host:WIN01"}
    assert service.last_diagnostics["skipped_events"] == 1


def test_empty_detections_and_empty_events():
    event = make_event(
        "evt-only", "host_log", "linux_syslog", "LINUX01", "10.0.0.20",
        "user_logout", "logout",
    )
    assert AttackTraceService().analyze([event], [])["graph"].nodes
    empty = AttackTraceService().analyze([], [])
    assert empty["graph"].nodes == []
    assert empty["graph"].edges == []
    assert empty["stages"] == []
    assert empty["paths"] == []
