from app.analyzers.tracing import AttackTraceService
from app.schemas.detection import DetectionResult
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent, ObjectInfo, SubjectInfo


def event(event_id, minute, host, ip, event_type, action, **kwargs):
    return NormalizedEvent(
        event_id=event_id, timestamp=f"2026-09-08T10:{minute:02d}:00Z",
        source_type=kwargs.pop("source_type", "host_behavior"), source="test",
        host=HostInfo(hostname=host, ip=ip), event_type=event_type,
        action=action, **kwargs,
    )


def test_rdp_without_authentication_is_not_lateral_movement():
    connection = event(
        "rdp", 0, "WEB01", "10.0.0.10", "network_connection", "connect",
        source_type="network_traffic",
        network=NetworkInfo(src_ip="10.0.0.10", dst_ip="10.0.0.20", dst_port=3389),
    )
    assert not any(e.relation == "lateral_movement" for e in AttackTraceService().analyze([connection])["graph"].edges)


def test_normal_https_process_connection_is_not_c2():
    connection = event(
        "https", 0, "PC01", "10.0.0.10", "network_connection", "connect",
        source_type="network_traffic",
        subject=SubjectInfo(type="process", name="browser.exe", pid=10),
        network=NetworkInfo(src_ip="10.0.0.10", dst_ip="8.8.8.8", dst_port=443),
    )
    assert not any(e.relation == "c2_communication" for e in AttackTraceService().analyze([connection])["graph"].edges)


def test_large_upload_without_file_read_is_not_exfiltration():
    upload = event(
        "upload", 0, "PC01", "10.0.0.10", "network_connection", "upload",
        source_type="network_traffic",
        network=NetworkInfo(src_ip="10.0.0.10", dst_ip="8.8.4.4"),
        raw_data={"bytes_out": 9_000_000},
    )
    assert not any(e.relation == "data_exfiltration" for e in AttackTraceService().analyze([upload])["graph"].edges)


def test_different_login_and_process_users_do_not_correlate():
    login = event(
        "login", 0, "PC01", "10.0.0.10", "user_login", "login",
        source_type="host_log", subject=SubjectInfo(type="user", name="alice", user="alice"),
    )
    process = event(
        "process", 1, "PC01", "10.0.0.10", "process_create", "create_process",
        subject=SubjectInfo(type="process", name="cmd.exe", pid=20, user="bob"),
    )
    graph = AttackTraceService().analyze([process, login])["graph"]
    assert not any(e.attributes.get("correlation_rule") == "login_followed_by_execution" for e in graph.edges)


def test_unrelated_download_and_execution_do_not_correlate():
    download = event("download", 0, "PC01", "10.0.0.10", "network_connection", "download")
    written = event(
        "write", 1, "PC01", "10.0.0.10", "file_create", "write",
        object=ObjectInfo(type="file", name="payload.exe", path="C:\\Temp\\payload.exe"),
    )
    process = event(
        "execute", 2, "PC01", "10.0.0.10", "process_create", "execute",
        subject=SubjectInfo(type="process", name="unrelated.exe", pid=30),
        raw_data={"command_line": "C:\\Temp\\unrelated.exe"},
    )
    graph = AttackTraceService().analyze([process, download, written])["graph"]
    assert not any(e.attributes.get("correlation_rule") == "download_write_execute" for e in graph.edges)


def test_concurrent_hosts_do_not_cross_correlate():
    connections = [
        event(f"c{i}", 0, f"WEB0{i}", f"10.0.0.1{i}", "network_connection", "connect",
              source_type="network_traffic",
              network=NetworkInfo(src_ip=f"10.0.0.1{i}", dst_ip=f"10.0.0.2{i}", dst_port=445))
        for i in (1, 2)
    ]
    logins = [
        event(f"l{i}", 1, f"OFFICE0{i}", f"10.0.0.2{i}", "user_login", "login",
              source_type="host_log",
              network=NetworkInfo(src_ip=f"10.0.0.1{i}", dst_ip=f"10.0.0.2{i}"), tags=["successful"])
        for i in (1, 2)
    ]
    edges = [e for e in AttackTraceService().analyze([*reversed(logins), *connections])["graph"].edges if e.relation == "lateral_movement"]
    assert {(e.source, e.target) for e in edges} == {
        ("host:WEB01", "host:OFFICE01"), ("host:WEB02", "host:OFFICE02")
    }


def test_semantically_duplicate_detections_collapse_to_one_edge():
    common = dict(
        timestamp="2026-09-08T10:00:00Z", analyzer="test",
        detection_type="malicious_behavior", title="same", confidence=0.9,
        related_event_ids=["evt-1"], related_entity_ids=["host:A", "host:B"],
        attack_technique_id="T1021.002", tags=["lateral_movement"],
    )
    detections = [DetectionResult(detection_id=f"det-{i}", **common) for i in range(20)]
    graph = AttackTraceService().analyze([], detections)["graph"]
    assert sum(e.relation == "lateral_movement" for e in graph.edges) == 1


def test_unrelated_normal_activity_does_not_form_attack_path():
    events = [
        event("dns", 0, "PC01", "10.0.0.10", "dns_query", "resolve",
              source_type="network_traffic", network=NetworkInfo(src_ip="10.0.0.10", dst_ip="8.8.8.8")),
        event("read", 1, "PC01", "10.0.0.10", "file_read", "read_file",
              object=ObjectInfo(type="file", path="C:\\public.txt")),
    ]
    result = AttackTraceService().analyze(events)
    assert result["stages"] == [] and result["paths"] == []
