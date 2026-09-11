from datetime import datetime, timedelta, timezone

import pytest

from app.analyzers.tracing import AttackTraceService
from app.analyzers.tracing.path_scorer import calculate_path_score
from app.schemas.attack_graph import AttackEdge
from app.schemas.detection import DetectionResult
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent, ObjectInfo, SubjectInfo


def event(event_id, minute, hostname, host_ip, event_type, action, **values):
    return NormalizedEvent(
        event_id=event_id,
        timestamp=f"2026-09-08T10:{minute:02d}:00Z",
        source_type=values.pop("source_type", "host_behavior"),
        source=values.pop("source", "test"),
        host=HostInfo(hostname=hostname, ip=host_ip),
        event_type=event_type,
        action=action,
        **values,
    )


def remote_pair(port, technique, auth_type="user_login"):
    connection = event(
        f"evt-connect-{port}", 10, "WEB01", "10.0.0.10",
        "network_connection", "connect", source_type="network_traffic",
        network=NetworkInfo(src_ip="10.0.0.10", dst_ip="10.0.0.20", dst_port=port),
    )
    authentication = event(
        f"evt-auth-{port}", 11, "OFFICE01", "10.0.0.20",
        auth_type, "authenticate", source_type="host_log",
        network=NetworkInfo(src_ip="10.0.0.10", dst_ip="10.0.0.20"),
        subject=SubjectInfo(type="user", name="admin", user="admin"), tags=["successful"],
    )
    return connection, authentication, technique


@pytest.mark.parametrize(
    ("port", "technique", "service"),
    [(3389, "T1021.001", "rdp"), (22, "T1021.004", "ssh"),
     (445, "T1021.002", "smb"), (5985, "T1021.006", "winrm"),
     (5986, "T1021.006", "winrm")],
)
def test_remote_services_require_closed_evidence_loop(port, technique, service):
    connection, authentication, _ = remote_pair(port, technique, "authenticate")
    graph = AttackTraceService().analyze([authentication, connection])["graph"]
    edge = next(edge for edge in graph.edges if edge.relation == "lateral_movement")
    assert edge.attack_technique_id == technique
    assert edge.attributes == {
        "correlation_rule": "network_connection_followed_by_remote_login",
        "remote_service": service,
        "remote_port": port,
        "time_delta_seconds": 60.0,
        "source_host": "WEB01",
        "target_host": "OFFICE01",
        "matched_src_ip": "10.0.0.10",
        "matched_target_ip": "10.0.0.20",
        "matched_authentication": "authenticate",
        "evidence_quality": "high",
    }


def test_unsupported_port_does_not_imply_lateral_movement():
    connection, authentication, _ = remote_pair(8080, "", "user_login")
    graph = AttackTraceService().analyze([connection, authentication])["graph"]
    assert not any(edge.relation == "lateral_movement" for edge in graph.edges)


@pytest.mark.parametrize("mutation", ["source_ip", "target_host", "outside_window"])
def test_broken_evidence_loop_does_not_correlate(mutation):
    connection, authentication, _ = remote_pair(445, "T1021.002")
    if mutation == "source_ip":
        authentication.network.src_ip = "10.0.0.99"
    elif mutation == "target_host":
        authentication.host.ip = "10.0.0.30"
    else:
        authentication.timestamp += timedelta(minutes=6)
    graph = AttackTraceService().analyze([authentication, connection])["graph"]
    assert not any(edge.relation == "lateral_movement" for edge in graph.edges)


def test_duplicate_out_of_order_events_produce_one_lateral_edge():
    connection, authentication, _ = remote_pair(3389, "T1021.001")
    duplicate_connection = connection.model_copy(update={"event_id": "evt-connect-copy"})
    duplicate_auth = authentication.model_copy(update={"event_id": "evt-auth-copy"})
    events = [duplicate_auth, connection, authentication, duplicate_connection]
    graph = AttackTraceService().analyze(events)["graph"]
    assert sum(edge.relation == "lateral_movement" for edge in graph.edges) == 1


def test_login_followed_by_same_user_execution():
    login = event(
        "evt-login", 1, "WEB01", "10.0.0.10", "user_login", "login",
        source_type="host_log", subject=SubjectInfo(type="user", name="alice", user="alice"),
    )
    execution = event(
        "evt-exec", 4, "WEB01", "10.0.0.10", "process_create", "create_process",
        subject=SubjectInfo(type="process", name="cmd.exe", pid=100, user="alice"),
    )
    graph = AttackTraceService().analyze([execution, login])["graph"]
    edge = next(e for e in graph.edges if e.attributes.get("correlation_rule") == "login_followed_by_execution")
    assert edge.source == "host:WEB01"
    assert edge.target == "process:WEB01:100"


def test_download_write_execute_semantic_chain():
    download = event(
        "evt-download", 1, "WEB01", "10.0.0.10", "network_connection", "download",
        source_type="network_traffic", network=NetworkInfo(src_ip="10.0.0.10", dst_ip="8.8.8.8"),
    )
    write = event(
        "evt-write", 2, "WEB01", "10.0.0.10", "file_create", "write",
        object=ObjectInfo(type="file", name="payload.exe", path="C:\\Temp\\payload.exe"),
    )
    execute = event(
        "evt-execute", 4, "WEB01", "10.0.0.10", "process_create", "execute",
        subject=SubjectInfo(type="process", name="payload.exe", pid=200),
        raw_data={"command_line": "C:\\Temp\\payload.exe -silent"},
    )
    graph = AttackTraceService().analyze([execute, download, write])["graph"]
    edge = next(e for e in graph.edges if e.attributes.get("correlation_rule") == "download_write_execute")
    assert edge.related_event_ids == ["evt-download", "evt-write", "evt-execute"]


def test_file_read_followed_by_large_upload_is_exfiltration():
    read = event(
        "evt-read", 20, "DB01", "10.0.0.30", "file_read", "read_file",
        subject=SubjectInfo(type="process", name="archive.exe", pid=300),
        object=ObjectInfo(type="file", name="customers.db", path="D:\\data\\customers.db"),
    )
    upload = event(
        "evt-upload", 25, "DB01", "10.0.0.30", "network_connection", "upload",
        source_type="network_traffic", subject=SubjectInfo(type="process", name="archive.exe", pid=300),
        network=NetworkInfo(src_ip="10.0.0.30", dst_ip="8.8.4.4"), raw_data={"bytes_out": 5000000},
    )
    graph = AttackTraceService().analyze([upload, read])["graph"]
    edge = next(e for e in graph.edges if e.relation == "data_exfiltration")
    assert edge.source == "file:DB01:D:\\data\\customers.db"
    assert edge.target == "ip:8.8.4.4"


def test_process_c2_inherits_detection_technique():
    connection = event(
        "evt-c2", 25, "DB01", "10.0.0.30", "network_connection", "connect",
        source_type="network_traffic", subject=SubjectInfo(type="process", name="agent.exe", pid=400),
        network=NetworkInfo(src_ip="10.0.0.30", dst_ip="8.8.8.8"),
    )
    detection = DetectionResult(
        detection_id="det-c2", timestamp=connection.timestamp, analyzer="c2_detector",
        detection_type="malicious_behavior", title="C2", confidence=0.95,
        related_event_ids=[connection.event_id],
        related_entity_ids=["process:DB01:400", "ip:8.8.8.8"],
        attack_technique_id="T1071.001", tags=["c2_communication"],
    )
    graph = AttackTraceService().analyze([connection], [detection])["graph"]
    edge = next(e for e in graph.edges if e.attributes.get("correlation_rule") == "process_connection_to_external_c2")
    assert edge.attack_technique_id == "T1071.001"
    assert edge.related_detection_ids == ["det-c2"]


def test_path_score_has_six_explainable_components():
    edges = [
        AttackEdge(
            edge_id=f"edge-{i}", source=f"host:H{i}", target=f"host:H{i+1}",
            relation=relation, timestamp=datetime(2026, 9, 8, 10, i, tzinfo=timezone.utc),
            confidence=0.9, related_event_ids=[f"evt-{i}"], attack_technique_id="T1021",
            attributes={"correlation_rule": "test"},
        )
        for i, relation in enumerate(["initial_access", "execute", "privilege_escalation", "lateral_movement", "c2_communication", "data_exfiltration"])
    ]
    score, breakdown = calculate_path_score(edges)
    assert 0.0 <= score <= 1.0
    assert set(breakdown) == {"edge_confidence", "evidence_completeness", "temporal_continuity", "entity_continuity", "attack_sequence", "stage_coverage"}
    assert breakdown["stage_coverage"] == 1.0


def test_end_to_end_external_web_office_db_c2():
    web_smb, office_login, _ = remote_pair(445, "T1021.002")
    office_rdp = event(
        "evt-rdp", 18, "OFFICE01", "10.0.0.20", "network_connection", "connect",
        source_type="network_traffic", network=NetworkInfo(src_ip="10.0.0.20", dst_ip="10.0.0.30", dst_port=3389),
    )
    db_login = event(
        "evt-db-login", 19, "DB01", "10.0.0.30", "user_login", "login",
        source_type="host_log", network=NetworkInfo(src_ip="10.0.0.20", dst_ip="10.0.0.30"), tags=["successful"],
    )
    events = [db_login, office_login, office_rdp, web_smb]
    detections = [
        DetectionResult(
            detection_id="det-initial", timestamp="2026-09-08T10:02:00Z", analyzer="initial_access",
            detection_type="malicious_behavior", title="Initial access", confidence=0.95,
            related_entity_ids=["ip:203.0.113.8", "host:WEB01"], attack_technique_id="T1190", tags=["initial_access"],
        ),
        DetectionResult(
            detection_id="det-c2", timestamp="2026-09-08T10:25:00Z", analyzer="c2_detector",
            detection_type="malicious_behavior", title="C2", confidence=0.93,
            related_entity_ids=["host:DB01", "ip:8.8.8.8"], attack_technique_id="T1071.001", tags=["c2_communication"],
        ),
    ]
    result = AttackTraceService().analyze(reversed(events), reversed(detections))
    path = result["paths"][0]
    assert path["nodes"] == ["ip:203.0.113.8", "host:WEB01", "host:OFFICE01", "host:DB01", "ip:8.8.8.8"]
    assert path["relations"] == ["initial_access", "lateral_movement", "lateral_movement", "c2_communication"]
    assert 0.0 <= path["score"] <= 1.0
    assert len(path["score_breakdown"]) == 6
