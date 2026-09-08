from app.analyzers.tracing import AttackChainReconstructor, AttackGraphBuilder
from app.schemas.detection import DetectionResult
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent, ObjectInfo, SubjectInfo


def test_build_graph_from_cross_source_events() -> None:
    process_event = NormalizedEvent(
        event_id="evt-process",
        timestamp="2026-09-08T10:20:00Z",
        source_type="host_behavior",
        source="windows_sysmon",
        host=HostInfo(hostname="WEB01", ip="10.0.0.10", os="windows"),
        event_type="file_create",
        subject=SubjectInfo(type="process", name="powershell.exe", pid=3152),
        object=ObjectInfo(type="file", name="payload.exe", path="C:\\Temp\\payload.exe"),
        action="create_file",
        severity="high",
    )
    network_event = NormalizedEvent(
        event_id="evt-network",
        timestamp="2026-09-08T10:21:00Z",
        source_type="network_traffic",
        source="zeek",
        host=HostInfo(hostname="WEB01", ip="10.0.0.10"),
        event_type="network_connection",
        network=NetworkInfo(src_ip="10.0.0.10", dst_ip="10.0.0.20", dst_port=445),
        action="connect",
    )

    graph = AttackGraphBuilder().build([network_event, process_event])

    node_ids = {node.node_id for node in graph.nodes}
    assert "host:WEB01" in node_ids
    assert "process:WEB01:3152" in node_ids
    assert "file:WEB01:C:\\Temp\\payload.exe" in node_ids
    assert "ip:10.0.0.10" in node_ids
    assert "ip:10.0.0.20" in node_ids
    assert {edge.relation for edge in graph.edges} == {"write", "connect"}
    assert graph.start_time == process_event.timestamp
    assert graph.end_time == network_event.timestamp


def test_detection_adds_semantic_edge_and_chain_stage() -> None:
    detection = DetectionResult(
        detection_id="det-lateral",
        timestamp="2026-09-08T10:30:00Z",
        analyzer="lateral_movement_analyzer",
        detection_type="malicious_behavior",
        title="SMB lateral movement",
        severity="high",
        confidence=0.91,
        related_event_ids=["evt-network"],
        related_entity_ids=["host:WEB01", "host:PC01"],
        attack_technique_id="T1021.002",
        tags=["lateral_movement"],
    )

    graph = AttackGraphBuilder().build([], [detection])
    stages = AttackChainReconstructor().reconstruct(graph)

    assert len(graph.edges) == 1
    assert graph.edges[0].relation == "lateral_movement"
    assert graph.edges[0].related_detection_ids == ["det-lateral"]
    assert stages[0]["stage"] == "lateral_movement"
    assert stages[0]["source"] == "host:WEB01"
    assert stages[0]["target"] == "host:PC01"


def test_invalid_entity_ids_do_not_create_dangling_edges() -> None:
    detection = DetectionResult(
        timestamp="2026-09-08T10:30:00Z",
        analyzer="test_analyzer",
        detection_type="anomaly",
        title="Invalid entity reference",
        related_entity_ids=["not-an-entity", "host:WEB01"],
    )

    graph = AttackGraphBuilder().build([], [detection])

    assert [node.node_id for node in graph.nodes] == ["host:WEB01"]
    assert graph.edges == []
