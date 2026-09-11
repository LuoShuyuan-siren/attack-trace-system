from datetime import timezone

import pytest

from app.analyzers.tracing import AttackGraphBuilder
from app.analyzers.tracing.entity_utils import node_from_id
from app.schemas.attack_graph import AttackEdge, AttackGraph, AttackNode
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent


def make_event(**changes) -> NormalizedEvent:
    values = {
        "event_id": "evt-contract",
        "timestamp": "2026-09-08T10:20:00",
        "source_type": "network_traffic",
        "source": "zeek",
        "host": HostInfo(hostname="WEB01", ip="10.0.0.10"),
        "event_type": "network_connection",
        "network": NetworkInfo(src_ip="10.0.0.10", dst_ip="10.0.0.20"),
        "action": "Open TCP Connection",
    }
    values.update(changes)
    return NormalizedEvent(**values)


def test_graph_output_uses_public_models_and_fields() -> None:
    graph = AttackGraphBuilder().build([make_event()])

    assert isinstance(graph, AttackGraph)
    assert all(isinstance(node, AttackNode) for node in graph.nodes)
    assert all(isinstance(edge, AttackEdge) for edge in graph.edges)
    assert set(graph.edges[0].model_dump()) == {
        "edge_id",
        "source",
        "target",
        "relation",
        "timestamp",
        "confidence",
        "related_event_ids",
        "related_detection_ids",
        "attack_technique_id",
        "attributes",
    }


def test_relation_is_snake_case_and_naive_time_becomes_utc() -> None:
    graph = AttackGraphBuilder().build([make_event()])
    connect_edge = next(edge for edge in graph.edges if edge.relation == "connect")

    assert connect_edge.timestamp.tzinfo == timezone.utc
    assert graph.start_time.tzinfo == timezone.utc
    assert graph.model_dump(mode="json")["start_time"].endswith("Z")


def test_non_snake_case_event_type_is_rejected() -> None:
    with pytest.raises(ValueError, match="event_type must use lowercase snake_case"):
        AttackGraphBuilder().build([make_event(event_type="Network Connection")])


@pytest.mark.parametrize(
    "entity_id",
    [
        "host:WEB01",
        "user:WEB01:administrator",
        "process:WEB01:3152",
        "file:WEB01:C:\\Temp\\payload.exe",
        "ip:192.168.1.20",
        "domain:evil.example.com",
    ],
)
def test_documented_entity_ids_are_accepted(entity_id: str) -> None:
    assert node_from_id(entity_id) is not None


@pytest.mark.parametrize(
    "entity_id",
    ["host:", "user:administrator", "process:WEB01:not-a-pid", "ip:not-an-ip"],
)
def test_malformed_entity_ids_are_rejected(entity_id: str) -> None:
    assert node_from_id(entity_id) is None
