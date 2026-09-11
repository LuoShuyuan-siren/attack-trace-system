from datetime import datetime, timedelta, timezone

from app.analyzers.tracing.path_finder import AttackPathFinder
from app.schemas.attack_graph import AttackEdge, AttackGraph, AttackNode

BASE = datetime(2026, 9, 8, 10, tzinfo=timezone.utc)


def edge(name, source, target, relation, minute, confidence=0.9):
    return AttackEdge(
        edge_id=name, source=source, target=target, relation=relation,
        timestamp=BASE + timedelta(minutes=minute), confidence=confidence,
        related_event_ids=[f"evt-{name}"], attack_technique_id="T1021",
        attributes={"rule": "test"},
    )


def graph(edges):
    ids = {value for item in edges for value in (item.source, item.target)}
    nodes = [
        AttackNode(node_id=value, node_type="host", name=value.split(":", 1)[1])
        for value in ids
    ]
    return AttackGraph(graph_id="robustness", nodes=nodes, edges=edges)


def test_cycle_does_not_loop_or_duplicate_paths():
    paths = AttackPathFinder().find_paths(graph([
        edge("a", "host:A", "host:B", "initial_access", 0),
        edge("b", "host:B", "host:C", "lateral_movement", 1),
        edge("c", "host:C", "host:A", "c2_communication", 2),
    ]))
    signatures = [tuple(path["edges"]) for path in paths]
    assert len(signatures) == len(set(signatures))
    assert all(len(path["edges"]) <= 3 for path in paths)


def test_repeated_stage_and_multiple_lateral_moves():
    path = AttackPathFinder().find_paths(graph([
        edge("a", "host:A", "host:B", "initial_access", 0),
        edge("b", "host:B", "host:C", "lateral_movement", 1),
        edge("c", "host:C", "host:D", "lateral_movement", 2),
        edge("d", "host:D", "host:E", "c2_communication", 3),
    ]))[0]
    assert path["relations"].count("lateral_movement") == 2
    assert 0 <= path["score"] <= 1


def test_shared_nodes_produce_distinct_paths():
    paths = AttackPathFinder().find_paths(graph([
        edge("a", "host:A", "host:B", "initial_access", 0),
        edge("b1", "host:B", "host:C", "lateral_movement", 1),
        edge("b2", "host:B", "host:D", "lateral_movement", 1),
        edge("c1", "host:C", "host:E", "c2_communication", 2),
        edge("c2", "host:D", "host:E", "c2_communication", 2),
    ]))
    assert len(paths) == 2
    assert paths[0]["nodes"] != paths[1]["nodes"]


def test_high_quality_short_path_beats_low_confidence_long_path():
    paths = AttackPathFinder().find_paths(graph([
        edge("h1", "host:A", "host:B", "initial_access", 0, 0.99),
        edge("h2", "host:B", "host:C", "c2_communication", 1, 0.99),
        edge("l1", "host:X", "host:Y", "initial_access", 0, 0.1),
        edge("l2", "host:Y", "host:Z", "execute", 1, 0.1),
        edge("l3", "host:Z", "host:Q", "lateral_movement", 2, 0.1),
    ]))
    assert paths[0]["nodes"][0] == "host:A"
    assert paths[0]["score"] > paths[1]["score"]


def test_time_reversal_noise_and_incomplete_branches_are_safe():
    edges = [
        edge("good1", "host:A", "host:B", "initial_access", 0),
        edge("good2", "host:B", "host:C", "c2_communication", 2),
        edge("reverse", "host:C", "host:D", "data_exfiltration", 1),
        *[
            edge(f"noise{i}", "host:B", f"host:N{i}", "lateral_movement", 3 + i, 0.05)
            for i in range(100)
        ],
        edge("incomplete", "host:ONLY", "host:END", "initial_access", 0),
    ]
    paths = AttackPathFinder().find_paths(graph(edges))
    assert not any("reverse" in path["edges"] for path in paths)
    assert all(
        0 <= path["score"] <= 1 and len(path["score_breakdown"]) == 6
        for path in paths
    )


def test_near_scoring_paths_remain_distinct_and_deterministic():
    candidate_graph = graph([
        edge("a1", "host:A", "host:B", "initial_access", 0, 0.90),
        edge("a2", "host:B", "host:C", "c2_communication", 1, 0.90),
        edge("b1", "host:X", "host:Y", "initial_access", 0, 0.89),
        edge("b2", "host:Y", "host:Z", "c2_communication", 1, 0.89),
    ])
    finder = AttackPathFinder()
    first = finder.find_paths(candidate_graph)
    second = finder.find_paths(candidate_graph)
    assert [path["edges"] for path in first] == [path["edges"] for path in second]
    assert len(first) == 2
    assert first[0]["score"] >= first[1]["score"]


def test_path_with_missing_intermediate_stages_is_still_scored_safely():
    paths = AttackPathFinder().find_paths(graph([
        edge("initial", "host:A", "host:B", "initial_access", 0),
        edge("exfil", "host:B", "host:C", "data_exfiltration", 1),
    ]))
    assert len(paths) == 1
    assert paths[0]["relations"] == ["initial_access", "data_exfiltration"]
    assert 0 <= paths[0]["score_breakdown"]["stage_coverage"] <= 1
