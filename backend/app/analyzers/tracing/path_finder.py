"""攻击图上的有向路径搜索。"""

from __future__ import annotations

from collections import defaultdict
from math import prod
from typing import Any

from app.analyzers.tracing.normalization import utc_datetime
from app.analyzers.tracing.path_scorer import calculate_path_score
from app.schemas.attack_graph import AttackEdge, AttackGraph


ATTACK_RELATIONS = {
    "initial_access",
    "spawn",
    "execute",
    "privilege_escalation",
    "lateral_movement",
    "c2_communication",
    "data_exfiltration",
}


class AttackPathFinder:
    """枚举语义攻击边构成的无环路径，并按证据强度排序。"""

    def find_paths(
        self,
        graph: AttackGraph,
        *,
        max_depth: int = 12,
        minimum_edges: int = 2,
    ) -> list[dict[str, Any]]:
        if max_depth < 1:
            raise ValueError("max_depth must be at least 1")
        if minimum_edges < 1:
            raise ValueError("minimum_edges must be at least 1")

        attack_edges = [edge for edge in graph.edges if edge.relation in ATTACK_RELATIONS]
        adjacency: dict[str, list[AttackEdge]] = defaultdict(list)
        incoming: set[str] = set()
        for edge in attack_edges:
            adjacency[edge.source].append(edge)
            incoming.add(edge.target)
        for edges in adjacency.values():
            edges.sort(
                key=lambda edge: (
                    edge.timestamp is None,
                    utc_datetime(edge.timestamp) if edge.timestamp else None,
                    edge.edge_id,
                )
            )

        roots = sorted(set(adjacency).difference(incoming)) or sorted(adjacency)
        paths: list[list[AttackEdge]] = []
        for root in roots:
            self._walk(adjacency, root, [], {root}, paths, max_depth, minimum_edges)

        results = [self._serialize(path) for path in paths]
        return sorted(
            results,
            key=lambda path: (-path["score"], -len(path["edges"]), path["nodes"]),
        )

    def _walk(
        self,
        adjacency: dict[str, list[AttackEdge]],
        current: str,
        path: list[AttackEdge],
        visited: set[str],
        results: list[list[AttackEdge]],
        max_depth: int,
        minimum_edges: int,
    ) -> None:
        candidates = [
            edge
            for edge in adjacency.get(current, [])
            if edge.target not in visited
            and self._chronological(path[-1] if path else None, edge)
        ]
        if not candidates or len(path) >= max_depth:
            if len(path) >= minimum_edges:
                results.append(path)
            return
        for edge in candidates:
            self._walk(
                adjacency,
                edge.target,
                [*path, edge],
                visited | {edge.target},
                results,
                max_depth,
                minimum_edges,
            )

    @staticmethod
    def _chronological(previous: AttackEdge | None, current: AttackEdge) -> bool:
        if not previous or previous.timestamp is None or current.timestamp is None:
            return True
        return utc_datetime(current.timestamp) >= utc_datetime(previous.timestamp)

    @staticmethod
    def _serialize(path: list[AttackEdge]) -> dict[str, Any]:
        path_score, score_breakdown = calculate_path_score(path)
        nodes = [path[0].source, *(edge.target for edge in path)]
        event_ids = list(
            dict.fromkeys(event_id for edge in path for event_id in edge.related_event_ids)
        )
        detection_ids = list(
            dict.fromkeys(
                detection_id
                for edge in path
                for detection_id in edge.related_detection_ids
            )
        )
        return {
            "nodes": nodes,
            "edges": [edge.edge_id for edge in path],
            "relations": [edge.relation for edge in path],
            "start_time": (
                utc_datetime(path[0].timestamp) if path[0].timestamp else None
            ),
            "end_time": (
                utc_datetime(path[-1].timestamp) if path[-1].timestamp else None
            ),
            "confidence": round(prod(edge.confidence for edge in path), 4),
            "score": path_score,
            "score_breakdown": score_breakdown,
            "related_event_ids": event_ids,
            "related_detection_ids": detection_ids,
        }
