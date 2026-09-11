"""从攻击图中生成按时间排序的攻击链阶段。"""

from __future__ import annotations

from typing import Any

from app.analyzers.tracing.normalization import utc_datetime
from app.schemas.attack_graph import AttackGraph


RELATION_STAGES = {
    "initial_access": "initial_access",
    "spawn": "execution",
    "execute": "execution",
    "privilege_escalation": "privilege_escalation",
    "lateral_movement": "lateral_movement",
    "c2_communication": "command_and_control",
    "data_exfiltration": "exfiltration",
}


class AttackChainReconstructor:
    """保留证据引用地将语义边转换为攻击阶段。"""

    def reconstruct(self, graph: AttackGraph) -> list[dict[str, Any]]:
        stages: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str | None]] = set()

        for edge in sorted(
            graph.edges,
            key=lambda item: (
                item.timestamp is None,
                utc_datetime(item.timestamp) if item.timestamp else None,
                item.edge_id,
            ),
        ):
            stage = RELATION_STAGES.get(edge.relation)
            if not stage:
                continue
            key = (stage, edge.source, edge.target, edge.attack_technique_id)
            if key in seen:
                continue
            seen.add(key)
            stages.append(
                {
                    "stage": stage,
                    "source": edge.source,
                    "target": edge.target,
                    "timestamp": utc_datetime(edge.timestamp) if edge.timestamp else None,
                    "technique_id": edge.attack_technique_id,
                    "confidence": edge.confidence,
                    "related_event_ids": edge.related_event_ids,
                    "related_detection_ids": edge.related_detection_ids,
                }
            )
        return stages
