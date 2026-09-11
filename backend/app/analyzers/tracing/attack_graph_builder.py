"""将标准化事件和检测结果关联为攻击关系图。"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from hashlib import sha256

from app.analyzers.tracing.entity_utils import (
    host_id,
    ip_id,
    node_from_id,
    object_id,
    process_id,
    user_id,
)
from app.analyzers.tracing.normalization import is_snake_case, snake_case, utc_datetime
from app.schemas.attack_graph import AttackEdge, AttackGraph, AttackNode
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

SEMANTIC_RELATIONS = {
    "initial_access",
    "spawn",
    "execute",
    "lateral_movement",
    "privilege_escalation",
    "c2_communication",
    "data_exfiltration",
}

TECHNIQUE_RELATIONS = {
    "T1110": "initial_access",
    "T1021": "lateral_movement",
    "T1046": "discovery",
    "T1078": "authenticate",
    "T1133": "initial_access",
    "T1136": "execute",
    "T1190": "initial_access",
    "T1219": "c2_communication",
    "T1548": "privilege_escalation",
    "T1068": "privilege_escalation",
    "T1505": "initial_access",
    "T1071": "c2_communication",
    "T1041": "data_exfiltration",
    "T1048": "data_exfiltration",
}


class AttackGraphBuilder:
    """基于确定性规则构建可解释、可复现的攻击图。"""

    def build(
        self,
        events: Iterable[NormalizedEvent],
        detections: Iterable[DetectionResult] = (),
        graph_id: str = "graph-current",
    ) -> AttackGraph:
        usable_events = [
            event
            for event in events
            if isinstance(event, NormalizedEvent)
            and isinstance(event.timestamp, datetime)
        ]
        usable_detections = [
            detection
            for detection in detections
            if isinstance(detection, DetectionResult)
            and isinstance(detection.timestamp, datetime)
        ]
        ordered_events = sorted(
            usable_events, key=lambda event: (utc_datetime(event.timestamp), event.event_id)
        )
        ordered_detections = sorted(
            usable_detections,
            key=lambda detection: (
                utc_datetime(detection.timestamp),
                detection.detection_id,
            ),
        )
        nodes: dict[str, AttackNode] = {}
        edges: dict[str, AttackEdge] = {}

        for event in ordered_events:
            if not is_snake_case(event.event_type):
                raise ValueError(
                    f"event_type must use lowercase snake_case: {event.event_type!r}"
                )
            event_nodes: dict[str, AttackNode] = {}
            event_edges: dict[str, AttackEdge] = {}
            try:
                self._consume_event(event, event_nodes, event_edges)
            except (AttributeError, TypeError, ValueError):
                continue
            for candidate in event_nodes.values():
                self._upsert_node(nodes, candidate)
            edges.update(event_edges)
        for detection in ordered_detections:
            detection_nodes: dict[str, AttackNode] = {}
            detection_edges: dict[str, AttackEdge] = {}
            try:
                self._consume_detection(detection, detection_nodes, detection_edges)
            except (AttributeError, TypeError, ValueError):
                continue
            for candidate in detection_nodes.values():
                self._upsert_node(nodes, candidate)
            edges.update(detection_edges)

        timestamps = [utc_datetime(event.timestamp) for event in ordered_events]
        timestamps.extend(
            utc_datetime(detection.timestamp) for detection in ordered_detections
        )
        return AttackGraph(
            graph_id=graph_id,
            nodes=sorted(nodes.values(), key=lambda node: node.node_id),
            edges=sorted(
                edges.values(),
                key=lambda edge: (edge.timestamp is None, edge.timestamp, edge.edge_id),
            ),
            start_time=min(timestamps) if timestamps else None,
            end_time=max(timestamps) if timestamps else None,
            description="由标准化事件和检测结果自动关联生成",
        )

    def _consume_event(
        self,
        event: NormalizedEvent,
        nodes: dict[str, AttackNode],
        edges: dict[str, AttackEdge],
    ) -> None:
        hostname = event.host.hostname
        host_node_id = None
        if hostname:
            host_node_id = host_id(hostname)
            self._upsert_node(
                nodes,
                AttackNode(
                    node_id=host_node_id,
                    node_type="host",
                    name=hostname,
                    severity=event.severity,
                    attributes={"ip": event.host.ip, "os": event.host.os},
                ),
            )

        subject_id = self._subject_node(event, nodes, hostname)
        target_id = self._object_node(event, nodes, hostname)

        if subject_id and target_id:
            self._add_edge(
                edges,
                source=subject_id,
                target=target_id,
                relation=self._event_relation(event),
                event=event,
            )
        elif subject_id and host_node_id:
            # Some normalized host sources describe the created/executed process
            # as the subject and preserve its parent only in raw_data.  Keep that
            # valid public-Schema representation connected to the host graph.
            relation = self._event_relation(event)
            if event.subject and event.subject.type == "process" and relation in {
                "spawn",
                "execute",
            }:
                self._add_edge(
                    edges,
                    source=host_node_id,
                    target=subject_id,
                    relation=relation,
                    event=event,
                )

        if event.network and event.network.dst_ip:
            source = self._network_source(event, nodes, host_node_id)
            target = ip_id(event.network.dst_ip)
            self._upsert_node(
                nodes,
                AttackNode(node_id=target, node_type="ip", name=event.network.dst_ip),
            )
            if source:
                relation = "resolve" if event.event_type == "dns_query" else "connect"
                self._add_edge(edges, source, target, relation, event)

        if event.event_type in {"user_login", "user_logout"} and hostname:
            username = event.subject.user if event.subject else None
            username = username or (event.subject.name if event.subject else None)
            if username:
                target = user_id(hostname, username)
                self._upsert_node(
                    nodes,
                    AttackNode(node_id=target, node_type="user", name=username),
                )
                source = self._network_source(event, nodes, host_node_id)
                if source and source != target:
                    relation = "login" if event.event_type == "user_login" else "authenticate"
                    self._add_edge(edges, source, target, relation, event)

    def _consume_detection(
        self,
        detection: DetectionResult,
        nodes: dict[str, AttackNode],
        edges: dict[str, AttackEdge],
    ) -> None:
        entity_ids: list[str] = []
        for entity_id in dict.fromkeys(detection.related_entity_ids):
            node = node_from_id(entity_id)
            if node:
                entity_ids.append(entity_id)
                node.severity = detection.severity
                node.tags = list(detection.tags)
                self._upsert_node(nodes, node)

        if len(entity_ids) < 2:
            return
        relation = self._detection_relation(detection)
        self._add_edge(
            edges,
            source=entity_ids[0],
            target=entity_ids[1],
            relation=relation,
            timestamp=detection.timestamp,
            confidence=detection.confidence,
            related_event_ids=detection.related_event_ids,
            related_detection_ids=[detection.detection_id],
            attack_technique_id=detection.attack_technique_id,
            attributes={"title": detection.title, "evidence": detection.evidence},
        )

    def _subject_node(
        self,
        event: NormalizedEvent,
        nodes: dict[str, AttackNode],
        hostname: str | None,
    ) -> str | None:
        subject = event.subject
        if not subject or not hostname:
            return None
        if subject.type == "process" and subject.pid is not None:
            node_id = process_id(hostname, subject.pid)
            name = subject.name or str(subject.pid)
            attributes = {"pid": subject.pid, "user": subject.user}
            node_type = "process"
        elif subject.type == "user" or subject.user:
            name = subject.user or subject.name
            if not name:
                return None
            node_id = user_id(hostname, name)
            attributes = {}
            node_type = "user"
        else:
            return None
        self._upsert_node(
            nodes,
            AttackNode(
                node_id=node_id,
                node_type=node_type,
                name=name,
                severity=event.severity,
                attributes=attributes,
                tags=list(event.tags),
            ),
        )
        return node_id

    def _object_node(
        self,
        event: NormalizedEvent,
        nodes: dict[str, AttackNode],
        hostname: str | None,
    ) -> str | None:
        obj = event.object
        if not obj or not hostname or not obj.type:
            return None
        if obj.type == "process" and obj.pid is not None:
            node_id = process_id(hostname, obj.pid)
            name = obj.name or str(obj.pid)
            attributes = {"pid": obj.pid}
        elif obj.type in {"file", "registry", "service"}:
            value = obj.path or obj.name
            if not value:
                return None
            node_id = object_id(hostname, obj.type, value)
            name = obj.name or value
            attributes = {"path": obj.path} if obj.path else {}
        else:
            return None
        self._upsert_node(
            nodes,
            AttackNode(
                node_id=node_id,
                node_type=obj.type,
                name=name,
                severity=event.severity,
                attributes=attributes,
                tags=list(event.tags),
            ),
        )
        return node_id

    def _network_source(
        self,
        event: NormalizedEvent,
        nodes: dict[str, AttackNode],
        fallback: str | None,
    ) -> str | None:
        src_ip = event.network.src_ip if event.network else None
        if not src_ip:
            return fallback
        node_id = ip_id(src_ip)
        self._upsert_node(nodes, AttackNode(node_id=node_id, node_type="ip", name=src_ip))
        return node_id

    @staticmethod
    def _event_relation(event: NormalizedEvent) -> str:
        aliases = {
            "create_process": "spawn",
            "execute_process": "execute",
            "execve": "execute",
            "create_file": "write",
            "write_file": "write",
            "modify_file": "modify",
            "delete_file": "modify",
            "read_file": "read",
        }
        return aliases.get(event.action, snake_case(event.action))

    @staticmethod
    def _detection_relation(detection: DetectionResult) -> str:
        for tag in detection.tags:
            normalized = snake_case(tag)
            if normalized in SEMANTIC_RELATIONS:
                return normalized
        technique = detection.attack_technique_id or ""
        for prefix, relation in TECHNIQUE_RELATIONS.items():
            if technique == prefix or technique.startswith(f"{prefix}."):
                return relation
        return detection.detection_type

    @staticmethod
    def _upsert_node(nodes: dict[str, AttackNode], candidate: AttackNode) -> None:
        existing = nodes.get(candidate.node_id)
        if not existing:
            nodes[candidate.node_id] = candidate
            return
        if SEVERITY_RANK[candidate.severity] > SEVERITY_RANK[existing.severity]:
            existing.severity = candidate.severity
        existing.attributes.update(
            {key: value for key, value in candidate.attributes.items() if value is not None}
        )
        existing.tags = sorted(set(existing.tags).union(candidate.tags))

    def _add_edge(
        self,
        edges: dict[str, AttackEdge],
        source: str,
        target: str,
        relation: str,
        event: NormalizedEvent | None = None,
        *,
        timestamp=None,
        confidence: float = 0.5,
        related_event_ids: list[str] | None = None,
        related_detection_ids: list[str] | None = None,
        attack_technique_id: str | None = None,
        attributes: dict | None = None,
    ) -> None:
        if event:
            timestamp = utc_datetime(event.timestamp)
        elif timestamp is not None:
            timestamp = utc_datetime(timestamp)
        event_ids = [event.event_id] if event else list(related_event_ids or [])
        technique_id = (
            event.attack.technique_id if event and event.attack else attack_technique_id
        )
        identity = "|".join(
            [source, target, relation, timestamp.isoformat() if timestamp else "", *event_ids]
        )
        edge_id = f"edge-{sha256(identity.encode('utf-8')).hexdigest()[:16]}"
        edges[edge_id] = AttackEdge(
            edge_id=edge_id,
            source=source,
            target=target,
            relation=relation,
            timestamp=timestamp,
            confidence=confidence,
            related_event_ids=event_ids,
            related_detection_ids=list(related_detection_ids or []),
            attack_technique_id=technique_id,
            attributes=attributes or {},
        )
