"""基于时间窗口和共享实体推断跨主机攻击关系。"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from hashlib import sha256

from app.analyzers.tracing.entity_utils import host_id, node_from_id
from app.analyzers.tracing.normalization import utc_datetime
from app.schemas.attack_graph import AttackEdge, AttackGraph, AttackNode
from app.schemas.event import NormalizedEvent

REMOTE_SERVICES = {
    22: ("ssh", "T1021.004"),
    3389: ("rdp", "T1021.001"),
    445: ("smb", "T1021.002"),
    5985: ("winrm", "T1021.006"),
    5986: ("winrm", "T1021.006"),
}
AUTH_EVENT_TYPES = {
    "user_login",
    "authenticate",
    "authentication_success",
    "remote_session",
    "remote_session_start",
}


class TemporalCorrelator:
    """关联源端连接与目标端登录，推断横向移动。

    规则要求两个事件处于时间窗口内，且连接目标 IP、登录目标主机、登录源 IP
    能形成闭环。这样比只按相同 IP 或相邻时间关联更能抑制误报。
    """

    def __init__(self, window: timedelta = timedelta(minutes=5)) -> None:
        if window <= timedelta(0):
            raise ValueError("window must be greater than zero")
        self.window = window

    def correlate(
        self,
        graph: AttackGraph,
        events: Iterable[NormalizedEvent],
    ) -> AttackGraph:
        ordered_events = sorted(
            events, key=lambda event: (utc_datetime(event.timestamp), event.event_id)
        )
        connections = [
            event
            for event in ordered_events
            if event.event_type == "network_connection"
            and event.network
            and event.network.src_ip
            and event.network.dst_ip
            and event.network.dst_port in REMOTE_SERVICES
        ]
        logins = [
            event
            for event in ordered_events
            if event.event_type in AUTH_EVENT_TYPES
            and event.host.hostname
            and event.network
            and event.network.src_ip
        ]

        nodes = {node.node_id: node.model_copy(deep=True) for node in graph.nodes}
        edges = {edge.edge_id: edge.model_copy(deep=True) for edge in graph.edges}
        ip_hosts = self._ip_host_index(ordered_events)

        for connection in connections:
            for login in logins:
                connection_time = utc_datetime(connection.timestamp)
                login_time = utc_datetime(login.timestamp)
                if login_time < connection_time:
                    continue
                if login_time - connection_time > self.window:
                    break
                if not self._matches(connection, login):
                    continue

                source_hostname = ip_hosts.get(connection.network.src_ip)
                if (
                    not source_hostname
                    or connection.host.hostname != source_hostname
                    or connection.host.ip != connection.network.src_ip
                ):
                    continue
                source = host_id(source_hostname)
                target = host_id(login.host.hostname)
                self._ensure_host(nodes, source, source_hostname)
                self._ensure_host(nodes, target, login.host.hostname)

                evidence_ids = [connection.event_id, login.event_id]
                edge_id = self._edge_id(source, target, connection, login)
                confidence = self._confidence(connection, login)
                service, technique_id = REMOTE_SERVICES[connection.network.dst_port]
                edges[edge_id] = AttackEdge(
                    edge_id=edge_id,
                    source=source,
                    target=target,
                    relation="lateral_movement",
                    timestamp=login_time,
                    confidence=confidence,
                    related_event_ids=evidence_ids,
                    attack_technique_id=technique_id,
                    attributes={
                        "correlation_rule": "network_connection_followed_by_remote_login",
                        "remote_service": service,
                        "remote_port": connection.network.dst_port,
                        "time_delta_seconds": (
                            login_time - connection_time
                        ).total_seconds(),
                        "source_host": source_hostname,
                        "target_host": login.host.hostname,
                        "matched_src_ip": connection.network.src_ip,
                        "matched_target_ip": connection.network.dst_ip,
                        "matched_authentication": login.event_type,
                        "evidence_quality": "high" if confidence >= 0.9 else "medium",
                    },
                )

        timestamps = [
            utc_datetime(edge.timestamp) for edge in edges.values() if edge.timestamp
        ]
        return graph.model_copy(
            update={
                "nodes": sorted(nodes.values(), key=lambda node: node.node_id),
                "edges": sorted(
                    edges.values(),
                    key=lambda edge: (edge.timestamp is None, edge.timestamp, edge.edge_id),
                ),
                "start_time": min(timestamps) if timestamps else graph.start_time,
                "end_time": max(timestamps) if timestamps else graph.end_time,
            },
            deep=True,
        )

    @staticmethod
    def _matches(connection: NormalizedEvent, login: NormalizedEvent) -> bool:
        target_matches = connection.network.dst_ip == login.host.ip
        source_matches = login.network.src_ip == connection.network.src_ip
        return bool(target_matches and source_matches)

    @staticmethod
    def _ip_host_index(events: list[NormalizedEvent]) -> dict[str, str]:
        return {
            event.host.ip: event.host.hostname
            for event in events
            if event.host.ip and event.host.hostname
        }

    @staticmethod
    def _ensure_host(
        nodes: dict[str, AttackNode], node_id: str, hostname: str
    ) -> None:
        if node_id not in nodes:
            node = node_from_id(node_id)
            nodes[node_id] = node or AttackNode(
                node_id=node_id, node_type="host", name=hostname
            )

    @staticmethod
    def _edge_id(
        source: str,
        target: str,
        connection: NormalizedEvent,
        login: NormalizedEvent,
    ) -> str:
        identity = "|".join(
            [
                source,
                target,
                "lateral_movement",
                str(connection.network.dst_port),
                utc_datetime(connection.timestamp).isoformat(),
                utc_datetime(login.timestamp).isoformat(),
            ]
        )
        return f"edge-{sha256(identity.encode('utf-8')).hexdigest()[:16]}"

    @staticmethod
    def _confidence(connection: NormalizedEvent, login: NormalizedEvent) -> float:
        confidence = 0.7
        if connection.network.dst_port in {22, 3389, 445, 5985, 5986}:
            confidence += 0.1
        if "successful" in login.tags or login.action in {"login", "authenticate"}:
            confidence += 0.1
        return round(min(confidence, 0.95), 2)
