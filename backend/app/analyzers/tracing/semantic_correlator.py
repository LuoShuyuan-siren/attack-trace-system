"""跨事件行为组合关联，不承担原始数据解析或 ATT&CK 检测。"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import timedelta
from hashlib import sha256
from ipaddress import ip_address

from app.analyzers.tracing.entity_utils import host_id, ip_id, object_id, process_id
from app.analyzers.tracing.normalization import utc_datetime
from app.schemas.attack_graph import AttackEdge, AttackGraph
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


class SemanticCorrelator:
    def __init__(self, window: timedelta = timedelta(minutes=10)) -> None:
        self.window = window
        self._active_detection_index: dict[str, list[DetectionResult]] = {}

    def correlate(
        self,
        graph: AttackGraph,
        events: Iterable[NormalizedEvent],
        detections: Iterable[DetectionResult] = (),
    ) -> AttackGraph:
        ordered = sorted(events, key=lambda e: (utc_datetime(e.timestamp), e.event_id))
        detection_by_event = self._detection_index(detections)
        self._active_detection_index = detection_by_event
        edges = {edge.edge_id: edge.model_copy(deep=True) for edge in graph.edges}
        self._login_execution(ordered, edges)
        self._download_execution(ordered, edges)
        self._file_exfiltration(ordered, edges, detection_by_event)
        self._process_c2(ordered, edges, detection_by_event)
        return graph.model_copy(
            update={"edges": sorted(edges.values(), key=self._edge_sort_key)}, deep=True
        )

    def _login_execution(self, events, edges) -> None:
        auth_events = [e for e in events if e.event_type in {"user_login", "authenticate"}]
        executions = [e for e in events if e.event_type in {"process_create", "execute"}]
        for auth in auth_events:
            username = self._username(auth)
            for execution in executions:
                if not self._within(auth, execution) or auth.host.hostname != execution.host.hostname:
                    continue
                if username and execution.subject and execution.subject.user != username:
                    continue
                if not execution.host.hostname or not execution.subject or execution.subject.pid is None:
                    continue
                self._put_edge(
                    edges,
                    host_id(execution.host.hostname),
                    process_id(execution.host.hostname, execution.subject.pid),
                    "execute",
                    execution,
                    [auth.event_id, execution.event_id],
                    0.82,
                    "login_followed_by_execution",
                    {"user": username},
                )

    def _download_execution(self, events, edges) -> None:
        downloads = [e for e in events if e.action == "download" or "download" in e.tags]
        files = [e for e in events if e.event_type == "file_create" or e.action == "write"]
        executions = [e for e in events if e.event_type in {"process_create", "execute"}]
        for download in downloads:
            for file_event in files:
                if not self._within(download, file_event) or download.host.hostname != file_event.host.hostname:
                    continue
                for execution in executions:
                    if not self._within(file_event, execution) or file_event.host.hostname != execution.host.hostname:
                        continue
                    path = file_event.object.path if file_event.object else None
                    if not path or not execution.subject or execution.subject.pid is None:
                        continue
                    command = str(execution.raw_data.get("command_line", execution.subject.name or ""))
                    if path.lower() not in command.lower() and path.split("\\")[-1].lower() not in command.lower():
                        continue
                    self._put_edge(
                        edges,
                        object_id(file_event.host.hostname, "file", path),
                        process_id(execution.host.hostname, execution.subject.pid),
                        "execute",
                        execution,
                        [download.event_id, file_event.event_id, execution.event_id],
                        0.9,
                        "download_write_execute",
                        {"download_event_id": download.event_id, "file_path": path},
                    )

    def _file_exfiltration(self, events, edges, detection_by_event) -> None:
        reads = [e for e in events if e.event_type == "file_read" or e.action == "read_file"]
        outbound = [e for e in events if self._is_exfil_signal(e, detection_by_event)]
        for read in reads:
            for network in outbound:
                if not self._within(read, network) or read.host.hostname != network.host.hostname:
                    continue
                if not read.object or not (read.object.path or read.object.name) or not network.network or not network.network.dst_ip:
                    continue
                if read.subject and network.subject and read.subject.pid != network.subject.pid:
                    continue
                technique = self._technique(network, detection_by_event)
                self._put_edge(
                    edges,
                    object_id(read.host.hostname, "file", read.object.path or read.object.name),
                    ip_id(network.network.dst_ip),
                    "data_exfiltration",
                    network,
                    [read.event_id, network.event_id],
                    0.88,
                    "file_read_followed_by_outbound_transfer",
                    {"bytes_out": network.raw_data.get("bytes_out")},
                    technique,
                )

    def _process_c2(self, events, edges, detection_by_event) -> None:
        for event in events:
            if event.event_type != "network_connection" or not event.subject or event.subject.pid is None:
                continue
            if not event.host.hostname or not event.network or not event.network.dst_ip:
                continue
            technique = self._technique(event, detection_by_event)
            tags = {tag.lower().replace("-", "_") for tag in event.tags}
            if not technique and not tags.intersection({"c2", "c2_communication"}):
                continue
            if not self._external(event.network.dst_ip):
                continue
            self._put_edge(
                edges,
                process_id(event.host.hostname, event.subject.pid),
                ip_id(event.network.dst_ip),
                "c2_communication",
                event,
                [event.event_id],
                0.9 if technique else 0.75,
                "process_connection_to_external_c2",
                {"matched_external_ip": event.network.dst_ip},
                technique,
            )

    def _put_edge(self, edges, source, target, relation, event, event_ids, confidence, rule, attributes, technique=None):
        identity = "|".join([source, target, relation, *event_ids])
        edge_id = f"edge-{sha256(identity.encode()).hexdigest()[:16]}"
        edges[edge_id] = AttackEdge(
            edge_id=edge_id, source=source, target=target, relation=relation,
            timestamp=utc_datetime(event.timestamp), confidence=confidence,
            related_event_ids=list(dict.fromkeys(event_ids)),
            related_detection_ids=[d.detection_id for d in self._event_detections(event.event_id, self._active_detection_index)],
            attack_technique_id=technique,
            attributes={"correlation_rule": rule, **attributes},
        )

    @staticmethod
    def _detection_index(detections):
        index = {}
        for detection in detections:
            for event_id in detection.related_event_ids:
                index.setdefault(event_id, []).append(detection)
        return index

    @staticmethod
    def _event_detections(event_id, index):
        return index.get(event_id, [])

    def _technique(self, event, index):
        detections = self._event_detections(event.event_id, index)
        return next((d.attack_technique_id for d in detections if d.attack_technique_id), None) or (event.attack.technique_id if event.attack else None)

    def _within(self, first, second):
        delta = utc_datetime(second.timestamp) - utc_datetime(first.timestamp)
        return timedelta(0) <= delta <= self.window

    @staticmethod
    def _username(event):
        return (event.subject.user or event.subject.name) if event.subject else None

    @staticmethod
    def _is_exfil_signal(event, index):
        if event.action == "upload" or "data_exfiltration" in event.tags:
            return True
        if int(event.raw_data.get("bytes_out", 0) or 0) >= 1_000_000:
            return True
        return any("exfil" in d.tags or d.attack_technique_id in {"T1041", "T1048"} for d in index.get(event.event_id, []))

    @staticmethod
    def _external(value):
        address = ip_address(value)
        return not address.is_private and not address.is_loopback and not address.is_link_local

    @staticmethod
    def _edge_sort_key(edge):
        return (edge.timestamp is None, utc_datetime(edge.timestamp) if edge.timestamp else None, edge.edge_id)
