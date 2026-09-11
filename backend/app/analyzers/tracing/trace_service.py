"""成员 7 攻击溯源流水线门面。"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime
from ipaddress import ip_address
from typing import Any

from app.analyzers.tracing.attack_graph_builder import AttackGraphBuilder
from app.analyzers.tracing.chain_reconstructor import AttackChainReconstructor
from app.analyzers.tracing.path_finder import AttackPathFinder
from app.analyzers.tracing.semantic_correlator import SemanticCorrelator
from app.analyzers.tracing.temporal_correlator import TemporalCorrelator
from app.analyzers.tracing.normalization import is_snake_case
from app.schemas.attack_graph import AttackGraph
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


class AttackTraceService:
    """组合图构建、时间关联、阶段重建和路径搜索。"""

    def __init__(self) -> None:
        self.graph_builder = AttackGraphBuilder()
        self.correlator = TemporalCorrelator()
        self.semantic_correlator = SemanticCorrelator()
        self.chain_reconstructor = AttackChainReconstructor()
        self.path_finder = AttackPathFinder()
        self.last_diagnostics: dict[str, int] = {}

    def analyze(
        self,
        events: Iterable[NormalizedEvent],
        detections: Iterable[DetectionResult] = (),
        *,
        graph_id: str = "graph-current",
    ) -> dict[str, Any]:
        event_list, skipped_events, duplicate_events = self._prepare_events(events)
        detection_list, skipped_detections, duplicate_detections = (
            self._prepare_detections(detections)
        )
        self.last_diagnostics = {
            "accepted_events": len(event_list),
            "skipped_events": skipped_events,
            "duplicate_events": duplicate_events,
            "accepted_detections": len(detection_list),
            "skipped_detections": skipped_detections,
            "duplicate_detections": duplicate_detections,
        }
        graph: AttackGraph = self.graph_builder.build(
            event_list, detection_list, graph_id=graph_id
        )
        graph = self.correlator.correlate(graph, event_list)
        graph = self.semantic_correlator.correlate(graph, event_list, detection_list)
        return {
            "graph": graph,
            "stages": self.chain_reconstructor.reconstruct(graph),
            "paths": self.path_finder.find_paths(graph),
        }

    @staticmethod
    def _prepare_events(
        events: Iterable[NormalizedEvent],
    ) -> tuple[list[NormalizedEvent], int, int]:
        accepted: dict[str, NormalizedEvent] = {}
        skipped = 0
        duplicates = 0
        for event in events:
            try:
                usable = AttackTraceService._usable_event(event)
            except (AttributeError, TypeError, ValueError):
                usable = False
            if not usable:
                skipped += 1
                continue
            if event.event_id in accepted:
                duplicates += 1
                continue
            accepted[event.event_id] = event
        return list(accepted.values()), skipped, duplicates

    @staticmethod
    def _prepare_detections(
        detections: Iterable[DetectionResult],
    ) -> tuple[list[DetectionResult], int, int]:
        accepted: dict[str, DetectionResult] = {}
        skipped = 0
        duplicates = 0
        for detection in detections:
            try:
                usable = isinstance(detection, DetectionResult) and isinstance(
                    detection.timestamp, datetime
                )
            except (AttributeError, TypeError):
                usable = False
            if not usable:
                skipped += 1
                continue
            if detection.detection_id in accepted:
                duplicates += 1
                continue
            accepted[detection.detection_id] = detection
        return list(accepted.values()), skipped, duplicates

    @staticmethod
    def _usable_event(event: object) -> bool:
        if not isinstance(event, NormalizedEvent):
            return False
        if not isinstance(event.timestamp, datetime) or not is_snake_case(event.event_type):
            return False
        addresses = [event.host.ip]
        if event.network:
            addresses.extend([event.network.src_ip, event.network.dst_ip])
        for address in addresses:
            if not address:
                continue
            try:
                ip_address(address.strip())
            except (AttributeError, ValueError):
                return False
        if event.subject and event.subject.pid is not None and event.subject.pid < 0:
            return False
        if event.object and event.object.pid is not None and event.object.pid < 0:
            return False
        return True
