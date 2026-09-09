"""网络流量分析器共用基类与工具。"""

from datetime import datetime, timezone

from app.core.analyzer import BaseAnalyzer
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


class TrafficAnalyzerBase(BaseAnalyzer):
    """网络流量分析器基类，提供共用辅助方法。"""

    def _make_detection(
        self,
        title: str,
        description: str,
        detection_type: str,
        severity: str,
        confidence: float,
        evidence: dict,
        related_event_ids: list[str] | None = None,
        tags: list[str] | None = None,
        attack_technique_id: str | None = None,
    ) -> DetectionResult:
        """构造 DetectionResult。"""
        return DetectionResult(
            timestamp=datetime.now(timezone.utc),
            analyzer=self.name,
            detection_type=detection_type,  # type: ignore[arg-type]
            title=title,
            description=description,
            severity=severity,  # type: ignore[arg-type]
            confidence=max(0.0, min(1.0, confidence)),
            related_event_ids=related_event_ids or [],
            related_entity_ids=[],
            evidence=evidence,
            attack_technique_id=attack_technique_id,
            tags=tags or [],
        )

    def _filter_traffic_events(
        self,
        events: list[NormalizedEvent],
    ) -> list[NormalizedEvent]:
        """过滤出网络流量相关事件。"""
        return [
            e for e in events
            if e.source_type == "network_traffic"
        ]

    def _extract_dns_info(self, event: NormalizedEvent) -> dict | None:
        """从 NormalizedEvent 中提取 DNS 信息。"""
        dns = event.raw_data.get("dns") if event.raw_data else None
        if isinstance(dns, dict):
            return dns
        return None

    def _extract_http_info(self, event: NormalizedEvent) -> dict | None:
        """从 NormalizedEvent 中提取 HTTP 信息。"""
        http = event.raw_data.get("http") if event.raw_data else None
        if isinstance(http, dict):
            return http
        return None
