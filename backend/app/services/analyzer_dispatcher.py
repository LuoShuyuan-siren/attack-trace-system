from app.analyzers.host_behavior import HostBehaviorAnalyzer
from app.analyzers.traffic import (
    ConnectionAnalyzer,
    DnsAnalyzer,
    HttpAnalyzer,
    IcmpAnalyzer,
)
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


def analyze_events(
    source_type: str,
    events: list[NormalizedEvent],
) -> list[DetectionResult]:
    """根据数据源类型调用对应分析器。"""

    if source_type in {"host_log", "host_behavior"}:
        analyzer = HostBehaviorAnalyzer()
        return analyzer.analyze(events)

    if source_type == "network_traffic":
        detections: list[DetectionResult] = []

        analyzers = [
            ConnectionAnalyzer(),
            DnsAnalyzer(),
            HttpAnalyzer(),
            IcmpAnalyzer(),
        ]

        for analyzer in analyzers:
            detections.extend(analyzer.analyze(events))

        return detections

    raise ValueError(f"未知 source_type: {source_type}")