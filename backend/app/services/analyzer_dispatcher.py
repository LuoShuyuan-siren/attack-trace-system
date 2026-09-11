from app.analyzers.host_behavior import HostBehaviorAnalyzer
from app.analyzers.traffic import (
    ConnectionAnalyzer,
    DnsAnalyzer,
    HttpAnalyzer,
    IcmpAnalyzer,
    SuricataAlertAnalyzer,
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
            SuricataAlertAnalyzer(),
        ]
        for analyzer in analyzers:
            detections.extend(analyzer.analyze(events))

        event_by_id = {event.event_id: event for event in events}

        for detection in detections:
            # SuricataAlertAnalyzer 已自行使用攻击活动首次出现时间，
            # 不再覆盖，否则会破坏攻击链时间顺序。
            if detection.analyzer == "suricata_alert_analyzer":
                continue

            related_events = [
                event_by_id[event_id]
                for event_id in detection.related_event_ids
                if event_id in event_by_id
            ]

            if related_events:
                detection.timestamp = max(
                    event.timestamp for event in related_events
                )

        return detections

    raise ValueError(f"未知 source_type: {source_type}")