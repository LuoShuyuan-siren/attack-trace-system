from typing import Any

from app.analyzers.tracing import AttackTraceService
from app.services.runtime_store import DETECTIONS, EVENTS


_trace_service = AttackTraceService()


def build_trace_result() -> dict[str, Any]:
    """根据当前运行时事件和检测结果生成攻击图、攻击链和路径。"""

    return _trace_service.analyze(
        events=EVENTS,
        detections=DETECTIONS,
    )