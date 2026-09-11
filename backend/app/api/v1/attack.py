from typing import Any

from fastapi import APIRouter

from app.services.runtime_store import ATTACK_MAPPINGS, DETECTIONS
from app.services.tracing_service import build_trace_result


router = APIRouter()


@router.get("/graph")
def get_attack_graph():
    """获取基于真实事件和检测结果生成的攻击关系图。"""

    result = build_trace_result()
    return result["graph"]


@router.get("/chain")
def get_attack_chain() -> dict[str, list]:
    """根据 ATT&CK 映射生成真实攻击链。"""

    stages = []

    for mapping in ATTACK_MAPPINGS:
        host = mapping.hosts[0] if mapping.hosts else "unknown"
        detection = next(
            (item for item in DETECTIONS if item.detection_id == mapping.detection_id),
            None,
        )

        for tactic in mapping.tactics:
            stages.append({
                "stage": tactic.stage,
                "host": host,
                "technique_id": mapping.technique_id,
                "tactic_id": tactic.tactic_id,
                "tactic_name": tactic.tactic_name,
                "timestamp": mapping.timestamp,
                "confidence": mapping.confidence,
                "related_event_ids": detection.related_event_ids if detection else [],
                "related_detection_ids": [mapping.detection_id],
            })

    return {"stages": stages}