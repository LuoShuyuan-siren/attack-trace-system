from typing import Any

from fastapi import APIRouter

from app.services.runtime_store import ATTACK_MAPPINGS
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

        for tactic in mapping.tactics:
            stages.append({
                "stage": tactic.stage,
                "host": host,
                "technique_id": mapping.technique_id,
            })

    return {"stages": stages}