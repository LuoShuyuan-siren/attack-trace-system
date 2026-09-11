from typing import Any

from fastapi import APIRouter, HTTPException

from app.services.tracing_service import build_trace_result

from app.services.llm_analysis import analyze_current_attack

router = APIRouter()


@router.get("/graph")
def get_attack_graph():
    """获取基于真实事件和检测结果生成的攻击关系图。"""

    result = build_trace_result()
    return result["graph"]


@router.get("/chain")
def get_attack_chain() -> dict[str, Any]:
    """返回 AttackTraceService 重建的阶段和候选路径。"""

    result = build_trace_result()
    nodes = {node.node_id: node for node in result["graph"].nodes}
    stages = []
    for stage in result["stages"]:
        source = nodes.get(stage.get("source"))
        target = nodes.get(stage.get("target"))
        stages.append({
            **stage,
            "host": next(
                (
                    node.name
                    for node in (source, target)
                    if node and node.node_type == "host"
                ),
                source.name if source else target.name if target else "unknown",
            ),
        })

    paths = result["paths"]
    return {
        "stages": stages,
        "paths": paths,
        "candidate_path_count": len(paths),
        "top_path_score": paths[0]["score"] if paths else None,
    }

@router.get("/ai-analysis")
def get_ai_analysis() -> dict[str, str]:
    """使用大模型综合分析当前攻击事件、检测结果和 ATT&CK 映射。"""

    try:
        analysis = analyze_current_attack()
    except RuntimeError as exc:
        message = str(exc)

        if "未配置" in message:
            raise HTTPException(
                status_code=503,
                detail=message,
            ) from exc

        raise HTTPException(
            status_code=502,
            detail=message,
        ) from exc

    return {
        "analysis": analysis,
    }