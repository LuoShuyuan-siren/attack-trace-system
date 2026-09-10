from typing import Any

from fastapi import APIRouter

from app.services.demo_data import DEMO_CHAIN, DEMO_GRAPH


router = APIRouter()


@router.get("/graph")
def get_attack_graph() -> dict[str, Any]:
    """获取攻击关系图"""

    return DEMO_GRAPH


@router.get("/chain")
def get_attack_chain() -> dict[str, list]:
    """获取攻击链"""

    return DEMO_CHAIN