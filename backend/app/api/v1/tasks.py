from fastapi import APIRouter


router = APIRouter()


@router.get("/graph")
def get_attack_graph() -> dict[str, list]:
    """获取攻击关系图"""

    return {
        "nodes": [],
        "edges": [],
    }


@router.get("/chain")
def get_attack_chain() -> dict[str, list]:
    """获取攻击链"""

    return {
        "stages": []
    }