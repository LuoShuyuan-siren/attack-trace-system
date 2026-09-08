from fastapi import APIRouter


router = APIRouter()


@router.get("/")
def list_events() -> dict[str, list]:
    """查询标准化安全事件"""

    return {
        "events": []
    }