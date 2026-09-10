from fastapi import APIRouter

from app.services.demo_data import DEMO_EVENTS


router = APIRouter()


@router.get("/")
def list_events() -> dict[str, list]:
    """查询标准化安全事件"""

    return {"events": DEMO_EVENTS}