from fastapi import APIRouter

from app.schemas.event import NormalizedEvent
from app.services.runtime_store import EVENTS


router = APIRouter()


@router.get("/")
def list_events() -> dict[str, list[NormalizedEvent]]:
    """查询运行时产生的标准化安全事件。"""

    return {"events": EVENTS}