from fastapi import APIRouter

from app.schemas.event import NormalizedEvent
from app.services.runtime_store import EVENTS
from app.services.session_reconstruction import SessionReconstructionService

router = APIRouter()


@router.get("/sessions")
def get_sessions() -> dict[str, list[dict[str, object]]]:
    """返回重建后的登录会话。"""
    service = SessionReconstructionService()
    return {"sessions": service.reconstruct_sessions(EVENTS)}


@router.get("/sessions/summary")
def get_session_summary() -> dict[str, object]:
    """返回会话摘要，附带高风险进程信息。"""
    service = SessionReconstructionService()
    return service.build_summary(EVENTS)
