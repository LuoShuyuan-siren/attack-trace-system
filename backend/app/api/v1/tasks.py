from fastapi import APIRouter

from app.services.demo_data import DEMO_TASKS


router = APIRouter()


@router.get("/")
def list_tasks() -> dict[str, list]:
    """获取分析任务状态"""

    return {"items": DEMO_TASKS}