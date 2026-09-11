from fastapi import APIRouter, HTTPException

from app.services.runtime_store import TASKS


router = APIRouter()


@router.get("/")
def list_tasks() -> dict[str, list]:
    """获取所有运行时分析任务。"""

    return {
        "items": list(TASKS.values())
    }


@router.get("/{task_id}")
def get_task(task_id: str) -> dict:
    """根据 task_id 获取单个分析任务状态。"""

    task = TASKS.get(task_id)

    if task is None:
        raise HTTPException(
            status_code=404,
            detail="任务不存在",
        )

    return task