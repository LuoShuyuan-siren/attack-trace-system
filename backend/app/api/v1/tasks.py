from fastapi import APIRouter, HTTPException

from app.services.runtime_store import (
    ATTACK_MAPPINGS,
    DETECTIONS,
    EVENTS,
    TASKS,
    persist_runtime_state,
)


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


@router.post("/{task_id}/remove")
def remove_task(task_id: str) -> dict:
    """撤销已加载任务，并移除该任务产生的运行时证据。"""
    task = TASKS.get(task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="任务不存在")
    if task.get("status") in {"running", "pending"}:
        raise HTTPException(status_code=409, detail="任务仍在执行，不能撤销")

    event_ids = set(task.get("event_ids", []))
    detection_ids = set(task.get("detection_ids", []))
    mapping_ids = set(task.get("mapping_ids", [])) or detection_ids
    EVENTS[:] = [event for event in EVENTS if event.event_id not in event_ids]
    DETECTIONS[:] = [
        detection for detection in DETECTIONS
        if detection.detection_id not in detection_ids
    ]
    ATTACK_MAPPINGS[:] = [
        mapping for mapping in ATTACK_MAPPINGS
        if mapping.detection_id not in mapping_ids
    ]
    persist_runtime_state()
    removed_task = {**task, "status": "removed", "progress": 0}
    TASKS.pop(task_id, None)
    return removed_task