from fastapi import APIRouter

from app.schemas.detection import DetectionResult
from app.services.runtime_store import DETECTIONS


router = APIRouter()


@router.get("/")
def list_detections() -> dict[str, list[DetectionResult]]:
    """查询运行时产生的安全检测结果。"""

    return {"items": DETECTIONS}