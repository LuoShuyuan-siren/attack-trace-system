from pathlib import Path
from tempfile import gettempdir
from typing import Literal
from uuid import uuid4
import shutil

from fastapi import APIRouter, File, Form, HTTPException, UploadFile

from app.services.parser_dispatcher import get_parser
from app.services.runtime_store import (
    ATTACK_MAPPINGS,
    DETECTIONS,
    EVENTS,
    TASKS,
    persist_runtime_state,
)

from datetime import datetime, timezone

from app.services.analyzer_dispatcher import analyze_events

from app.services.attack_mapping_service import map_detections
from app.services.session_reconstruction import SessionReconstructionService
from app.services.forensics_enrichment import align_event_times

router = APIRouter()

SourceType = Literal[
    "host_log",
    "host_behavior",
    "network_traffic",
]


@router.get("/sources")
def list_data_sources() -> dict[str, list[str]]:
    """返回当前系统支持的数据源类型。"""

    return {
        "source_types": [
            "host_log",
            "host_behavior",
            "network_traffic",
        ]
    }


@router.post("/upload")
def upload_data(
    file: UploadFile = File(...),
    source_type: SourceType = Form(...),
) -> dict:
    """上传原始数据并立即解析为标准化事件。"""

    task_id = f"task-{uuid4()}"
    now = datetime.now(timezone.utc).isoformat()

    TASKS[task_id] = {
        "task_id": task_id,
        "name": f"{source_type} 数据分析",
        "status": "running",
        "progress": 20,
        "created_at": now,
        "updated_at": now,
    }

    upload_dir = Path(gettempdir()) / "attack-trace-system" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

    safe_name = Path(file.filename or "upload.dat").name
    stored_path = upload_dir / f"{task_id}_{safe_name}"

    try:
        with stored_path.open("wb") as output:
            shutil.copyfileobj(file.file, output)

        TASKS[task_id]["progress"] = 50
        TASKS[task_id]["updated_at"] = datetime.now(timezone.utc).isoformat()

        parser = get_parser(source_type, stored_path)
        events = parser.parse(stored_path)

        events = align_event_times(events)
        EVENTS.extend(events)

        detections = analyze_events(source_type, events)

        attack_mappings = map_detections(detections)

        mapping_by_detection_id = {
            mapping.detection_id: mapping
            for mapping in attack_mappings
        }

        for detection in detections:
            mapping = mapping_by_detection_id.get(detection.detection_id)

            if mapping and mapping.technique_id != "unknown":
                detection.attack_technique_id = mapping.technique_id

        DETECTIONS.extend(detections)
        ATTACK_MAPPINGS.extend(attack_mappings)
        persist_runtime_state()

        session_summary = SessionReconstructionService().build_summary(events)

        TASKS[task_id].update({
            "status": "success",
            "progress": 100,
            "updated_at": datetime.now(timezone.utc).isoformat(),
            "session_count": session_summary["session_count"],
            "suspicious_processes": session_summary["suspicious_processes"],
        })

    except ValueError as exc:
        TASKS[task_id].update({
            "status": "failed",
            "progress": 100,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    except Exception as exc:
        TASKS[task_id].update({
            "status": "failed",
            "progress": 100,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        })
        raise HTTPException(
            status_code=500,
            detail=f"文件解析失败: {exc}",
        ) from exc

    return {
        "task_id": task_id,
        "status": "success",
        "progress": 100,
        "message": (
            f"分析完成，共生成 {len(events)} 条事件，"
            f"{len(detections)} 条检测结果，"
            f"{len(attack_mappings)} 条 ATT&CK 映射"
        ),
        "event_count": len(events),
        "detection_count": len(detections),
        "attack_mapping_count": len(attack_mappings),
        "session_count": SessionReconstructionService().build_summary(events)["session_count"],
        "suspicious_processes": SessionReconstructionService().build_summary(events)["suspicious_processes"],
        "attack_mappings": [
            mapping.to_dict()
            for mapping in attack_mappings
        ],
    }