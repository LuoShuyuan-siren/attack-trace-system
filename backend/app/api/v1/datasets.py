import json
from pathlib import Path

from fastapi import APIRouter, HTTPException

router = APIRouter()


@router.get("/adfa-ld")
def get_adfa_ld_evaluation() -> dict[str, object]:
    """Return the latest local ADFA-LD evaluation summary."""
    result_path = Path(__file__).resolve().parents[4] / "backend" / "examples" / "adfa_ld_evaluation.json"
    try:
        return json.loads(result_path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="尚未生成 ADFA-LD 评估结果") from exc
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="ADFA-LD 评估结果格式无效") from exc