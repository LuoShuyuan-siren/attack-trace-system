from fastapi import APIRouter


router = APIRouter()


@router.get("/sources")
def list_data_sources() -> dict[str, list[str]]:
    """返回当前系统支持的数据源类型"""

    return {
        "source_types": [
            "host_log",
            "host_behavior",
            "network_traffic",
        ]
    }