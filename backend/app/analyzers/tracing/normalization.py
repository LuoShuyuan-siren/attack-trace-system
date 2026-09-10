"""溯源模块内部的格式归一化工具。"""

from __future__ import annotations

import re
from datetime import datetime, timezone


SNAKE_CASE_PATTERN = re.compile(r"^[a-z][a-z0-9]*(?:_[a-z0-9]+)*$")


def utc_datetime(value: datetime) -> datetime:
    """将公共 Schema 接受的 datetime 统一转换为 UTC 感知时间。"""

    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def snake_case(value: str, fallback: str = "unknown") -> str:
    """将可扩展关系名限制为项目约定的小写下划线格式。"""

    normalized = re.sub(r"[^a-z0-9]+", "_", value.strip().lower()).strip("_")
    if not normalized:
        return fallback
    if normalized[0].isdigit():
        normalized = f"relation_{normalized}"
    return normalized


def is_snake_case(value: str) -> bool:
    return bool(SNAKE_CASE_PATTERN.fullmatch(value))
