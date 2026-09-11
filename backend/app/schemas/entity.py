from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


EntityType = Literal[
    "host",
    "user",
    "process",
    "file",
    "ip",
    "domain",
    "registry",
    "service",
]


class Entity(BaseModel):
    """攻击溯源系统中的统一实体"""

    entity_id: str

    entity_type: EntityType

    name: str

    host_id: str | None = None

    first_seen: datetime | None = None
    last_seen: datetime | None = None

    attributes: dict[str, Any] = Field(default_factory=dict)

    tags: list[str] = Field(default_factory=list)