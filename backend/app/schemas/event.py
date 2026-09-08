from datetime import datetime
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, Field


class HostInfo(BaseModel):
    """事件所属主机信息"""

    hostname: str | None = None
    ip: str | None = None
    os: str | None = None


class SubjectInfo(BaseModel):
    """发起行为的主体，例如进程或用户"""

    type: str | None = None
    name: str | None = None
    pid: int | None = None
    user: str | None = None


class ObjectInfo(BaseModel):
    """行为作用的目标，例如文件、进程、注册表等"""

    type: str | None = None
    name: str | None = None
    path: str | None = None
    pid: int | None = None


class NetworkInfo(BaseModel):
    """网络连接相关信息"""

    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None


class AttackInfo(BaseModel):
    """MITRE ATT&CK 映射信息"""

    technique_id: str | None = None
    technique_name: str | None = None
    tactic: str | None = None


class NormalizedEvent(BaseModel):
    """系统统一安全事件格式"""

    event_id: str = Field(
        default_factory=lambda: f"evt-{uuid4()}"
    )

    timestamp: datetime

    source_type: Literal[
        "host_log",
        "host_behavior",
        "network_traffic",
    ]

    source: str

    host: HostInfo = Field(default_factory=HostInfo)

    event_type: str

    subject: SubjectInfo | None = None
    object: ObjectInfo | None = None
    network: NetworkInfo | None = None

    action: str

    raw_data: dict[str, Any] = Field(default_factory=dict)

    severity: Literal[
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ] = "info"

    attack: AttackInfo | None = None

    tags: list[str] = Field(default_factory=list)