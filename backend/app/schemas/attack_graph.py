from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field


NodeType = Literal[
    "host",
    "user",
    "process",
    "file",
    "ip",
    "domain",
    "registry",
    "service",
]


class AttackNode(BaseModel):
    """攻击关系图节点"""

    node_id: str

    node_type: NodeType

    name: str

    severity: Literal[
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ] = "info"

    attributes: dict[str, Any] = Field(default_factory=dict)

    tags: list[str] = Field(default_factory=list)


class AttackEdge(BaseModel):
    """攻击关系图中的实体关系"""

    edge_id: str

    source: str

    target: str

    relation: str

    timestamp: datetime | None = None

    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
    )

    related_event_ids: list[str] = Field(default_factory=list)

    related_detection_ids: list[str] = Field(default_factory=list)

    attack_technique_id: str | None = None

    attributes: dict[str, Any] = Field(default_factory=dict)


class AttackGraph(BaseModel):
    """完整攻击关系图"""

    graph_id: str

    nodes: list[AttackNode] = Field(default_factory=list)

    edges: list[AttackEdge] = Field(default_factory=list)

    start_time: datetime | None = None

    end_time: datetime | None = None

    description: str | None = None