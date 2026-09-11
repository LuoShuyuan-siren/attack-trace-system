"""Internal models for the tracing multi-agent layer."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class TraceContext(BaseModel):
    graph_summary: dict[str, Any]
    attack_stages: list[dict[str, Any]] = Field(default_factory=list)
    candidate_paths: list[dict[str, Any]] = Field(default_factory=list)
    diagnostics: dict[str, int] = Field(default_factory=dict)
    related_event_ids: list[str] = Field(default_factory=list)
    related_detection_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    attack_technique_ids: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    indicators: list[str] = Field(default_factory=list)


class ChainReview(BaseModel):
    status: Literal["supported", "weak", "unsupported"]
    confidence: float = Field(ge=0, le=1)
    supported_stages: list[str] = Field(default_factory=list)
    weak_stages: list[str] = Field(default_factory=list)
    missing_stages: list[str] = Field(default_factory=list)
    suspicious_edges: list[str] = Field(default_factory=list)
    evidence_ids: list[str] = Field(default_factory=list)
    summary: str


class StageEvidenceReview(BaseModel):
    stage: str
    status: Literal["supported", "weak", "unsupported"]
    supported: bool
    confidence: float = Field(ge=0, le=1)
    event_ids: list[str] = Field(default_factory=list)
    detection_ids: list[str] = Field(default_factory=list)
    edge_ids: list[str] = Field(default_factory=list)
    missing_evidence: list[str] = Field(default_factory=list)
    explanation: str


class EvidenceReview(BaseModel):
    stages: list[StageEvidenceReview] = Field(default_factory=list)
    overall_confidence: float = Field(ge=0, le=1)


class AttributionReview(BaseModel):
    techniques: list[str] = Field(default_factory=list)
    ttp_pattern: list[str] = Field(default_factory=list)
    possible_profile: str
    similarity_reasoning: list[str] = Field(default_factory=list)
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str] = Field(default_factory=list)


class TraceReport(BaseModel):
    attack_origin: str
    timeline: list[str] = Field(default_factory=list)
    victim_hosts: list[str] = Field(default_factory=list)
    lateral_movement_path: list[str] = Field(default_factory=list)
    privilege_escalation: str
    c2_communication: str
    data_exfiltration: str
    techniques: list[str] = Field(default_factory=list)
    key_evidence_ids: list[str] = Field(default_factory=list)
    overall_confidence: float = Field(ge=0, le=1)
    uncertainties: list[str] = Field(default_factory=list)
    summary: str


class AgentStatus(BaseModel):
    enabled: bool
    degraded: bool
    errors: list[str] = Field(default_factory=list)
