from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.schemas.event import NormalizedEvent
from app.services.event_ingestion import ingest_events
from app.services.runtime_store import (
    ATTACK_MAPPINGS,
    DETECTIONS,
    EVENTS,
    INGESTION_DIAGNOSTICS,
    persistence_enabled,
)

router = APIRouter()


class AgentEventBatch(BaseModel):
    agent_id: str = Field(min_length=1, max_length=200)
    events: list[NormalizedEvent] = Field(max_length=1000)


@router.post("/events")
def receive_agent_events(batch: AgentEventBatch) -> dict[str, object]:
    """Receive a bounded batch of normalized events from a collector agent."""

    result = ingest_events(batch.events)
    return {"agent_id": batch.agent_id, "status": "accepted", **result}


@router.get("/health")
def agent_health() -> dict[str, object]:
    """Return backend ingestion and evidence-store health counters."""
    return {
        "status": "ok",
        "persistence_enabled": persistence_enabled(),
        "event_count": len(EVENTS),
        "detection_count": len(DETECTIONS),
        "attack_mapping_count": len(ATTACK_MAPPINGS),
        "ingestion": INGESTION_DIAGNOSTICS,
    }
