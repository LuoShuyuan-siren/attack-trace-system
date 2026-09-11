from fastapi import APIRouter

from app.services.network_context import NetworkContextService
from app.services.runtime_store import EVENTS

router = APIRouter()


@router.get("/sessions")
def get_network_sessions() -> dict[str, list[dict[str, object]]]:
    service = NetworkContextService()
    return {"sessions": service.reconstruct_sessions(EVENTS)}


@router.get("/covert-channels")
def get_covert_channels() -> dict[str, object]:
    service = NetworkContextService()
    return service.summarize_covert_channels(EVENTS)
