from fastapi import APIRouter

from app.api.v1 import attack
from app.api.v1 import data
from app.api.v1 import detections
from app.api.v1 import events
from app.api.v1 import tasks


api_router = APIRouter()

api_router.include_router(
    data.router,
    prefix="/data",
    tags=["Data"],
)

api_router.include_router(
    events.router,
    prefix="/events",
    tags=["Events"],
)

api_router.include_router(
    detections.router,
    prefix="/detections",
    tags=["Detections"],
)

api_router.include_router(
    attack.router,
    prefix="/attack",
    tags=["Attack"],
)

api_router.include_router(
    tasks.router,
    prefix="/tasks",
    tags=["Tasks"],
)