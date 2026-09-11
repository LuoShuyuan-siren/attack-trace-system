from fastapi import APIRouter

from app.api.v1 import attack
from app.api.v1 import agent
from app.api.v1 import adfa_ingestion
from app.api.v1 import data
from app.api.v1 import datasets
from app.api.v1 import detections
from app.api.v1 import events
from app.api.v1 import forensics
from app.api.v1 import intelligence
from app.api.v1 import network_context
from app.api.v1 import sessions
from app.api.v1 import tasks


api_router = APIRouter()

api_router.include_router(
    agent.router,
    prefix="/agent",
    tags=["Collector Agent"],
)

api_router.include_router(
    adfa_ingestion.router,
    prefix="/datasets",
    tags=["Datasets"],
)

api_router.include_router(
    data.router,
    prefix="/data",
    tags=["Data"],
)

api_router.include_router(
    datasets.router,
    prefix="/datasets",
    tags=["Datasets"],
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
    sessions.router,
    prefix="/sessions",
    tags=["Sessions"],
)

api_router.include_router(
    network_context.router,
    prefix="/network",
    tags=["Network"],
)

api_router.include_router(
    forensics.router,
    prefix="/forensics",
    tags=["Forensics"],
)

api_router.include_router(
    intelligence.router,
    prefix="/intelligence",
    tags=["External Intelligence"],
)

api_router.include_router(
    tasks.router,
    prefix="/tasks",
    tags=["Tasks"],
)