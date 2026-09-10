from typing import Any

from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent

from app.analyzers.attack_mapping import AttackMappingResult

EVENTS: list[NormalizedEvent] = []
DETECTIONS: list[DetectionResult] = []
ATTACK_MAPPINGS: list[AttackMappingResult] = []

TASKS: dict[str, dict[str, Any]] = {}