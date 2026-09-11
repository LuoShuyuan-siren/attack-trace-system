import os
from typing import Any

from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent

from app.analyzers.attack_mapping import AttackMappingResult
from app.services.persistent_store import SQLiteRuntimeStore

EVENTS: list[NormalizedEvent] = []
DETECTIONS: list[DetectionResult] = []
ATTACK_MAPPINGS: list[AttackMappingResult] = []

_persistent_store = None
db_path = os.getenv("ATTACK_TRACE_DB_PATH")
if db_path:
	_persistent_store = SQLiteRuntimeStore(db_path)
	loaded = _persistent_store.load()
	EVENTS.extend(loaded[0])
	DETECTIONS.extend(loaded[1])
	ATTACK_MAPPINGS.extend(loaded[2])

TASKS: dict[str, dict[str, Any]] = {}

INGESTION_DIAGNOSTICS: dict[str, Any] = {
	"batch_count": 0,
	"received_event_count": 0,
	"accepted_event_count": 0,
	"duplicate_event_count": 0,
	"detection_count": 0,
	"last_ingest_at": None,
	"last_event_timestamp": None,
	"by_source_type": {},
}


def persist_runtime_state() -> None:
	if _persistent_store is not None:
		_persistent_store.save(EVENTS, DETECTIONS, ATTACK_MAPPINGS)


def persistence_enabled() -> bool:
	return _persistent_store is not None