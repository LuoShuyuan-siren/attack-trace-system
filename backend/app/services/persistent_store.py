from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from app.analyzers.attack_mapping.models import AttackMappingResult, TacticRef
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


class SQLiteRuntimeStore:
    """Small optional SQLite store for restart-safe runtime evidence."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS detections (
                    detection_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS attack_mappings (
                    detection_id TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                """
            )

    def load(self) -> tuple[list[NormalizedEvent], list[DetectionResult], list[AttackMappingResult]]:
        with self._connect() as connection:
            events = [
                NormalizedEvent.model_validate_json(payload)
                for (payload,) in connection.execute("SELECT payload FROM events")
            ]
            detections = [
                DetectionResult.model_validate_json(payload)
                for (payload,) in connection.execute("SELECT payload FROM detections")
            ]
            mappings = [
                _mapping_from_dict(json.loads(payload))
                for (payload,) in connection.execute("SELECT payload FROM attack_mappings")
            ]
        return events, detections, mappings

    def save(
        self,
        events: list[NormalizedEvent],
        detections: list[DetectionResult],
        mappings: list[AttackMappingResult],
    ) -> None:
        with self._connect() as connection:
            connection.executemany(
                "INSERT OR REPLACE INTO events(event_id, payload) VALUES (?, ?)",
                [(event.event_id, event.model_dump_json()) for event in events],
            )
            connection.executemany(
                "INSERT OR REPLACE INTO detections(detection_id, payload) VALUES (?, ?)",
                [(item.detection_id, item.model_dump_json()) for item in detections],
            )
            connection.executemany(
                "INSERT OR REPLACE INTO attack_mappings(detection_id, payload) VALUES (?, ?)",
                [(item.detection_id, json.dumps(item.to_dict(), ensure_ascii=True)) for item in mappings],
            )


def _mapping_from_dict(data: dict[str, Any]) -> AttackMappingResult:
    return AttackMappingResult(
        detection_id=str(data["detection_id"]),
        timestamp=str(data["timestamp"]),
        analyzer=str(data["analyzer"]),
        technique_id=str(data["technique_id"]),
        technique_name=str(data["technique_name"]),
        tactics=tuple(
            TacticRef(
                tactic_id=str(item["tactic_id"]),
                tactic_name=str(item["tactic_name"]),
                stage=str(item["stage"]),
            )
            for item in data.get("tactics", [])
        ),
        mapping_source=str(data.get("mapping_source", "none")),
        matched_rule_ids=tuple(data.get("matched_rule_ids", [])),
        ttp_tags=tuple(data.get("ttp_tags", [])),
        confidence=float(data.get("confidence", 0.0)),
        related_entity_ids=tuple(data.get("related_entity_ids", [])),
        evidence=dict(data.get("evidence", {})),
        notes=tuple(data.get("notes", [])),
    )
