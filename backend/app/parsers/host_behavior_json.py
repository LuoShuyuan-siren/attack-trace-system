"""Parse normalized host-behavior events from JSON or JSONL files."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.parser import BaseParser
from app.schemas.event import NormalizedEvent


class HostBehaviorJsonParser(BaseParser):
    """Accept a normalized event array, a wrapper object, or JSONL."""

    @property
    def name(self) -> str:
        return "host_behavior_json"

    @property
    def source_type(self) -> str:
        return "host_behavior"

    def parse(self, source: Path) -> list[NormalizedEvent]:
        try:
            text = source.read_text(encoding="utf-8-sig", errors="replace")
        except OSError as exc:
            raise ValueError(f"无法读取主机行为文件: {exc}") from exc

        records = self._records(text)
        events: list[NormalizedEvent] = []
        for index, record in enumerate(records):
            try:
                events.append(NormalizedEvent.model_validate(record))
            except (TypeError, ValueError) as exc:
                raise ValueError(f"主机行为第 {index + 1} 条记录格式无效: {exc}") from exc
        return events

    @staticmethod
    def _records(text: str) -> list[dict[str, Any]]:
        try:
            document = json.loads(text)
        except json.JSONDecodeError:
            records: list[dict[str, Any]] = []
            for line_number, line in enumerate(text.splitlines(), start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise ValueError(f"JSONL 第 {line_number} 行格式无效") from exc
                if not isinstance(record, dict):
                    raise ValueError(f"JSONL 第 {line_number} 行必须是对象")
                records.append(record)
            return records

        if isinstance(document, list):
            records = document
        elif isinstance(document, dict) and isinstance(document.get("events"), list):
            records = document["events"]
        elif isinstance(document, dict) and "timestamp" in document:
            records = [document]
        else:
            raise ValueError("主机行为文件必须是事件数组、events 包装对象或 JSONL")

        if not all(isinstance(record, dict) for record in records):
            raise ValueError("主机行为事件必须全部是 JSON 对象")
        return records