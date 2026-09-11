from __future__ import annotations

import json
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.schemas.event import NormalizedEvent
from app.collectors.windows_subscription import WindowsNativeEventSubscription


class WindowsRealtimeCollector:
    """Poll Windows event channels, including Sysmon's ETW-backed channel."""

    def __init__(
        self,
        *,
        channels: tuple[str, ...] = (
            "Microsoft-Windows-Sysmon/Operational",
            "Security",
        ),
        limit: int = 100,
        state_path: str | Path | None = None,
        native_subscription: bool = False,
    ) -> None:
        if limit <= 0:
            raise ValueError("limit must be positive")
        self.channels = channels
        self.limit = limit
        self._seen: dict[str, set[str]] = {channel: set() for channel in channels}
        self.state_path = Path(state_path) if state_path else None
        self._cursors = self._load_cursors()
        self._parser = None
        self._native_subscription = (
            WindowsNativeEventSubscription(channels) if native_subscription else None
        )

    def collect_once(self) -> list[NormalizedEvent]:
        if not _is_windows():
            return []
        if self._parser is None:
            try:
                from app.parsers.windows_log_parser import WindowsLogParser

                self._parser = WindowsLogParser()
            except ImportError:
                return []
        events: list[NormalizedEvent] = []
        native_events = self._native_subscription.collect_once() if self._native_subscription else []
        native_active = bool(self._native_subscription and self._native_subscription._started)
        if native_active:
            channel_events = native_events
        else:
            channel_events = [
                (channel, xml_text)
                for channel in self.channels
                for xml_text in self._query_channel(channel)
            ]
        for channel, xml_text in channel_events:
            event = self._parse(channel, xml_text)
            if event is not None:
                events.append(event)
        self._save_cursors()
        return events

    def _query_channel(self, channel: str) -> list[str]:
        cursor = self._cursors.get(channel)
        command = ["wevtutil", "qe", channel, "/f:xml"]
        if cursor is None:
            command.extend(["/rd:true", f"/c:{self.limit}"])
        else:
            command.extend(["/rd:false", f"/q:*[System[(EventRecordID > {cursor})]]"])
        try:
            completed = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=15,
                check=True,
            )
        except (OSError, subprocess.SubprocessError):
            return []
        return _split_event_xml(completed.stdout)

    def _parse(self, channel: str, xml_text: str) -> NormalizedEvent | None:
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError:
            return None
        system = root.find(".//{*}System")
        record_id = _text(system, "EventRecordID") or xml_text
        numeric_record_id = _int(record_id)
        cursor = self._cursors.get(channel)
        if numeric_record_id is not None and cursor is not None and numeric_record_id <= cursor:
            return None
        if record_id in self._seen[channel]:
            return None
        self._seen[channel].add(record_id)
        if numeric_record_id is not None:
            self._cursors[channel] = max(numeric_record_id, self._cursors.get(channel, 0))
        if len(self._seen[channel]) > self.limit * 4:
            self._seen[channel] = set(list(self._seen[channel])[-self.limit * 2 :])

        event_id = int(_text(system, "EventID") or 0)
        timestamp = None
        created = system.find("{*}TimeCreated") if system is not None else None
        if created is not None:
            timestamp = created.attrib.get("SystemTime")
        hostname = _text(system, "Computer") or "unknown"
        data: dict[str, Any] = {}
        for node in root.findall(".//{*}EventData/{*}Data"):
            name = node.attrib.get("Name")
            if name:
                value = node.text
                data[name] = value.strip() if value and value.strip() else None
        if self._parser is None:
            return None
        return self._parser._parse_event(
            event_id,
            data,
            timestamp or datetime.now(timezone.utc).isoformat(),
            hostname,
        )

    def _load_cursors(self) -> dict[str, int]:
        if self.state_path is None or not self.state_path.exists():
            return {}
        try:
            data = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}
        return {
            str(channel): int(value)
            for channel, value in data.items()
            if isinstance(value, (int, str)) and str(value).isdigit()
        }

    def _save_cursors(self) -> None:
        if self.state_path is None:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(
                json.dumps(self._cursors, ensure_ascii=True, indent=2),
                encoding="utf-8",
            )
        except OSError:
            return


def _split_event_xml(output: str) -> list[str]:
    root = ET.fromstring(f"<Events>{output}</Events>") if output.strip() else None
    if root is None:
        return []
    return [ET.tostring(child, encoding="unicode") for child in root]


def _text(parent: ET.Element | None, name: str) -> str | None:
    if parent is None:
        return None
    node = parent.find(f"{{*}}{name}")
    value = node.text if node is not None else None
    return value.strip() if value and value.strip() else None


def _is_windows() -> bool:
    import platform

    return platform.system().lower() == "windows"


def _int(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None
