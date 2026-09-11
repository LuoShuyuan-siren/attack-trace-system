from __future__ import annotations

import csv
import json
import os
import platform
import socket
import subprocess
import time
from collections.abc import Iterable
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib import request
from uuid import uuid4

from app.schemas.event import (
    HostInfo,
    NetworkInfo,
    NormalizedEvent,
    ObjectInfo,
    SubjectInfo,
)
from app.collectors.system_log_tail import LinuxSystemLogTail
from app.collectors.linux_realtime import LinuxRealtimeCollector
from app.collectors.live_packet import LivePacketCollector
from app.collectors.windows_realtime import WindowsRealtimeCollector
from app.services.clock_calibration import ClockCalibration, ClockCalibrationService


class CollectorAgent:
    """Small cross-platform collector for lab and development environments."""

    def __init__(
        self,
        *,
        agent_id: str | None = None,
        backend_url: str = "http://127.0.0.1:8000/api/v1/agent/events",
        cache_path: str | Path = "collector-events.jsonl",
        watch_paths: Iterable[str | Path] = (),
        linux_system_log: str | Path | None = None,
        ebpf_jsonl: str | Path | None = None,
        enable_windows_realtime: bool = False,
        windows_state_path: str | Path | None = None,
        enable_windows_native_subscription: bool = False,
        packet_interface: str | None = None,
        packet_timeout: int = 2,
        enable_clock_calibration: bool = True,
    ) -> None:
        self.agent_id = agent_id or socket.gethostname()
        self._health = {
            "agent_id": self.agent_id,
            "started_at": datetime.now(timezone.utc).isoformat(),
            "last_collect_at": None,
            "last_send_at": None,
            "collected_event_count": 0,
            "sent_event_count": 0,
            "send_failure_count": 0,
            "source_counts": {},
            "last_error": None,
        }
        self.backend_url = backend_url
        self.cache_path = Path(cache_path)
        self.watch_paths = [Path(path) for path in watch_paths]
        self._file_state: dict[str, tuple[int, int]] = {}
        self._linux_system_log = (
            LinuxSystemLogTail(linux_system_log, hostname=self.agent_id)
            if linux_system_log
            else None
        )
        self._linux_realtime = (
            LinuxRealtimeCollector(
                hostname=self.agent_id,
                audit_log=None,
                ebpf_jsonl=ebpf_jsonl,
            )
            if ebpf_jsonl
            else None
        )
        self._windows_realtime = (
            WindowsRealtimeCollector(
                state_path=windows_state_path,
                native_subscription=enable_windows_native_subscription,
            )
            if enable_windows_realtime
            else None
        )
        self._live_packets = (
            LivePacketCollector(interface=packet_interface, timeout=packet_timeout)
            if packet_interface is not None
            else None
        )
        self._clock = (
            ClockCalibrationService().measure()
            if enable_clock_calibration
            else ClockCalibration(source="disabled")
        )

    def collect_once(self) -> list[NormalizedEvent]:
        events = self._collect_processes()
        events.extend(self._collect_files())
        events.extend(self._collect_network())
        if self._linux_system_log:
            events.extend(self._linux_system_log.collect_once())
        if self._linux_realtime:
            events.extend(self._linux_realtime.collect_once())
        if self._windows_realtime:
            events.extend(self._windows_realtime.collect_once())
        if self._live_packets:
            events.extend(self._live_packets.collect_once())
        events = self._annotate_clock(events)
        self._health["last_collect_at"] = datetime.now(timezone.utc).isoformat()
        self._health["collected_event_count"] += len(events)
        for event in events:
            source_counts = self._health["source_counts"]
            source_counts[event.source_type] = source_counts.get(event.source_type, 0) + 1
        return events

    def _annotate_clock(self, events: list[NormalizedEvent]) -> list[NormalizedEvent]:
        if not events:
            return events
        return [
            event.model_copy(update={
                "raw_data": {
                    **event.raw_data,
                    "clock_offset_ms": self._clock.offset_ms,
                    "clock_source": self._clock.source,
                    "clock_confidence": self._clock.confidence,
                    "clock_synchronized": self._clock.synchronized,
                    "clock_details": self._clock.details,
                },
            })
            for event in events
        ]

    def run(self, *, interval_seconds: float = 5.0) -> None:
        if interval_seconds <= 0:
            raise ValueError("interval_seconds must be positive")
        while True:
            events = self.collect_once()
            self.append_cache(events)
            self.send(events)
            time.sleep(interval_seconds)

    def append_cache(self, events: list[NormalizedEvent]) -> None:
        if not events:
            return
        self.cache_path.parent.mkdir(parents=True, exist_ok=True)
        with self.cache_path.open("a", encoding="utf-8") as output:
            for event in events:
                output.write(event.model_dump_json() + "\n")

    def send(self, events: list[NormalizedEvent]) -> bool:
        if not events:
            return True
        payload = json.dumps(
            {"agent_id": self.agent_id, "events": [event.model_dump(mode="json") for event in events]},
        ).encode("utf-8")
        request_data = request.Request(
            self.backend_url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with request.urlopen(request_data, timeout=10) as response:
                accepted = 200 <= response.status < 300
                self._health["last_send_at"] = datetime.now(timezone.utc).isoformat()
                if accepted:
                    self._health["sent_event_count"] += len(events)
                else:
                    self._health["send_failure_count"] += 1
                return accepted
        except OSError as exc:
            self._health["send_failure_count"] += 1
            self._health["last_error"] = str(exc)
            return False

    def health(self) -> dict[str, Any]:
        return {
            **self._health,
            "cache_path": str(self.cache_path),
            "cache_exists": self.cache_path.exists(),
            "cache_size_bytes": self.cache_path.stat().st_size if self.cache_path.exists() else 0,
        }

    def replay_cache(self, *, batch_size: int = 100) -> int:
        if batch_size <= 0:
            raise ValueError("batch_size must be positive")
        if not self.cache_path.exists():
            return 0

        events: list[NormalizedEvent] = []
        sent = 0
        with self.cache_path.open(encoding="utf-8") as source:
            for line in source:
                if not line.strip():
                    continue
                events.append(NormalizedEvent.model_validate_json(line))
                if len(events) >= batch_size:
                    if not self.send(events):
                        return sent
                    sent += len(events)
                    events = []
        if events and self.send(events):
            sent += len(events)
        return sent

    def _host(self) -> HostInfo:
        try:
            host_ip = socket.gethostbyname(socket.gethostname())
        except OSError:
            host_ip = None
        return HostInfo(
            hostname=socket.gethostname(),
            ip=host_ip,
            os=platform.system().lower(),
        )

    def _collect_processes(self) -> list[NormalizedEvent]:
        if platform.system().lower() == "windows":
            return self._collect_windows_processes()
        return self._collect_proc_processes()

    def _collect_windows_processes(self) -> list[NormalizedEvent]:
        try:
            completed = subprocess.run(
                ["tasklist", "/FO", "CSV", "/NH"],
                capture_output=True,
                text=True,
                timeout=10,
                check=True,
            )
        except (OSError, subprocess.SubprocessError):
            return []

        events: list[NormalizedEvent] = []
        for row in csv.reader(completed.stdout.splitlines()):
            if len(row) < 2 or not row[1].isdigit():
                continue
            name, pid = row[0], int(row[1])
            events.append(self._process_event(name=name, pid=pid, ppid=None, command_line=name))
        return events

    def _collect_proc_processes(self) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        proc_root = Path("/proc")
        if not proc_root.exists():
            return events
        for proc_dir in proc_root.iterdir():
            if not proc_dir.name.isdigit():
                continue
            try:
                stat_fields = (proc_dir / "stat").read_text(encoding="utf-8").split()
                command_line = (proc_dir / "cmdline").read_bytes().replace(b"\x00", b" ").decode(errors="replace").strip()
                name = stat_fields[1].strip("()")
                pid, ppid = int(stat_fields[0]), int(stat_fields[3])
            except (OSError, ValueError, IndexError):
                continue
            events.append(self._process_event(name=name, pid=pid, ppid=ppid, command_line=command_line or name))
        return events

    def _process_event(self, *, name: str, pid: int, ppid: int | None, command_line: str) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=f"evt-agent-{uuid4()}",
            timestamp=datetime.now(timezone.utc),
            source_type="host_behavior",
            source="collector_agent",
            host=self._host(),
            event_type="process_snapshot",
            subject=SubjectInfo(type="process", name=name, pid=pid),
            action="observe_process",
            raw_data={"pid": pid, "ppid": ppid, "process_name": name, "command_line": command_line},
            tags=["collector", "process_snapshot"],
        )

    def _collect_files(self) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        current: dict[str, tuple[int, int]] = {}
        for root in self.watch_paths:
            paths = root.rglob("*") if root.is_dir() else [root]
            for path in paths:
                if not path.is_file():
                    continue
                try:
                    stat = path.stat()
                except OSError:
                    continue
                key = str(path.resolve())
                current[key] = (stat.st_mtime_ns, stat.st_size)
                previous = self._file_state.get(key)
                if previous is None:
                    action, event_type = "observe_file", "file_snapshot"
                elif previous != current[key]:
                    action, event_type = "modify_file", "file_modify"
                else:
                    continue
                events.append(NormalizedEvent(
                    event_id=f"evt-agent-{uuid4()}",
                    timestamp=datetime.now(timezone.utc),
                    source_type="host_behavior",
                    source="collector_agent",
                    host=self._host(),
                    event_type=event_type,
                    object=ObjectInfo(type="file", name=path.name, path=key),
                    action=action,
                    raw_data={"path": key, "size": stat.st_size, "mtime_ns": stat.st_mtime_ns},
                    tags=["collector", "file"],
                ))
        for deleted in self._file_state.keys() - current.keys():
            events.append(NormalizedEvent(
                event_id=f"evt-agent-{uuid4()}",
                timestamp=datetime.now(timezone.utc),
                source_type="host_behavior",
                source="collector_agent",
                host=self._host(),
                event_type="file_delete",
                object=ObjectInfo(type="file", name=Path(deleted).name, path=deleted),
                action="delete_file",
                raw_data={"path": deleted},
                tags=["collector", "file"],
            ))
        self._file_state = current
        return events

    def _collect_network(self) -> list[NormalizedEvent]:
        try:
            import psutil
        except ImportError:
            return []
        events: list[NormalizedEvent] = []
        for connection in psutil.net_connections(kind="inet"):
            if not connection.raddr:
                continue
            events.append(NormalizedEvent(
                event_id=f"evt-agent-{uuid4()}",
                timestamp=datetime.now(timezone.utc),
                source_type="network_traffic",
                source="collector_agent",
                host=self._host(),
                event_type="network_connection",
                subject=SubjectInfo(type="process", pid=connection.pid),
                network=NetworkInfo(
                    src_ip=connection.laddr.ip,
                    src_port=connection.laddr.port,
                    dst_ip=connection.raddr.ip,
                    dst_port=connection.raddr.port,
                    protocol="tcp" if connection.type == socket.SOCK_STREAM else "udp",
                ),
                action="connect",
                raw_data={"status": connection.status, "pid": connection.pid},
                tags=["collector", "network_connection"],
            ))
        return events
