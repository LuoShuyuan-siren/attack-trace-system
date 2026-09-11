from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.collectors.system_log_tail import LinuxSystemLogTail
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent, ObjectInfo, SubjectInfo


class LinuxRealtimeCollector:
    """Read auditd incrementally and consume JSONL emitted by an eBPF sensor."""

    def __init__(
        self,
        *,
        hostname: str,
        audit_log: str | Path | None = None,
        ebpf_jsonl: str | Path | None = None,
    ) -> None:
        self.hostname = hostname
        self.audit_tail = LinuxSystemLogTail(audit_log, hostname=hostname) if audit_log else None
        self.ebpf_jsonl = Path(ebpf_jsonl) if ebpf_jsonl else None
        self._offset = 0

    def collect_once(self) -> list[NormalizedEvent]:
        events = self.audit_tail.collect_once() if self.audit_tail else []
        if self.ebpf_jsonl and self.ebpf_jsonl.exists():
            events.extend(self._read_ebpf())
        return events

    def _read_ebpf(self) -> list[NormalizedEvent]:
        events: list[NormalizedEvent] = []
        try:
            with self.ebpf_jsonl.open("rb") as source:
                source.seek(self._offset)
                chunk = source.read()
                self._offset = source.tell()
        except OSError:
            return events
        for line in chunk.splitlines():
            try:
                record = json.loads(line)
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
            if isinstance(record, dict):
                event = self._from_record(record)
                if event:
                    events.append(event)
        return events

    def _from_record(self, record: dict[str, Any]) -> NormalizedEvent | None:
        syscall = str(record.get("syscall") or record.get("syscall_name") or "").lower()
        event_type = str(record.get("event_type") or ("system_call" if syscall else "process_exec"))
        pid = _int(record.get("pid"))
        target_pid = _int(record.get("target_pid") or record.get("target_tgid"))
        subject = SubjectInfo(type="process", name=record.get("comm") or record.get("process_name"), pid=pid, user=record.get("user") or record.get("uid"))
        object_info = ObjectInfo(type="process", name=record.get("target_comm"), pid=target_pid) if target_pid else None
        network = None
        if record.get("remote_ip"):
            network = NetworkInfo(
                dst_ip=str(record["remote_ip"]),
                dst_port=_int(record.get("remote_port")),
                protocol="TCP",
            )
        raw = dict(record)
        if syscall:
            raw["syscall_name"] = syscall
        if record.get("path") and isinstance(raw.get("arguments"), dict):
            raw["arguments"] = {**raw["arguments"], "path": record["path"]}
        return NormalizedEvent(
            event_id=str(record.get("event_id") or f"evt-ebpf-{uuid4()}"),
            timestamp=_timestamp(record.get("timestamp")),
            source_type="host_behavior",
            source="ebpf",
            host=HostInfo(hostname=self.hostname, os="linux"),
            event_type=event_type,
            subject=SubjectInfo(
                type="process",
                name=record.get("comm") or record.get("process_name") or record.get("exe"),
                pid=pid,
                user=record.get("user") or record.get("uid"),
            ),
            object=object_info,
            network=network,
            action=str(record.get("action") or syscall or event_type),
            raw_data=raw,
            severity=str(record.get("severity") or "info"),
            tags=["collector", "ebpf", "syscall"] if syscall else ["collector", "ebpf"],
        )


def _int(value: Any) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _timestamp(value: Any) -> datetime:
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    if isinstance(value, str) and value:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return datetime.now(timezone.utc)
