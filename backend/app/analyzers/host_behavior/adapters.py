"""Compatibility helpers for reading host-behavior event fields.

The public NormalizedEvent schema intentionally keeps parser-specific details
in raw_data. Parsers may use slightly different names while the team is still
agreeing on a convention, so rules should read those details through this
module instead of depending on raw keys directly.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from app.schemas.event import NormalizedEvent


_NESTED_RAW_DATA_KEYS = ("event_data", "EventData", "data", "details")


def raw_value(event: NormalizedEvent, *keys: str) -> Any | None:
    """Return the first non-empty raw value matching one of keys.

    Matching is case-insensitive and also checks common nested event-data
    dictionaries. This provides a small compatibility layer for Sysmon,
    Windows Security Log, auditd and eBPF parsers without changing schemas.
    """

    containers: list[dict[str, Any]] = [event.raw_data]
    for nested_key in _NESTED_RAW_DATA_KEYS:
        nested = event.raw_data.get(nested_key)
        if isinstance(nested, dict):
            containers.append(nested)

    # Respect the caller's alias order. This matters when a parser preserves
    # both a numeric audit syscall and a preferred symbolic syscall_name.
    for requested_key in keys:
        lowered_key = requested_key.casefold()
        for container in containers:
            for key, value in container.items():
                if (
                    str(key).casefold() == lowered_key
                    and value not in (None, "")
                ):
                    return value
    return None


def coerce_int(value: Any | None) -> int | None:
    """Convert decimal or hexadecimal process identifiers to integers."""

    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value).strip(), 0)
    except (TypeError, ValueError):
        return None


def host_name(event: NormalizedEvent) -> str | None:
    return event.host.hostname or event.host.ip


def user_name(event: NormalizedEvent) -> str | None:
    if event.subject and event.subject.user:
        value = event.subject.user.strip()
        if value.casefold() not in {"-", "n/a", "none", "unknown"}:
            return value
    value = raw_value(event, "username", "user", "User")
    if value is None:
        return None
    normalized = str(value).strip()
    if normalized.casefold() in {"-", "n/a", "none", "unknown"}:
        return None
    return normalized


def process_name(event: NormalizedEvent) -> str | None:
    if _object_is_created_process(event):
        return event.object.name or event.object.path
    if event.subject and event.subject.name:
        return event.subject.name
    value = raw_value(event, "process_name", "image", "Image", "exe")
    return str(value) if value is not None else None


def process_image(event: NormalizedEvent) -> str | None:
    """Return the most specific executable path available for the process."""

    if _object_is_created_process(event):
        return event.object.path or event.object.name
    value = raw_value(event, "image", "Image", "process_path", "exe")
    if value is not None:
        return str(value)
    return process_name(event)


def process_pid(event: NormalizedEvent) -> int | None:
    if _object_is_created_process(event):
        return event.object.pid
    if event.subject and event.subject.pid is not None:
        return event.subject.pid
    return coerce_int(raw_value(event, "process_id", "ProcessId", "pid"))


def parent_process_name(event: NormalizedEvent) -> str | None:
    if _object_is_created_process(event) and event.subject:
        if event.subject.name:
            return event.subject.name
    value = raw_value(
        event,
        "parent_process_name",
        "parent_image",
        "ParentImage",
        "parent_name",
    )
    return str(value) if value is not None else None


def parent_pid(event: NormalizedEvent) -> int | None:
    if _object_is_created_process(event) and event.subject:
        if event.subject.pid is not None:
            return event.subject.pid
    return coerce_int(
        raw_value(
            event,
            "parent_pid",
            "parent_process_id",
            "ParentProcessId",
            "ppid",
        )
    )


def command_line(event: NormalizedEvent) -> str:
    value = raw_value(event, "command_line", "CommandLine", "cmdline", "args")
    return str(value) if value is not None else ""


def object_path(event: NormalizedEvent) -> str | None:
    if event.object:
        if event.object.path:
            return event.object.path
        if event.object.name:
            return event.object.name
    value = raw_value(
        event,
        "path",
        "target_filename",
        "TargetFilename",
        "file_path",
        "name",
    )
    return str(value) if value is not None else None


def syscall_name(event: NormalizedEvent) -> str | None:
    value = raw_value(event, "syscall_name", "syscall", "Syscall", "name")
    if value is not None:
        return str(value).casefold()
    if event.event_type in {"system_call", "syscall"}:
        return event.action.casefold()
    return None


def normalized_executable_name(value: str | None) -> str:
    """Return a case-folded executable basename for Windows or POSIX paths."""

    if not value:
        return ""
    return value.replace("\\", "/").rsplit("/", 1)[-1].casefold()


def normalized_path(value: str | None) -> str:
    if not value:
        return ""
    return value.replace("\\", "/").casefold()


def host_entity_id(event: NormalizedEvent) -> str | None:
    host = host_name(event)
    return f"host:{host}" if host else None


def user_entity_id(event: NormalizedEvent) -> str | None:
    host = host_name(event)
    user = user_name(event)
    if not host or not user:
        return None
    return f"user:{host}:{user}"


def process_entity_id(event: NormalizedEvent, pid: int | None = None) -> str | None:
    host = host_name(event)
    resolved_pid = process_pid(event) if pid is None else pid
    if not host or resolved_pid is None:
        return None
    return f"process:{host}:{resolved_pid}"


def file_entity_id(event: NormalizedEvent, path: str | None = None) -> str | None:
    host = host_name(event)
    resolved_path = object_path(event) if path is None else path
    if not host or not resolved_path:
        return None
    return f"file:{host}:{resolved_path}"


def compact_entities(values: Iterable[str | None]) -> list[str]:
    """Remove empty and duplicate entity IDs while preserving order."""

    return list(dict.fromkeys(value for value in values if value))


def _object_is_created_process(event: NormalizedEvent) -> bool:
    """Whether process_create models parent as subject and child as object."""

    return bool(
        event.event_type in {"process_create", "process_exec"}
        and event.object
        and event.object.type == "process"
        and event.object.pid is not None
    )


def process_execution_entities(
    event: NormalizedEvent,
    *,
    source_pid: int | None = None,
) -> list[str]:
    """Return ordered source-to-target entities for process execution."""

    if source_pid is not None:
        source = process_entity_id(event, source_pid)
    else:
        source = user_entity_id(event) or host_entity_id(event)
    return compact_entities((source, process_entity_id(event)))


def process_file_entities(
    event: NormalizedEvent,
    *,
    path: str | None = None,
) -> list[str]:
    """Return ordered process-to-file entities for file behavior."""

    source = process_entity_id(event) or host_entity_id(event)
    return compact_entities((source, file_entity_id(event, path)))
