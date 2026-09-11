"""Rules for sensitive, persistence-related and high-volume file behavior."""

from __future__ import annotations

from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

from app.schemas.event import NormalizedEvent

from .adapters import (
    compact_entities,
    file_entity_id,
    host_entity_id,
    host_name,
    normalized_path,
    object_path,
    process_entity_id,
    process_file_entities,
    process_pid,
    raw_value,
)
from .rule_match import RuleMatch


_FILE_EVENT_TYPES = {"file_create", "file_delete", "file_modify", "file_read"}
_SENSITIVE_PATH_MARKERS = (
    "/.aws/credentials",
    "/.ssh/",
    "/etc/passwd",
    "/etc/shadow",
    "/system32/config/sam",
    "/system32/config/security",
    "/users/",
)
_WINDOWS_CREDENTIAL_SUFFIXES = (
    "/login data",
    "/ntuser.dat",
)
_PERSISTENCE_PATH_MARKERS = (
    "/etc/cron.",
    "/etc/crontab",
    "/etc/ld.so.preload",
    "/etc/systemd/system/",
    "/startup/",
)
_SECURITY_LOG_PATHS = (
    "/var/log/audit/audit.log",
    "/var/log/auth.log",
    "/var/log/secure",
)
_REGISTRY_PERSISTENCE_MARKERS = (
    "/software\\microsoft\\windows\\currentversion\\run",
    "/software\\microsoft\\windows\\currentversion\\runonce",
    "/system\\currentcontrolset\\services\\",
    "/software\\microsoft\\windows nt\\currentversion\\image file execution options\\",
)
_EXECUTABLE_SUFFIXES = (
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".ps1",
    ".sh",
)


def evaluate_file_event(event: NormalizedEvent) -> list[RuleMatch]:
    if event.event_type == "registry_modify":
        return _evaluate_registry_event(event)
    if event.event_type not in _FILE_EVENT_TYPES:
        return []

    path = object_path(event)
    normalized = normalized_path(path)
    if not normalized:
        return []

    entities = process_file_entities(event, path=path)
    evidence = {
        "file_path": path,
        "operation": event.action,
        "process_id": process_pid(event),
        "file_hash": raw_value(event, "file_hash", "hash", "Hashes"),
    }
    matches: list[RuleMatch] = []

    if event.event_type == "file_read" and _is_sensitive_path(normalized):
        matches.append(
            RuleMatch(
                rule_id="HB-FILE-001",
                title="Sensitive file read",
                description=(
                    "A process read an operating-system or user credential file."
                ),
                severity="high",
                confidence=0.86,
                related_event_ids=[event.event_id],
                related_entity_ids=entities,
                evidence={
                    **evidence,
                    "matched_conditions": ["sensitive_path", "read_operation"],
                },
                tags=[
                    "host_behavior",
                    "file",
                    "credential_access",
                ],
            )
        )

    if event.event_type in {"file_create", "file_modify"} and any(
        marker in normalized for marker in _PERSISTENCE_PATH_MARKERS
    ):
        matches.append(
            RuleMatch(
                rule_id="HB-FILE-002",
                title="Persistence-related file modification",
                description=(
                    "A process created or modified a file in an automatic "
                    "startup or service configuration location."
                ),
                severity="high",
                confidence=0.84,
                related_event_ids=[event.event_id],
                related_entity_ids=entities,
                evidence={
                    **evidence,
                    "matched_conditions": [
                        "persistence_path",
                        "create_or_modify_operation",
                    ],
                },
                tags=["host_behavior", "file", "persistence"],
            )
        )

    if event.event_type == "file_delete" and _is_security_log(normalized):
        matches.append(
            RuleMatch(
                rule_id="HB-FILE-003",
                title="Security log file deleted",
                description=(
                    "A process deleted a host security or authentication log."
                ),
                severity="critical",
                confidence=0.94,
                related_event_ids=[event.event_id],
                related_entity_ids=entities,
                evidence={
                    **evidence,
                    "matched_conditions": [
                        "security_log_path",
                        "delete_operation",
                    ],
                },
                tags=[
                    "host_behavior",
                    "file",
                    "defense_evasion",
                    "log_deletion",
                ],
                detection_type="malicious_behavior",
            )
        )

    if (
        event.event_type in {"file_create", "file_modify"}
        and normalized.endswith(_EXECUTABLE_SUFFIXES)
        and _is_temporary_path(normalized)
    ):
        matches.append(
            RuleMatch(
                rule_id="HB-FILE-004",
                title="Executable written to a temporary directory",
                description=(
                    "A script or executable was written to a user or system "
                    "temporary directory."
                ),
                severity="medium",
                confidence=0.7,
                related_event_ids=[event.event_id],
                related_entity_ids=entities,
                evidence={
                    **evidence,
                    "matched_conditions": [
                        "executable_or_script",
                        "temporary_directory",
                        "create_or_modify_operation",
                    ],
                },
                tags=[
                    "host_behavior",
                    "file",
                    "execution",
                    "temporary_directory",
                ],
            )
        )

    return matches


def _evaluate_registry_event(event: NormalizedEvent) -> list[RuleMatch]:
    path = object_path(event)
    normalized = normalized_path(path)
    markers = (
        "/software/microsoft/windows/currentversion/run",
        "/software/microsoft/windows/currentversion/runonce",
        "/system/currentcontrolset/services/",
        "/software/microsoft/windows nt/currentversion/image file execution options/",
    )
    if not normalized or not any(marker in normalized for marker in markers):
        return []
    return [
        RuleMatch(
            rule_id="HB-REG-001",
            title="Registry persistence key modified",
            description=(
                "A process created, modified or renamed a Windows registry "
                "key commonly used for persistence or execution hijacking."
            ),
            severity="high",
            confidence=0.88,
            related_event_ids=[event.event_id],
            related_entity_ids=compact_entities(
                (process_entity_id(event) or host_entity_id(event), file_entity_id(event, path))
            ),
            evidence={
                "registry_path": path,
                "operation": event.action,
                "process_id": process_pid(event),
                "matched_conditions": ["registry_persistence_key"],
            },
            tags=["host_behavior", "registry", "persistence"],
        )
    ]


def evaluate_bulk_file_changes(
    events: list[NormalizedEvent],
    *,
    threshold: int,
    window: timedelta,
) -> list[tuple[datetime, RuleMatch]]:
    """Detect bursts of file changes grouped by host and process."""

    if threshold < 2:
        raise ValueError("bulk file threshold must be at least 2")

    grouped: dict[tuple[str, int | None], deque[NormalizedEvent]] = defaultdict(deque)
    reported_until: dict[tuple[str, int | None], datetime] = {}
    matches: list[tuple[datetime, RuleMatch]] = []

    for event in events:
        if event.event_type not in {"file_create", "file_delete", "file_modify"}:
            continue
        host = host_name(event)
        if not host:
            continue
        pid = process_pid(event)
        if pid is None:
            continue
        timestamp = _as_utc(event.timestamp)
        key = (host, pid)
        bucket = grouped[key]
        bucket.append(event)
        while bucket and timestamp - _as_utc(bucket[0].timestamp) > window:
            bucket.popleft()

        paths = list(
            dict.fromkeys(
                path
                for item in bucket
                if (path := object_path(item)) is not None
            )
        )
        if (
            len(paths) < threshold
            or timestamp
            <= reported_until.get(
                key, datetime.min.replace(tzinfo=timezone.utc)
            )
        ):
            continue

        related_events = list(bucket)
        matches.append(
            (
                event.timestamp,
                RuleMatch(
                    rule_id="HB-FILE-005",
                    title="High-volume file changes",
                    description=(
                        "One process changed many files in a short time window."
                    ),
                    severity="high",
                    confidence=0.8,
                    related_event_ids=[item.event_id for item in related_events],
                    related_entity_ids=compact_entities(
                        (
                            process_entity_id(event)
                            or host_entity_id(event),
                            file_entity_id(event, paths[0]),
                            *(
                                file_entity_id(event, path)
                                for path in paths[1:10]
                            ),
                        )
                    ),
                    evidence={
                        "event_count": len(related_events),
                        "unique_file_count": len(paths),
                        "file_path": paths[0],
                        "sample_paths": paths[:10],
                        "operation": "bulk_file_change",
                        "window_seconds": int(window.total_seconds()),
                        "time_delta_seconds": (
                            timestamp
                            - _as_utc(related_events[0].timestamp)
                        ).total_seconds(),
                        "process_id": pid,
                        "matched_conditions": [
                            "unique_file_threshold",
                            "time_window",
                        ],
                    },
                    tags=[
                        "host_behavior",
                        "file",
                        "impact",
                        "bulk_changes",
                    ],
                ),
            )
        )
        reported_until[key] = timestamp + window

    return matches


def _is_sensitive_path(path: str) -> bool:
    if any(marker in path for marker in _SENSITIVE_PATH_MARKERS[:-1]):
        return True
    return "/users/" in path and path.endswith(_WINDOWS_CREDENTIAL_SUFFIXES)


def _is_security_log(path: str) -> bool:
    return path in _SECURITY_LOG_PATHS or path.endswith(".evtx")


def _is_temporary_path(path: str) -> bool:
    return any(
        marker in path
        for marker in (
            "/appdata/local/temp/",
            "/tmp/",
            "/var/tmp/",
            "/windows/temp/",
        )
    )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
