"""Rules for high-risk and suspicious system-call sequences."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.schemas.event import NormalizedEvent

from .adapters import (
    coerce_int,
    compact_entities,
    host_entity_id,
    host_name,
    process_name,
    process_entity_id,
    process_pid,
    raw_value,
    syscall_name,
)
from .rule_match import RuleMatch


_HIGH_RISK_SYSCALLS = {
    "finit_module": ("Kernel module loaded", "critical", 0.92),
    "init_module": ("Kernel module loaded", "critical", 0.92),
    "kexec_load": ("Alternate kernel load requested", "critical", 0.96),
    "process_vm_writev": ("Cross-process memory write", "high", 0.9),
    "ptrace": ("Process tracing or memory access", "medium", 0.72),
}


def evaluate_syscall_event(event: NormalizedEvent) -> list[RuleMatch]:
    if event.event_type not in {"system_call", "syscall"}:
        return []

    syscall = syscall_name(event)
    matches: list[RuleMatch] = []

    if syscall in _HIGH_RISK_SYSCALLS:
        matches.append(_high_risk_syscall_match(event, syscall))

    privileged_execution = _privileged_execution_match(event, syscall)
    if privileged_execution is not None:
        matches.append(privileged_execution)

    return matches


def _high_risk_syscall_match(
    event: NormalizedEvent,
    syscall: str,
) -> RuleMatch:

    title, severity, confidence = _HIGH_RISK_SYSCALLS[syscall]
    arguments = raw_value(event, "arguments", "args")
    target_pid = _target_pid(arguments)
    if target_pid is not None:
        entities = compact_entities(
            (
                process_entity_id(event),
                process_entity_id(event, target_pid),
            )
        )
    else:
        entities = compact_entities(
            (host_entity_id(event), process_entity_id(event))
        )

    return RuleMatch(
        rule_id="HB-SYSCALL-001",
        title=title,
        description=(
            f"The process invoked the high-risk system call {syscall}; "
            "review its arguments and surrounding events."
        ),
        severity=severity,
        confidence=confidence,
        related_event_ids=[event.event_id],
        related_entity_ids=entities,
        evidence={
            "syscall": syscall,
            "pid": process_pid(event),
            "target_pid": target_pid,
            "operation": syscall,
            "arguments": arguments,
            "result": raw_value(event, "result", "return_value", "exit"),
            "matched_conditions": ["high_risk_syscall"],
        },
        tags=[
            "host_behavior",
            "syscall",
            "execution",
            "high_risk",
        ],
    )


def _privileged_execution_match(
    event: NormalizedEvent,
    syscall: str | None,
) -> RuleMatch | None:
    """Detect a successful exec transition from a user to root identity."""

    if syscall not in {"execve", "execveat"}:
        return None

    uid = raw_value(event, "uid")
    euid = raw_value(event, "euid")
    auid = raw_value(event, "auid")
    success = raw_value(event, "success", "result")
    if not _identity_changed(uid, euid) or not _is_root_identity(euid):
        return None
    if not _is_success(success):
        return None

    host = host_name(event)
    root_entity = f"user:{host}:root" if host else None
    process = process_name(event)
    executable = raw_value(event, "exe", "executable", "process_path")
    return RuleMatch(
        rule_id="HB-SYSCALL-003",
        title="Successful privileged process execution",
        description=(
            "A successful exec system call changed the effective identity "
            "from a non-root user to root."
        ),
        severity="high",
        confidence=0.9,
        related_event_ids=[event.event_id],
        related_entity_ids=compact_entities(
            (process_entity_id(event) or host_entity_id(event), root_entity)
        ),
        evidence={
            "pid": process_pid(event),
            "process_name": process,
            "syscall": syscall,
            "uid": uid,
            "euid": euid,
            "auid": auid,
            "exe": executable,
            "success": success,
            "operation": "privileged_execution",
            "matched_conditions": [
                "successful_exec",
                "real_effective_uid_changed",
                "effective_uid_root",
            ],
        },
        tags=[
            "host_behavior",
            "syscall",
            "privilege_escalation",
            "elevated_execution",
        ],
        detection_type="malicious_behavior",
    )


def _identity_changed(left: object, right: object) -> bool:
    if left in (None, "") or right in (None, ""):
        return False
    return str(left).strip().casefold() != str(right).strip().casefold()


def _is_root_identity(value: object) -> bool:
    return str(value).strip().casefold() in {"0", "root"}


def _is_success(value: object) -> bool:
    return str(value).strip().casefold() in {
        "1",
        "success",
        "successful",
        "true",
        "yes",
    }


def evaluate_memfd_execution_sequences(
    events: list[NormalizedEvent],
    *,
    window: timedelta,
) -> list[tuple[datetime, RuleMatch]]:
    """Detect memfd_create followed by execve in the same host process."""

    pending: dict[tuple[str, int], NormalizedEvent] = {}
    matches: list[tuple[datetime, RuleMatch]] = []

    for event in events:
        if event.event_type not in {"system_call", "syscall"}:
            continue
        host = host_name(event)
        pid = process_pid(event)
        syscall = syscall_name(event)
        if not host or pid is None or not syscall:
            continue

        key = (host, pid)
        timestamp = _as_utc(event.timestamp)
        if syscall == "memfd_create":
            pending[key] = event
            continue

        start_event = pending.get(key)
        if start_event is None:
            continue
        elapsed = timestamp - _as_utc(start_event.timestamp)
        if elapsed > window:
            pending.pop(key, None)
            continue
        if syscall not in {"execve", "execveat"}:
            continue

        matches.append(
            (
                event.timestamp,
                RuleMatch(
                    rule_id="HB-SYSCALL-002",
                    title="Anonymous in-memory file executed",
                    description=(
                        "A process called memfd_create and then executed a file "
                        "within the configured sequence window."
                    ),
                    severity="high",
                    confidence=0.9,
                    related_event_ids=[start_event.event_id, event.event_id],
                    related_entity_ids=compact_entities(
                        (host_entity_id(event), process_entity_id(event))
                    ),
                    evidence={
                        "sequence": ["memfd_create", syscall],
                        "elapsed_seconds": elapsed.total_seconds(),
                        "time_delta_seconds": elapsed.total_seconds(),
                        "window_seconds": int(window.total_seconds()),
                        "pid": pid,
                        "operation": "memory_file_execution",
                        "matched_conditions": [
                            "memfd_create",
                            syscall,
                            "same_host_and_process",
                            "within_time_window",
                        ],
                    },
                    tags=[
                        "host_behavior",
                        "syscall",
                        "execution",
                        "defense_evasion",
                        "memory_execution",
                    ],
                    detection_type="malicious_behavior",
                ),
            )
        )
        pending.pop(key, None)

    return matches


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _target_pid(arguments: object) -> int | None:
    if not isinstance(arguments, dict):
        return None
    for key in ("target_pid", "pid", "process_id"):
        if key in arguments:
            return coerce_int(arguments[key])
    return None
