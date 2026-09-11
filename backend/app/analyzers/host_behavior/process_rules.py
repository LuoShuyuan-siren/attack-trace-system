"""Rules for suspicious process creation and explicit memory behavior."""

from __future__ import annotations

from app.schemas.event import NormalizedEvent

from .adapters import (
    command_line,
    compact_entities,
    host_entity_id,
    normalized_executable_name,
    normalized_path,
    parent_pid,
    parent_process_name as event_parent_process_name,
    process_entity_id,
    process_execution_entities,
    process_image,
    process_name,
    process_pid,
)
from .rule_match import RuleMatch


_DOCUMENT_PROCESSES = {
    "acrord32.exe",
    "excel.exe",
    "outlook.exe",
    "powerpnt.exe",
    "soffice.bin",
    "winword.exe",
}
_SHELL_OR_SCRIPT_PROCESSES = {
    "bash",
    "cmd.exe",
    "cscript.exe",
    "mshta.exe",
    "powershell.exe",
    "pwsh",
    "pwsh.exe",
    "regsvr32.exe",
    "rundll32.exe",
    "sh",
    "wscript.exe",
}
_WEB_SERVICE_PROCESSES = {
    "apache2",
    "httpd",
    "nginx",
    "php-fpm",
    "tomcat",
    "w3wp.exe",
}
_SUSPICIOUS_COMMAND_INDICATORS = {
    "-encodedcommand": "encoded PowerShell command",
    " -enc ": "encoded PowerShell command",
    "frombase64string": "Base64 decoding",
    "invoke-expression": "dynamic PowerShell execution",
    "iex(": "dynamic PowerShell execution",
    "downloadstring(": "in-memory download",
    "javascript:": "script protocol execution",
}
_TEMP_EXECUTABLE_SUFFIXES = (
    ".bat",
    ".cmd",
    ".com",
    ".dll",
    ".exe",
    ".ps1",
    ".sh",
)


def evaluate_process_event(
    event: NormalizedEvent,
    *,
    resolved_parent_name: str | None = None,
) -> list[RuleMatch]:
    """Evaluate process and explicit memory-behavior rules for one event."""

    if event.event_type in {
        "process_injection",
        "process_access",
        "remote_thread_create",
        "process_memory_write",
        "image_load",
        "process_tamper",
        "reflective_load",
    }:
        return [_explicit_memory_behavior(event)]

    if event.event_type not in {"process_create", "process_exec"} and event.action not in {
        "create_process",
        "execute",
        "exec",
    }:
        return []

    matches: list[RuleMatch] = []
    child = normalized_executable_name(process_name(event))
    parent_name = event_parent_process_name(event) or resolved_parent_name
    parent = normalized_executable_name(parent_name)
    cmdline = command_line(event)
    normalized_cmdline = cmdline.casefold()
    child_pid = process_pid(event)
    child_path = normalized_path(process_image(event))

    execution_entities = process_execution_entities(event)
    parent_child_entities = process_execution_entities(
        event,
        source_pid=parent_pid(event),
    )
    common_evidence = {
        "pid": child_pid,
        "ppid": parent_pid(event),
        "process_name": child or process_name(event),
        "process_image": process_image(event),
        "parent_process": parent or parent_name,
        "command_line": cmdline,
    }

    if parent in _DOCUMENT_PROCESSES and child in _SHELL_OR_SCRIPT_PROCESSES:
        matches.append(
            RuleMatch(
                rule_id="HB-PROC-001",
                title="Document application spawned a command interpreter",
                description=(
                    "A document or email application created a shell or script "
                    "interpreter, which is uncommon in normal office workflows."
                ),
                severity="high",
                confidence=0.88,
                related_event_ids=[event.event_id],
                related_entity_ids=parent_child_entities,
                evidence={
                    **common_evidence,
                    "matched_conditions": [
                        "document_process_parent",
                        "shell_or_script_child",
                    ],
                },
                tags=[
                    "host_behavior",
                    "process",
                    "execution",
                    "suspicious_parent_child",
                ],
            )
        )

    if parent in _WEB_SERVICE_PROCESSES and child in _SHELL_OR_SCRIPT_PROCESSES:
        matches.append(
            RuleMatch(
                rule_id="HB-PROC-002",
                title="Web service spawned a command interpreter",
                description=(
                    "A web-facing service created a shell or script interpreter; "
                    "this may indicate exploitation or web-shell activity."
                ),
                severity="critical",
                confidence=0.93,
                related_event_ids=[event.event_id],
                related_entity_ids=parent_child_entities,
                evidence={
                    **common_evidence,
                    "matched_conditions": [
                        "web_service_parent",
                        "shell_or_script_child",
                    ],
                },
                tags=[
                    "host_behavior",
                    "process",
                    "initial_access",
                    "execution",
                    "web_service",
                    "shell",
                ],
            )
        )

    indicators = sorted(
        {
            label
            for indicator, label in _SUSPICIOUS_COMMAND_INDICATORS.items()
            if indicator in f" {normalized_cmdline} "
        }
    )
    if indicators:
        matches.append(
            RuleMatch(
                rule_id="HB-PROC-003",
                title="Suspicious process command line",
                description=(
                    "The process command line contains execution or decoding "
                    "patterns commonly used by malicious scripts."
                ),
                severity="high",
                confidence=0.82,
                related_event_ids=[event.event_id],
                related_entity_ids=execution_entities,
                evidence={
                    **common_evidence,
                    "matched_conditions": indicators,
                },
                tags=[
                    "host_behavior",
                    "process",
                    "execution",
                    "command_line",
                ],
            )
        )

    if (
        child_path.endswith(_TEMP_EXECUTABLE_SUFFIXES)
        and _is_temporary_path(child_path)
    ):
        matches.append(
            RuleMatch(
                rule_id="HB-PROC-004",
                title="Executable launched from a temporary directory",
                description=(
                    "A script or executable was launched from a user or system "
                    "temporary directory."
                ),
                severity="medium",
                confidence=0.72,
                related_event_ids=[event.event_id],
                related_entity_ids=execution_entities,
                evidence={
                    **common_evidence,
                    "matched_conditions": [
                        "executable_or_script",
                        "temporary_directory",
                    ],
                },
                tags=[
                    "host_behavior",
                    "process",
                    "execution",
                    "temporary_directory",
                ],
            )
        )

    return matches


def _explicit_memory_behavior(event: NormalizedEvent) -> RuleMatch:
    event_kind = event.event_type
    technique = str(
        event.raw_data.get("technique")
        or event.raw_data.get("injection_type")
        or event.raw_data.get("operation")
        or event.action
    )
    if event_kind in {"image_load", "reflective_load"}:
        title = "Suspicious image or reflective load"
        description = (
            "Host telemetry reported an image load outside the normal loader "
            "path or a reflective/in-memory module load."
        )
    elif event_kind == "process_tamper":
        title = "Process tampering detected"
        description = "Host telemetry reported tampering with a running process."
    else:
        title = "Explicit cross-process memory behavior"
        description = (
            "Host telemetry reported process injection, remote thread creation "
            "or a cross-process memory write."
        )

    return RuleMatch(
        rule_id="HB-MEM-001",
        title=title,
        description=description,
        severity="critical",
        confidence=0.95,
        related_event_ids=[event.event_id],
        related_entity_ids=compact_entities(
            (
                process_entity_id(event) or host_entity_id(event),
                process_entity_id(
                    event,
                    event.object.pid if event.object else None,
                ),
            )
        ),
        evidence={
            "pid": process_pid(event),
            "target_pid": event.object.pid if event.object else None,
            "process_name": process_name(event),
            "event_type": event.event_type,
            "operation": event.action,
            "technique": technique,
            "source": event.source,
            "matched_conditions": [event.event_type],
            "raw_data": event.raw_data,
        },
        tags=[
            "host_behavior",
            "memory",
            "execution",
            "process_injection",
        ],
        detection_type="malicious_behavior",
    )


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
