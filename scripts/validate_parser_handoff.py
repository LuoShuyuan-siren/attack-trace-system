"""Validate parser handoff JSON files against the host behavior analyzer."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5

from pydantic import TypeAdapter, ValidationError


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.analyzers.host_behavior import HostBehaviorAnalyzer  # noqa: E402
from app.analyzers.host_behavior.adapters import (  # noqa: E402
    command_line,
    object_path,
    host_name,
    parent_pid,
    parent_process_name,
    process_name,
    process_pid,
    raw_value,
)
from app.schemas.event import NormalizedEvent  # noqa: E402


HOST_BEHAVIOR_EVENT_TYPES = {
    "file_create",
    "file_delete",
    "file_modify",
    "file_read",
    "process_create",
    "process_exec",
    "process_injection",
    "process_memory_write",
    "remote_thread_create",
    "syscall",
    "system_call",
}
EVENT_ID_PATTERN = re.compile(
    r"^evt-[0-9a-fA-F]{8}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{12}$"
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("inputs", nargs="+", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--detections-output", type=Path)
    parser.add_argument(
        "--simulated-input",
        action="append",
        default=[],
        type=Path,
    )
    return parser.parse_args()


def inspect_events(events: list[NormalizedEvent]) -> list[dict]:
    issues: dict[str, list[str]] = defaultdict(list)
    known_processes: dict[tuple[str, int], str] = {}

    for item in sorted(events, key=lambda value: value.timestamp):
        if not EVENT_ID_PATTERN.fullmatch(item.event_id):
            issues["event_id_not_evt_uuid"].append(item.event_id)

        if item.host.os is None:
            issues["host_os_missing"].append(item.event_id)

        if set(item.raw_data) == {"xml_snippet"}:
            issues["raw_data_only_contains_xml_snippet"].append(item.event_id)

        if item.event_type in {"process_create", "process_exec"}:
            if process_pid(item) is None:
                issues["process_pid_missing"].append(item.event_id)
            if parent_pid(item) is None:
                issues["parent_pid_missing"].append(item.event_id)
            item_host = host_name(item)
            item_parent_pid = parent_pid(item)
            parent_known = bool(
                item_host
                and item_parent_pid is not None
                and (item_host, item_parent_pid) in known_processes
            )
            if parent_process_name(item) is None and not parent_known:
                issues["parent_process_name_missing"].append(item.event_id)
            if not command_line(item):
                issues["command_line_missing"].append(item.event_id)

        if item.event_type in {
            "file_create",
            "file_delete",
            "file_modify",
            "file_read",
        }:
            if object_path(item) is None:
                issues["file_path_missing"].append(item.event_id)
            if process_pid(item) is None:
                issues["file_process_context_missing"].append(item.event_id)

        if item.event_type in {"system_call", "syscall"}:
            syscall = raw_value(item, "syscall_name", "syscall", "Syscall")
            if syscall is None:
                issues["syscall_name_missing"].append(item.event_id)
            elif str(syscall).strip().isdigit():
                issues["numeric_syscall_without_symbolic_name"].append(
                    item.event_id
                )
            if raw_value(item, "arguments", "args") is None:
                issues["syscall_arguments_missing"].append(item.event_id)
            if raw_value(item, "result", "return_value", "exit") is None:
                issues["syscall_result_missing"].append(item.event_id)

        item_host = host_name(item)
        item_pid = process_pid(item)
        item_process_name = process_name(item)
        if item_host and item_pid is not None and item_process_name:
            known_processes[(item_host, item_pid)] = item_process_name

    return [
        {
            "code": code,
            "count": len(event_ids),
            "sample_event_ids": event_ids[:5],
        }
        for code, event_ids in sorted(issues.items())
    ]


def stable_detection_ids(results) -> None:
    for result in results:
        seed = "|".join(
            [
                str(result.evidence.get("rule_id", "")),
                *result.related_event_ids,
            ]
        )
        result.detection_id = f"det-{uuid5(NAMESPACE_URL, seed)}"


def inspect_file(path: Path, simulated_paths: set[Path]) -> dict:
    try:
        events = TypeAdapter(list[NormalizedEvent]).validate_json(
            path.read_text(encoding="utf-8-sig")
        )
    except (OSError, ValidationError, ValueError) as exc:
        return {
            "file_name": path.name,
            "schema_valid": False,
            "error": str(exc),
        }

    data_origin = (
        "simulated"
        if path.resolve() in simulated_paths
        else "parser_output"
    )
    results = HostBehaviorAnalyzer().analyze(events)
    stable_detection_ids(results)
    event_types = Counter(item.event_type for item in events)
    supported_count = sum(
        count
        for event_type, count in event_types.items()
        if event_type in HOST_BEHAVIOR_EVENT_TYPES
    )
    is_windows = any(
        item.source.startswith("windows_")
        or (item.host.os or "").casefold() == "windows"
        for item in events
    )
    expected_range = [18, 22] if is_windows else [15, 20]
    file_issues = inspect_events(events)
    if len(events) < expected_range[0]:
        file_issues.append(
            {
                "code": "sample_size_below_handoff_target",
                "count": 1,
                "sample_event_ids": [],
                "observed_event_count": len(events),
                "expected_event_count_range": expected_range,
            }
        )
    if supported_count == 0:
        file_issues.append(
            {
                "code": "no_host_behavior_event_types",
                "count": 1,
                "sample_event_ids": [],
            }
        )
    if not results:
        file_issues.append(
            {
                "code": (
                    "simulated_sample_has_no_detectable_attack_behavior"
                    if data_origin == "simulated"
                    else "no_detection_triggered"
                ),
                "count": 1,
                "sample_event_ids": [],
            }
        )

    return {
        "file_name": path.name,
        "data_origin": data_origin,
        "schema_valid": True,
        "event_count": len(events),
        "expected_event_count_range": expected_range,
        "host_behavior_event_count": supported_count,
        "event_types": dict(sorted(event_types.items())),
        "detection_count": len(results),
        "detection_rule_ids": [
            str(item.evidence.get("rule_id")) for item in results
        ],
        "issues": file_issues,
        "detections": [
            item.model_dump(mode="json") for item in results
        ],
    }


def main() -> None:
    args = parse_args()
    simulated_paths = {
        path.resolve() for path in args.simulated_input
    }
    inputs = [
        inspect_file(path, simulated_paths) for path in args.inputs
    ]
    report = {
        "schema_version": 1,
        "inputs": inputs,
        "totals": {
            "file_count": len(inputs),
            "valid_file_count": sum(
                bool(item.get("schema_valid")) for item in inputs
            ),
            "event_count": sum(
                int(item.get("event_count", 0)) for item in inputs
            ),
            "detection_count": sum(
                int(item.get("detection_count", 0)) for item in inputs
            ),
        },
        "recommendations": [
            (
                "Windows parser: extract structured EventData fields instead "
                "of exposing only a truncated xml_snippet."
            ),
            (
                "Windows parser: include Sysmon-style process_create, file "
                "and memory-behavior events for host behavior integration."
            ),
            (
                "Verify that a simulated handoff file actually contains the "
                "claimed attack cases before treating it as test coverage."
            ),
            (
                "All event IDs should follow evt-UUID so event references "
                "remain stable across analyzers and attack tracing."
            ),
            (
                "Linux parser: attach pid/process subject context to every "
                "file event so process-to-file edges can be built."
            ),
            (
                "Linux parser: provide symbolic syscall_name; if a numeric "
                "syscall is retained, also provide architecture."
            ),
            (
                "Windows should provide 18-22 and Linux should provide 15-20 "
                "representative events including normal and attack behavior."
            ),
        ],
    }

    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8")
    else:
        print(rendered, end="")

    if args.detections_output:
        detections = [
            detection
            for item in inputs
            for detection in item.get("detections", [])
        ]
        args.detections_output.parent.mkdir(parents=True, exist_ok=True)
        args.detections_output.write_text(
            json.dumps(detections, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )


if __name__ == "__main__":
    main()
