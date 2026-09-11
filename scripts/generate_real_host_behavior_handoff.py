"""Build a compact member-4 handoff from real Linux parser output.

The source files stay outside the repository. Only a deterministic 20-event
subset, its host-behavior detections, and a validation summary are committed.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Callable
from uuid import NAMESPACE_URL, uuid5


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.analyzers.host_behavior import HostBehaviorAnalyzer  # noqa: E402
from app.schemas.detection import DetectionResult  # noqa: E402
from app.schemas.event import NormalizedEvent  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the compact real Linux host-behavior handoff."
    )
    parser.add_argument("--t1003-008", required=True, type=Path)
    parser.add_argument("--t1068", required=True, type=Path)
    parser.add_argument("--t1548-003", required=True, type=Path)
    parser.add_argument("--t1552-004", required=True, type=Path)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=BACKEND_ROOT / "examples",
    )
    return parser.parse_args()


def load_events(path: Path) -> list[NormalizedEvent]:
    payload = json.loads(path.read_text(encoding="utf-8-sig"))
    if not isinstance(payload, list):
        raise ValueError(f"{path.name}: top-level value must be a list")
    return [NormalizedEvent.model_validate(item) for item in payload]


def unique_commands(
    events: list[NormalizedEvent],
    limit: int,
) -> list[NormalizedEvent]:
    selected: list[NormalizedEvent] = []
    seen: set[str] = set()
    for event in events:
        command = str(event.raw_data.get("command_line") or "")
        if not command or command in seen:
            continue
        selected.append(event)
        seen.add(command)
        if len(selected) == limit:
            break
    if len(selected) != limit:
        raise ValueError(f"expected {limit} unique commands, got {len(selected)}")
    return selected


def first_matching(
    events: list[NormalizedEvent],
    predicate: Callable[[NormalizedEvent], bool],
    *,
    excluded_ids: set[str] | None = None,
) -> NormalizedEvent:
    excluded_ids = excluded_ids or set()
    for event in events:
        if event.event_id not in excluded_ids and predicate(event):
            return event
    raise ValueError("required representative event was not found")


def syscall(event: NormalizedEvent) -> str:
    value = event.raw_data.get("syscall_name", event.raw_data.get("syscall", ""))
    return str(value).casefold()


def select_t1068(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    predicates: list[Callable[[NormalizedEvent], bool]] = [
        lambda event: syscall(event) == "execve",
        lambda event: event.event_type == "user_login",
        lambda event: event.event_type == "process_create",
        lambda event: syscall(event) == "socket",
        lambda event: syscall(event) == "275",
        lambda event: syscall(event) == "49",
        lambda event: syscall(event) == "54",
    ]
    selected: list[NormalizedEvent] = []
    selected_ids: set[str] = set()
    for predicate in predicates:
        event = first_matching(events, predicate, excluded_ids=selected_ids)
        selected.append(event)
        selected_ids.add(event.event_id)
    return selected


def select_t1548(events: list[NormalizedEvent]) -> list[NormalizedEvent]:
    selected = [event for event in events if syscall(event) == "execve"]
    if len(selected) != 2:
        raise ValueError(f"expected two privileged execve events, got {len(selected)}")
    selected_ids = {event.event_id for event in selected}
    for name in ("openat", "rename"):
        event = first_matching(
            events,
            lambda item, expected=name: syscall(item) == expected,
            excluded_ids=selected_ids,
        )
        selected.append(event)
        selected_ids.add(event.event_id)
    return selected


def stable_detection_ids(results: list[DetectionResult]) -> None:
    for result in results:
        seed = "|".join(
            [str(result.evidence.get("rule_id", "")), *result.related_event_ids]
        )
        result.detection_id = f"det-{uuid5(NAMESPACE_URL, seed)}"


def dump_models(values: list[NormalizedEvent] | list[DetectionResult]) -> list[dict]:
    return [value.model_dump(mode="json") for value in values]


def write_json(path: Path, payload: object) -> None:
    path.write_text(
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    args = parse_args()
    sources = {
        "T1003.008": (args.t1003_008, load_events(args.t1003_008)),
        "T1068": (args.t1068, load_events(args.t1068)),
        "T1548.003": (args.t1548_003, load_events(args.t1548_003)),
        "T1552.004": (args.t1552_004, load_events(args.t1552_004)),
    }
    selected_by_technique = {
        "T1003.008": unique_commands(sources["T1003.008"][1], 4),
        "T1068": select_t1068(sources["T1068"][1]),
        "T1548.003": select_t1548(sources["T1548.003"][1]),
        "T1552.004": unique_commands(sources["T1552.004"][1], 5),
    }
    selected = sorted(
        (
            event
            for technique_events in selected_by_technique.values()
            for event in technique_events
        ),
        key=lambda event: event.timestamp,
    )
    if len(selected) != 20 or len({event.event_id for event in selected}) != 20:
        raise ValueError("handoff must contain exactly 20 unique events")

    detections = HostBehaviorAnalyzer().analyze(selected)
    stable_detection_ids(detections)
    event_ids = {event.event_id for event in selected}
    unresolved = sorted(
        {
            event_id
            for result in detections
            for event_id in result.related_event_ids
            if event_id not in event_ids
        }
    )
    if unresolved:
        raise ValueError(f"detections reference missing events: {unresolved}")

    rule_counts = Counter(
        str(result.evidence.get("rule_id", "unknown")) for result in detections
    )
    technique_by_event_id = {
        event.event_id: technique
        for technique, technique_events in selected_by_technique.items()
        for event in technique_events
    }
    expected_technique_by_detection_id = {
        result.detection_id: technique_by_event_id[result.related_event_ids[0]]
        for result in detections
    }
    summary = {
        "dataset_kind": "real_parser_output_subset",
        "schema_validation": "passed",
        "source_event_count": sum(len(events) for _, events in sources.values()),
        "selected_event_count": len(selected),
        "detection_count": len(detections),
        "selected_counts_by_source_technique": {
            technique: len(events)
            for technique, events in selected_by_technique.items()
        },
        "detection_counts_by_rule": dict(sorted(rule_counts.items())),
        "source_files": {
            technique: path.name for technique, (path, _) in sources.items()
        },
        "integrity": {
            "unique_event_ids": len(event_ids) == len(selected),
            "all_related_event_ids_resolved": not unresolved,
            "entity_direction_convention": "source_then_target",
        },
        "attack_mapping": {
            "status": "pending_member6",
            "source_labels": list(selected_by_technique),
            "source_technique_by_event_id": technique_by_event_id,
            "expected_technique_by_detection_id": (
                expected_technique_by_detection_id
            ),
            "note": (
                "attack_technique_id remains null in member-4 output; member 6 "
                "performs the unified ATT&CK mapping."
            ),
        },
    }
    package = {
        "normalized_events": dump_models(selected),
        "detection_results": dump_models(detections),
        "summary": summary,
    }

    args.output_dir.mkdir(parents=True, exist_ok=True)
    write_json(
        args.output_dir / "member4_host_behavior_real_events.json",
        dump_models(selected),
    )
    write_json(
        args.output_dir / "member4_host_behavior_real_detections.json",
        dump_models(detections),
    )
    write_json(
        args.output_dir / "member4_host_behavior_real_summary.json",
        summary,
    )
    write_json(
        args.output_dir / "member4_host_behavior_real_package.json",
        package,
    )
    print(
        f"validated {summary['source_event_count']} source events; "
        f"selected {len(selected)} and generated {len(detections)} detections"
    )
    print(f"rules: {dict(sorted(rule_counts.items()))}")


if __name__ == "__main__":
    main()
