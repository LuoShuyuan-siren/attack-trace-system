"""Validate real fixtures and run evidence-preserving tracing diagnostics."""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from pydantic import ValidationError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.analyzers.tracing import AttackGraphBuilder, AttackTraceService
from app.analyzers.tracing.agents import TraceAgentOrchestrator
from app.analyzers.tracing.agents.llm import create_llm_client
from app.analyzers.tracing.normalization import utc_datetime
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


@dataclass
class LoadedInput:
    events: list[NormalizedEvent] = field(default_factory=list)
    detections: list[DetectionResult] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    file_notes: list[str] = field(default_factory=list)
    detection_field_missing: Counter = field(default_factory=Counter)


def _payload_array(path: Path, kind: str, loaded: LoadedInput) -> list[Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        loaded.errors.append(f"{path}: cannot read valid JSON: {exc}")
        return []
    if isinstance(payload, list):
        return payload
    key = "normalized_events" if kind == "events" else "detection_results"
    wrapped = payload.get(key) if isinstance(payload, dict) else None
    if isinstance(wrapped, list):
        loaded.file_notes.append(f"{path}: read {kind} from wrapper field {key}")
        if kind == "events":
            declared = (payload.get("summary") or {}).get("total_events")
            if declared is not None and declared != len(wrapped):
                loaded.file_notes.append(
                    f"{path}: summary.total_events={declared}, actual={len(wrapped)}"
                )
        return wrapped
    loaded.errors.append(f"{path}: expected a top-level array or wrapper field {key}")
    return []


def load_inputs(event_paths: list[str], detection_paths: list[str]) -> LoadedInput:
    loaded = LoadedInput()
    specs = (
        ("events", event_paths, NormalizedEvent, loaded.events),
        ("detections", detection_paths, DetectionResult, loaded.detections),
    )
    for kind, paths, model, destination in specs:
        for value in paths:
            path = Path(value)
            for index, item in enumerate(_payload_array(path, kind, loaded)):
                if kind == "detections" and isinstance(item, dict):
                    for key in (
                        "detection_id", "related_event_ids", "related_entity_ids",
                        "attack_technique_id", "confidence", "evidence", "tags",
                    ):
                        if key not in item:
                            loaded.detection_field_missing[key] += 1
                try:
                    destination.append(model.model_validate(item))
                except ValidationError as exc:
                    for error in exc.errors(include_url=False):
                        location = ".".join(map(str, error["loc"])) or "<root>"
                        loaded.errors.append(f"{path}[{index}].{location}: {error['msg']}")
    return loaded


def _replacement_count(value: Any) -> int:
    if isinstance(value, str):
        return value.count("\ufffd")
    if isinstance(value, dict):
        return sum(_replacement_count(item) for item in value.values())
    if isinstance(value, (list, tuple)):
        return sum(_replacement_count(item) for item in value)
    return 0


def _format_span(seconds: float) -> str:
    days, remainder = divmod(int(seconds), 86400)
    hours, remainder = divmod(remainder, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{days}d {hours:02d}:{minutes:02d}:{seconds:02d}"


def linux_coverage(events: list[NormalizedEvent]) -> dict[str, int]:
    linux = [event for event in events if (event.host.os or "").lower() == "linux"]

    def text(event: NormalizedEvent) -> str:
        return " ".join([event.event_type, event.action, *event.tags, str(event.raw_data)]).lower()

    return {
        "linux_events": len(linux),
        "ssh_success": sum("ssh" in text(e) and any(x in text(e) for x in ("success", "accepted", "login")) for e in linux),
        "ssh_failure": sum("ssh" in text(e) and any(x in text(e) for x in ("fail", "denied", "invalid")) for e in linux),
        "sudo": sum("sudo" in text(e) for e in linux),
        "su": sum(e.event_type == "su" or e.action == "su" or " su " in f" {text(e)} " for e in linux),
        "auditd": sum(e.source == "linux_auditd" or "auditd" in e.tags for e in linux),
        "execve": sum(
            e.action == "execve" or e.event_type == "execve"
            or e.raw_data.get("syscall_name") == "execve"
            or str(e.raw_data.get("syscall")) == "59"
            for e in linux
        ),
        "process_execution": sum(e.event_type in {"process_create", "execute"} for e in linux),
        "network_connection": sum(e.event_type == "network_connection" for e in linux),
        "with_username": sum(bool(e.subject and (e.subject.user or e.subject.name)) for e in linux),
        "with_source_ip": sum(bool(e.network and e.network.src_ip) for e in linux),
        "with_destination_ip": sum(bool(e.network and e.network.dst_ip) for e in linux),
        "with_hostname": sum(bool(e.host.hostname) for e in linux),
        "with_timestamp": len(linux),
        "with_process_pid": sum(bool(e.subject and e.subject.type == "process" and e.subject.pid is not None) for e in linux),
        "sensitive_file_access": sum(
            bool(e.object and (e.object.path or e.object.name))
            and any(value in (e.object.path or e.object.name).lower() for value in ("/etc/shadow", "/etc/passwd", "/etc/sudoers", "/.ssh/"))
            for e in linux
        ),
    }


def correlation_diagnostics(loaded: LoadedInput) -> dict[str, Any]:
    events, detections = loaded.events, loaded.detections
    event_ids = {event.event_id for event in events}
    entity_ids = {node.node_id for node in AttackGraphBuilder().build(events, []).nodes}
    event_refs = [ref for item in detections for ref in item.related_event_ids]
    entity_refs = [ref for item in detections for ref in item.related_entity_ids]
    valid_event_refs = [ref for ref in event_refs if ref in event_ids]
    valid_entity_refs = [ref for ref in entity_refs if ref in entity_ids]
    missing_event_refs = [ref for ref in event_refs if ref not in event_ids]
    missing_entity_refs = [ref for ref in entity_refs if ref not in entity_ids]
    network_events = [event for event in events if event.network is not None]
    timestamps = [utc_datetime(item.timestamp) for item in [*events, *detections]]
    minimum = min(timestamps) if timestamps else None
    maximum = max(timestamps) if timestamps else None
    span_seconds = (maximum - minimum).total_seconds() if minimum and maximum else 0
    result = {
        "schema_valid": not loaded.errors,
        "total_events": len(events),
        "total_detections": len(detections),
        "missing_event_reference_count": len(missing_event_refs),
        "missing_entity_reference_count": len(missing_entity_refs),
        "valid_event_reference_count": len(valid_event_refs),
        "valid_entity_reference_count": len(valid_entity_refs),
        "valid_event_references": sorted(set(valid_event_refs)),
        "valid_entity_references": sorted(set(valid_entity_refs)),
        "missing_event_references": sorted(set(missing_event_refs)),
        "missing_entity_references": sorted(set(missing_entity_refs)),
        "detections_without_attack_technique_id": sum(not item.attack_technique_id for item in detections),
        "detections_without_related_entity_ids": sum(not item.related_entity_ids for item in detections),
        "events_without_hostname": sum(not event.host.hostname for event in events),
        "events_without_host_ip": sum(not event.host.ip for event in events),
        "network_events_without_process_context": sum(
            not event.subject or event.subject.type != "process" or event.subject.pid is None
            for event in network_events
        ),
        "unicode_replacement_character_count": _replacement_count(
            [item.model_dump(mode="json") for item in [*events, *detections]]
        ),
        "min_timestamp": minimum.isoformat() if minimum else None,
        "max_timestamp": maximum.isoformat() if maximum else None,
        "total_time_span": _format_span(span_seconds),
        "detection_field_missing_counts": dict(loaded.detection_field_missing),
        "linux_coverage": linux_coverage(events),
    }
    reasons = []
    checks = (
        (loaded.errors, f"schema validation errors: {len(loaded.errors)}"),
        (missing_event_refs, f"missing detection event references: {len(missing_event_refs)}"),
        (missing_entity_refs, f"missing detection entity references: {len(missing_entity_refs)}"),
        (result["detections_without_related_entity_ids"], f"detections without related entity IDs: {result['detections_without_related_entity_ids']}"),
        (result["events_without_hostname"], f"events without hostname: {result['events_without_hostname']}"),
        (result["events_without_host_ip"], f"events without host IP: {result['events_without_host_ip']}"),
        (result["network_events_without_process_context"], f"network events without process context: {result['network_events_without_process_context']}"),
        (result["unicode_replacement_character_count"], f"Unicode replacement characters: {result['unicode_replacement_character_count']}"),
        (span_seconds > 86400, f"input time span exceeds 24 hours: {result['total_time_span']}"),
    )
    reasons.extend(message for condition, message in checks if condition)
    low = bool(loaded.errors) or (
        bool(network_events) and result["network_events_without_process_context"] == len(network_events)
    ) or (bool(events) and result["events_without_hostname"] == len(events))
    result["correlation_ready"] = "low" if low else ("medium" if reasons else "high")
    result["correlation_readiness_reasons"] = reasons
    return result


def _print(key: str, value: Any) -> None:
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, sort_keys=True, default=str)
    print(f"{key}={value}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--events", action="append", default=[])
    parser.add_argument("--detections", action="append", default=[])
    parser.add_argument("--label", default="integration")
    parser.add_argument("--agents", action="store_true")
    args = parser.parse_args()
    if not args.events and not args.detections:
        parser.error("at least one --events or --detections input is required")

    loaded = load_inputs(args.events, args.detections)
    for note in loaded.file_notes:
        _print("input_note", note)
    for error in loaded.errors:
        _print("validation_error", error)
    for key, value in correlation_diagnostics(loaded).items():
        _print(key, value)
    if loaded.errors:
        return 2

    service = AttackTraceService()
    result = service.analyze(loaded.events, loaded.detections, graph_id=f"graph-{args.label}")
    graph = result["graph"]
    summary = {
        "input_events": len(loaded.events), "input_detections": len(loaded.detections),
        **service.last_diagnostics,
        "node_count": len(graph.nodes), "edge_count": len(graph.edges),
        "relations_histogram": dict(sorted(Counter(edge.relation for edge in graph.edges).items())),
        "stages": result["stages"], "stage_count": len(result["stages"]),
        "candidate_path_count": len(result["paths"]),
        "top_path_score": result["paths"][0]["score"] if result["paths"] else None,
    }
    for key, value in summary.items():
        _print(key, value)

    if not args.agents:
        _print("agent_enabled", False)
        _print("agent_degraded", False)
        return 0
    agent_result = TraceAgentOrchestrator(
        llm=create_llm_client(), enabled=True, trace_service=service
    ).analyze(loaded.events, loaded.detections, graph_id=f"graph-{args.label}-agents")
    status, analysis = agent_result["agent_status"], agent_result["agent_analysis"]
    _print("agent_enabled", status["enabled"])
    _print("agent_degraded", status["degraded"])
    _print("agent_errors", status["errors"])
    _print("evidence_confidence", analysis["evidence"]["overall_confidence"])
    _print("chain_status", analysis["chain_review"]["status"])
    _print("chain_confidence", analysis["chain_review"]["confidence"])
    _print("missing_stages", analysis["chain_review"]["missing_stages"])
    _print("attribution_confidence", analysis["attribution"]["confidence"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
