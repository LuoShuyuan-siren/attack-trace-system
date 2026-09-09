"""Host process, file, system-call and explicit memory behavior analyzer."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from app.core.analyzer import BaseAnalyzer
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent

from .adapters import (
    host_name,
    parent_pid,
    parent_process_name,
    process_name,
    process_pid,
)
from .file_rules import evaluate_bulk_file_changes, evaluate_file_event
from .process_rules import evaluate_process_event
from .rule_match import RuleMatch
from .syscall_rules import (
    evaluate_memfd_execution_sequences,
    evaluate_syscall_event,
)


class HostBehaviorAnalyzer(BaseAnalyzer):
    """Analyze normalized host telemetry without parsing original log files."""

    def __init__(
        self,
        *,
        bulk_file_threshold: int = 20,
        bulk_file_window_seconds: int = 60,
        memfd_execution_window_seconds: int = 30,
    ) -> None:
        if bulk_file_threshold < 2:
            raise ValueError("bulk_file_threshold must be at least 2")
        if bulk_file_window_seconds <= 0:
            raise ValueError("bulk_file_window_seconds must be positive")
        if memfd_execution_window_seconds <= 0:
            raise ValueError("memfd_execution_window_seconds must be positive")

        self._bulk_file_threshold = bulk_file_threshold
        self._bulk_file_window = timedelta(seconds=bulk_file_window_seconds)
        self._memfd_execution_window = timedelta(
            seconds=memfd_execution_window_seconds
        )

    @property
    def name(self) -> str:
        return "host_behavior_analyzer"

    def analyze(
        self,
        events: list[NormalizedEvent],
    ) -> list[DetectionResult]:
        """Return detections in event-time order.

        Network-only events are ignored. Missing parser-specific raw fields
        lower rule coverage but never cause the whole analysis task to fail.
        """

        host_events = sorted(
            (
                event
                for event in events
                if event.source_type in {"host_log", "host_behavior"}
            ),
            key=lambda event: _as_utc(event.timestamp),
        )
        timestamped_matches: list[tuple[datetime, RuleMatch]] = []
        process_names: dict[tuple[str, int], str] = {}

        for event in host_events:
            host = host_name(event)
            resolved_parent_name = parent_process_name(event)
            event_parent_pid = parent_pid(event)
            if (
                resolved_parent_name is None
                and host is not None
                and event_parent_pid is not None
            ):
                resolved_parent_name = process_names.get(
                    (host, event_parent_pid)
                )

            for match in evaluate_process_event(
                event,
                resolved_parent_name=resolved_parent_name,
            ):
                timestamped_matches.append((event.timestamp, match))
            for match in evaluate_file_event(event):
                timestamped_matches.append((event.timestamp, match))
            for match in evaluate_syscall_event(event):
                timestamped_matches.append((event.timestamp, match))

            event_pid = process_pid(event)
            event_process_name = process_name(event)
            if host and event_pid is not None and event_process_name:
                process_names[(host, event_pid)] = event_process_name

        timestamped_matches.extend(
            evaluate_bulk_file_changes(
                host_events,
                threshold=self._bulk_file_threshold,
                window=self._bulk_file_window,
            )
        )
        timestamped_matches.extend(
            evaluate_memfd_execution_sequences(
                host_events,
                window=self._memfd_execution_window,
            )
        )
        timestamped_matches.sort(key=lambda item: _as_utc(item[0]))

        return [
            self._to_detection(timestamp, match)
            for timestamp, match in timestamped_matches
        ]

    def _to_detection(
        self,
        timestamp: datetime,
        match: RuleMatch,
    ) -> DetectionResult:
        return DetectionResult(
            timestamp=timestamp,
            analyzer=self.name,
            detection_type=match.detection_type,
            title=match.title,
            description=match.description,
            severity=match.severity,
            confidence=match.confidence,
            related_event_ids=match.related_event_ids,
            related_entity_ids=match.related_entity_ids,
            evidence={"rule_id": match.rule_id, **match.evidence},
            attack_technique_id=None,
            tags=list(dict.fromkeys([match.rule_id, *match.tags])),
        )


def _as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)
