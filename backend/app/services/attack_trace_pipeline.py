"""Member 6 integration pipeline for traffic analysis and ATT&CK mapping."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from app.analyzers.attack_mapping import (
    AttackMapper,
    AttackMappingResult,
    AttackStage,
    build_attack_stages,
    build_ttp_profile,
)
from app.analyzers.attack_mapping.models import TTPProfile
from app.analyzers.traffic import (
    ConnectionAnalyzer,
    DnsAnalyzer,
    HttpAnalyzer,
    IcmpAnalyzer,
)
from app.parsers.traffic import PcapParser, SuricataParser, ZeekParser
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


@dataclass(frozen=True)
class AttackTracePipelineResult:
    events: list[NormalizedEvent]
    detections: list[DetectionResult]
    mappings: list[AttackMappingResult]
    stages: list[AttackStage]
    ttp_profile: TTPProfile

    def to_member7_payload(self) -> dict[str, object]:
        return {
            "normalized_events": [
                event.model_dump(mode="json") for event in self.events
            ],
            "detection_results": [
                detection.model_dump(mode="json")
                for detection in self.detections
            ],
            "mapping_results": [
                mapping.to_dict() for mapping in self.mappings
            ],
            "stages": [stage.to_dict() for stage in self.stages],
            "ttp_profile": self.ttp_profile.to_dict(),
        }


class TrafficAnalysisPipeline:
    """Run traffic parsers, analyzers, and member6 ATT&CK mapping."""

    def __init__(self, analyzers: Iterable[object] | None = None) -> None:
        self._parsers = {
            ".pcap": PcapParser(),
            ".pcapng": PcapParser(),
            ".cap": PcapParser(),
            ".log": ZeekParser(),
            ".json": SuricataParser(),
            "eve": SuricataParser(),
        }
        self._analyzers = list(analyzers) if analyzers is not None else [
            DnsAnalyzer(),
            HttpAnalyzer(),
            IcmpAnalyzer(),
            ConnectionAnalyzer(),
        ]

    def run(self, source: Path) -> AttackTracePipelineResult:
        events = self._parse(source)
        detections = self._analyze(events)
        return build_pipeline_result(events, detections)

    def _parse(self, source: Path) -> list[NormalizedEvent]:
        parser = self._parsers.get(source.suffix.lower())
        if parser is None:
            raise ValueError(f"Unsupported traffic source: {source.suffix}")
        return parser.parse(source)

    def _analyze(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        detections: list[DetectionResult] = []
        for analyzer in self._analyzers:
            detections.extend(analyzer.analyze(events))
        return detections


def build_pipeline_result(
    events: list[NormalizedEvent],
    detections: Iterable[DetectionResult],
) -> AttackTracePipelineResult:
    deduplicated = deduplicate_detections(list(detections))
    mappings = AttackMapper().map_many(deduplicated)
    stages = build_attack_stages(mappings)
    profile = build_ttp_profile(mappings)
    return AttackTracePipelineResult(
        events=events,
        detections=deduplicated,
        mappings=mappings,
        stages=stages,
        ttp_profile=profile,
    )


def deduplicate_detections(
    detections: Iterable[DetectionResult],
) -> list[DetectionResult]:
    seen: set[tuple[object, ...]] = set()
    result: list[DetectionResult] = []
    for detection in sorted(
        detections,
        key=lambda item: (item.timestamp, item.detection_id),
    ):
        key = _dedupe_key(detection)
        if key in seen:
            continue
        seen.add(key)
        result.append(detection)
    return result


def _dedupe_key(detection: DetectionResult) -> tuple[object, ...]:
    evidence = detection.evidence or {}
    event_ids = tuple(sorted(detection.related_event_ids[:20]))
    return (
        detection.analyzer,
        detection.detection_type,
        evidence.get("src_ip"),
        evidence.get("dst_ip"),
        event_ids,
    )
