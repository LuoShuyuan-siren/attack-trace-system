from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any
import json
import os

from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent
from app.services.external_intelligence import ExternalC2Intelligence


APT_PROFILES: dict[str, dict[str, Any]] = {
    "APT29": {
        "name": "APT29",
        "techniques": {"T1059.001", "T1071.001", "T1021.002", "T1041"},
        "tags": {"powershell", "c2", "exfiltration"},
    },
    "APT41": {
        "name": "APT41",
        "techniques": {"T1059.001", "T1560", "T1071.001", "T1021.002"},
        "tags": {"powershell", "web", "lateral_movement"},
    },
    "Lazarus Group": {
        "name": "Lazarus Group",
        "techniques": {"T1059.001", "T1071.004", "T1055", "T1041"},
        "tags": {"dns_tunnel", "process_injection", "exfiltration"},
    },
}


def load_apt_profiles() -> tuple[dict[str, dict[str, Any]], str, str]:
    """Load optional versioned APT profiles, falling back to bundled profiles."""
    path = os.getenv("ATTACK_TRACE_APT_PROFILES")
    if not path:
        return APT_PROFILES, "bundled", "builtin-1"
    try:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return APT_PROFILES, "bundled", "builtin-1"

    profiles = document.get("profiles") if isinstance(document, dict) else document
    if not isinstance(profiles, dict):
        return APT_PROFILES, "bundled", "builtin-1"
    normalized: dict[str, dict[str, Any]] = {}
    for name, profile in profiles.items():
        if not isinstance(profile, dict):
            continue
        techniques = profile.get("techniques", [])
        tags = profile.get("tags", [])
        if not isinstance(techniques, list) or not isinstance(tags, list):
            continue
        normalized[str(name)] = {
            "name": str(profile.get("name", name)),
            "techniques": set(str(item) for item in techniques),
            "tags": set(str(item).casefold() for item in tags),
        }
    if not normalized:
        return APT_PROFILES, "bundled", "builtin-1"
    version = str(document.get("version", "external")) if isinstance(document, dict) else "external"
    return normalized, "external", version


def align_event_times(
    events: list[NormalizedEvent],
    host_offsets_ms: dict[str, int] | None = None,
    host_clock_metadata: dict[str, dict[str, Any]] | None = None,
) -> list[NormalizedEvent]:
    """Apply measured host clock offsets and preserve alignment provenance."""

    offsets = host_offsets_ms or {}
    metadata = host_clock_metadata or {}
    aligned: list[NormalizedEvent] = []
    for event in events:
        host_key = event.host.hostname or event.host.ip or "unknown"
        offset_ms = offsets.get(host_key, _raw_offset_ms(event))
        clock_info = metadata.get(host_key, {})
        raw_data = dict(event.raw_data)
        raw_data.setdefault("original_timestamp", event.timestamp.isoformat())
        raw_data["clock_offset_ms"] = offset_ms
        raw_data["clock_source"] = str(
            clock_info.get("source")
            or raw_data.get("clock_source")
            or ("event_metadata" if "clock_offset_ms" in event.raw_data else "unspecified")
        )
        raw_data["clock_confidence"] = float(
            clock_info.get("confidence", raw_data.get("clock_confidence", 0.0))
        )
        raw_data["alignment_applied"] = bool(offset_ms)
        aligned.append(event.model_copy(update={
            "timestamp": event.timestamp - timedelta(milliseconds=offset_ms),
            "raw_data": raw_data,
        }))
    return aligned


def build_process_tree(events: list[NormalizedEvent]) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: list[dict[str, Any]] = []
    for event in events:
        if event.subject is None or event.subject.pid is None:
            continue
        host = event.host.hostname or event.host.ip or "unknown"
        pid = event.subject.pid
        node_id = f"process:{host}:{pid}"
        nodes[node_id] = {
            "node_id": node_id,
            "host": host,
            "pid": pid,
            "name": event.subject.name or "unknown",
            "user": event.subject.user,
        }
        ppid = _int_value(event.raw_data.get("ppid"))
        if ppid is not None and ppid != pid:
            edges.append({
                "source": f"process:{host}:{ppid}",
                "target": node_id,
                "relation": "parent_process",
                "event_id": event.event_id,
            })
    unique_edges = list({(item["source"], item["target"]): item for item in edges}.values())
    return {"nodes": list(nodes.values()), "edges": unique_edges}


def match_apt_profiles(
    events: list[NormalizedEvent],
    detections: list[DetectionResult],
) -> list[dict[str, Any]]:
    techniques = {
        detection.attack_technique_id
        for detection in detections
        if detection.attack_technique_id
    }
    tags = {tag.casefold() for event in events for tag in event.tags}
    tags.update(tag.casefold() for detection in detections for tag in detection.tags)
    results: list[dict[str, Any]] = []
    profiles, profile_source, profile_version = load_apt_profiles()
    for profile in profiles.values():
        profile_techniques = profile["techniques"]
        technique_overlap = techniques & profile_techniques
        tag_overlap = tags & profile["tags"]
        denominator = len(techniques | profile_techniques) or 1
        score = (len(technique_overlap) / denominator) * 0.8
        score += min(0.2, len(tag_overlap) / max(1, len(profile["tags"])) * 0.2)
        results.append({
            "profile": profile["name"],
            "similarity": round(min(score, 1.0), 4),
            "matched_techniques": sorted(technique_overlap),
            "matched_tags": sorted(tag_overlap),
            "evidence_based": bool(technique_overlap or tag_overlap),
            "profile_source": profile_source,
            "profile_version": profile_version,
        })
    return sorted(results, key=lambda item: item["similarity"], reverse=True)


def extract_attacker_fingerprint(
    events: list[NormalizedEvent],
    detections: list[DetectionResult],
) -> dict[str, Any]:
    process_names = sorted({
        event.subject.name for event in events
        if event.subject and event.subject.name
    })
    command_lines = sorted({
        str(value) for event in events
        for value in [event.raw_data.get("command_line")]
        if value
    })
    user_agents = sorted({
        str(value) for event in events
        for value in [event.raw_data.get("user_agent")]
        if value
    })
    techniques = sorted({
        detection.attack_technique_id for detection in detections
        if detection.attack_technique_id
    })
    material = "|".join(process_names + command_lines + user_agents + techniques)
    return {
        "process_names": process_names,
        "command_lines": command_lines,
        "user_agents": user_agents,
        "attack_techniques": techniques,
        "fingerprint_hash": sha256(material.encode("utf-8")).hexdigest(),
        "evidence_event_ids": [event.event_id for event in events],
    }


def build_c2_infrastructure(
    events: list[NormalizedEvent],
    *,
    enrich: bool = False,
) -> dict[str, Any]:
    endpoints: dict[str, dict[str, Any]] = {}
    relationships: dict[tuple[str, str], dict[str, Any]] = {}
    for event in events:
        if not event.network:
            continue
        if event.network.dst_ip:
            key = f"ip:{event.network.dst_ip}"
            endpoints.setdefault(key, {"type": "ip", "value": event.network.dst_ip, "ports": set(), "event_ids": []})
            endpoints[key]["ports"].add(event.network.dst_port)
            endpoints[key]["event_ids"].append(event.event_id)
        domain = _domain_from_raw(event.raw_data)
        if domain:
            key = f"domain:{domain}"
            endpoints.setdefault(key, {"type": "domain", "value": domain, "ports": set(), "event_ids": []})
            endpoints[key]["ports"].add(event.network.dst_port)
            endpoints[key]["event_ids"].append(event.event_id)
            if event.network.dst_ip:
                ip_key = f"ip:{event.network.dst_ip}"
                relationship = relationships.setdefault(
                    (key, ip_key),
                    {"source": key, "target": ip_key, "relation": "resolves_to", "event_ids": []},
                )
                relationship["event_ids"].append(event.event_id)
    serialized = []
    for endpoint in endpoints.values():
        item = {
            **endpoint,
            "ports": sorted(port for port in endpoint["ports"] if port is not None),
        }
        if enrich:
            intelligence = ExternalC2Intelligence().lookup(endpoint["value"])
            item["intelligence"] = {
                "whois": intelligence.whois,
                "rdap": intelligence.rdap,
                "passive_dns": intelligence.passive_dns,
            }
        serialized.append(item)
    return {
        "endpoints": serialized,
        "relationships": list(relationships.values()),
        "external_enrichment": "not_configured",
    }


def build_report(
    trace: dict[str, Any],
    events: list[NormalizedEvent],
    detections: list[DetectionResult],
    *,
    enrich_c2: bool = False,
) -> dict[str, Any]:
    graph = trace["graph"]
    return {
        "report_type": "attack_trace",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "event_count": len(events),
        "detection_count": len(detections),
        "timeline": trace["stages"],
        "graph": graph.model_dump(mode="json"),
        "paths": trace["paths"],
        "process_tree": build_process_tree(events),
        "apt_matches": match_apt_profiles(events, detections),
        "attacker_fingerprint": extract_attacker_fingerprint(events, detections),
        "c2_infrastructure": build_c2_infrastructure(events, enrich=enrich_c2),
        "limitations": [
            "APT matches use the bundled TTP profiles and are not attribution proof.",
            "WHOIS, RDAP, passive DNS and certificate enrichment are not configured.",
        ],
    }


def _raw_offset_ms(event: NormalizedEvent) -> int:
    value = event.raw_data.get("clock_offset_ms", 0)
    return _int_value(value) or 0


def _int_value(value: object) -> int | None:
    try:
        return int(value) if value is not None else None
    except (TypeError, ValueError):
        return None


def _domain_from_raw(raw_data: dict[str, Any]) -> str | None:
    for key in ("query", "host", "hostname", "domain", "url"):
        value = raw_data.get(key)
        if isinstance(value, str) and "." in value:
            return value.split("/", 1)[0].lower().rstrip(".")
    for value in raw_data.values():
        if isinstance(value, dict):
            domain = _domain_from_raw(value)
            if domain:
                return domain
    return None
