"""Manual scalability benchmark; intentionally excluded from pytest."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

from app.analyzers.tracing import AttackPathFinder, AttackTraceService
from app.schemas.detection import DetectionResult
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent, SubjectInfo


def synthetic(size: int):
    base = datetime(2026, 9, 8, tzinfo=timezone.utc)
    events = []
    for index in range(size):
        host_number = index % 20
        hostname = f"{'WIN' if host_number % 2 == 0 else 'LINUX'}{host_number:02d}"
        host_ip = f"10.0.0.{host_number + 10}"
        timestamp = base + timedelta(seconds=index)
        kind = index % 3
        if kind == 0:
            events.append(NormalizedEvent(
                event_id=f"evt-{index}", timestamp=timestamp,
                source_type="host_log", source="windows_security" if host_number % 2 == 0 else "linux_auth",
                host=HostInfo(hostname=hostname, ip=host_ip),
                event_type="user_logout", action="logout",
            ))
        elif kind == 1:
            events.append(NormalizedEvent(
                event_id=f"evt-{index}", timestamp=timestamp,
                source_type="host_behavior", source="sysmon" if host_number % 2 == 0 else "auditd",
                host=HostInfo(hostname=hostname, ip=host_ip),
                event_type="process_create", action="create_process",
                subject=SubjectInfo(type="process", name="normal.exe", pid=index + 100),
            ))
        else:
            events.append(NormalizedEvent(
                event_id=f"evt-{index}", timestamp=timestamp,
                source_type="network_traffic", source="zeek",
                host=HostInfo(hostname=hostname, ip=host_ip),
                event_type="network_connection", action="connect",
                network=NetworkInfo(
                    src_ip=host_ip, dst_ip=f"192.0.2.{index % 200 + 1}", dst_port=443
                ),
            ))
    detections = []
    for chain_index in range(max(1, size // 2500)):
        minute = chain_index * 5
        detections.extend([
            DetectionResult(
                detection_id=f"det-{chain_index}-initial",
                timestamp=base + timedelta(minutes=minute), analyzer="benchmark",
                detection_type="malicious_behavior", title="initial", confidence=0.9,
                related_entity_ids=[f"ip:203.0.113.{chain_index + 1}", f"host:WIN{chain_index:02d}"],
                attack_technique_id="T1190", tags=["initial_access"],
            ),
            DetectionResult(
                detection_id=f"det-{chain_index}-c2",
                timestamp=base + timedelta(minutes=minute + 1), analyzer="benchmark",
                detection_type="malicious_behavior", title="c2", confidence=0.9,
                related_entity_ids=[f"host:WIN{chain_index:02d}", "ip:8.8.8.8"],
                attack_technique_id="T1071.001", tags=["c2_communication"],
            ),
        ])
    return events, detections


def run(size: int):
    events, detections = synthetic(size)
    service = AttackTraceService()
    started = perf_counter()
    result = service.analyze(events, detections, graph_id=f"benchmark-{size}")
    total = perf_counter() - started
    path_started = perf_counter()
    paths = AttackPathFinder().find_paths(result["graph"])
    path_time = perf_counter() - path_started
    graph = result["graph"]
    print(
        f"events={size} detections={len(detections)} total_seconds={total:.4f} "
        f"nodes={len(graph.nodes)} edges={len(graph.edges)} "
        f"stages={len(result['stages'])} paths={len(paths)} "
        f"path_finder_seconds={path_time:.4f}"
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sizes", nargs="+", type=int, default=[1000, 5000, 10000])
    args = parser.parse_args()
    for size in args.sizes:
        run(size)


if __name__ == "__main__":
    main()
