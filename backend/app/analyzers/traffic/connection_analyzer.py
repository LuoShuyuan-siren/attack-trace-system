"""网络连接 / 会话分析器。

检测能力：
- 5-tuple 会话识别
- 短时间大量连接
- 同一源访问大量端口
- 同一源访问大量目标
- 非常用端口通信
- 长连接
- 周期性连接
- Beacon-like 行为
"""

from collections import defaultdict
from datetime import datetime

from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent
from app.parsers.traffic.config import CONNECTION_THRESHOLDS
from app.parsers.traffic.utils import (
    detect_periodicity,
    rate_per_minute,
)
from app.analyzers.traffic.base import TrafficAnalyzerBase


class ConnectionAnalyzer(TrafficAnalyzerBase):
    """网络连接 / 会话分析器。

    消费 NormalizedEvent 中的网络连接事件，
    输出 DetectionResult。
    """

    @property
    def name(self) -> str:
        return "connection_analyzer"

    def analyze(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        """分析网络连接事件，输出检测结果。"""
        traffic_events = [
            e for e in self._filter_traffic_events(events)
            if e.event_type in {"network_flow", "network_connection"}
        ]

        if not traffic_events:
            return []

        results: list[DetectionResult] = []

        # 按源 IP 分组
        by_src: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in traffic_events:
            src_ip = e.network.src_ip if e.network else "unknown"
            by_src[src_ip].append(e)

        for src_ip, src_events in by_src.items():
            if src_ip == "unknown":
                continue
            results.extend(self._analyze_per_source(src_ip, src_events))

        return results

    def _analyze_per_source(
        self,
        src_ip: str,
        events: list[NormalizedEvent],
    ) -> list[DetectionResult]:
        """分析单个源 IP 的网络连接。"""
        results: list[DetectionResult] = []

        dst_ips: set[str] = set()
        dst_ports: set[int] = set()
        timestamps: list[datetime] = []
        event_ids: list[str] = []
        connection_pairs: dict[str, list[NormalizedEvent]] = defaultdict(list)

        for e in events:
            net = e.network
            if net is None:
                continue

            if net.dst_ip:
                dst_ips.add(net.dst_ip)
            if net.dst_port:
                dst_ports.add(net.dst_port)
            timestamps.append(e.timestamp)
            event_ids.append(e.event_id)

            pair_key = f"{net.src_ip}:{net.dst_ip}:{net.dst_port}"
            connection_pairs[pair_key].append(e)

        total_connections = len(events)
        if total_connections == 0:
            return []

        indicators: dict[str, object] = {
            "total_connections": total_connections,
            "unique_dst_ips": len(dst_ips),
            "unique_dst_ports": len(dst_ports),
        }

        # 1. 短时间大量连接
        max_rate = rate_per_minute(timestamps) if timestamps else 0.0
        indicators["max_connection_rate_per_min"] = round(max_rate, 1)

        # 2. 端口扫描检测
        port_scan_detected = (
            len(dst_ports) >= CONNECTION_THRESHOLDS.port_scan_threshold
            and total_connections >= CONNECTION_THRESHOLDS.port_scan_threshold
        )

        # 3. 大量目标 IP
        mass_connection_detected = (
            len(dst_ips) >= CONNECTION_THRESHOLDS.mass_connection_threshold
        )

        # 4. 非常用端口
        uncommon_port_conns: list[int] = []
        for port in dst_ports:
            if port and port not in CONNECTION_THRESHOLDS.uncommon_ports:
                uncommon_port_conns.append(port)
        indicators["uncommon_ports_count"] = len(uncommon_port_conns)

        # 5. 长连接检测
        long_connections: list[str] = []
        for pair_key, pair_events in connection_pairs.items():
            if len(pair_events) < 2:
                continue
            sorted_ts = sorted([e.timestamp for e in pair_events])
            duration = (sorted_ts[-1] - sorted_ts[0]).total_seconds()
            if duration > CONNECTION_THRESHOLDS.long_connection_threshold:
                long_connections.append(pair_key)

        indicators["long_connections"] = len(long_connections)

        # 6. 周期性连接 / Beacon 检测
        beacon_pairs: list[str] = []
        for pair_key, pair_events in connection_pairs.items():
            pair_timestamps = [e.timestamp for e in pair_events]
            is_periodic, _, _ = detect_periodicity(
                pair_timestamps,
                min_intervals=CONNECTION_THRESHOLDS.beacon_min_intervals,
                max_jitter_ratio=CONNECTION_THRESHOLDS.beacon_max_jitter_ratio,
            )
            if is_periodic:
                beacon_pairs.append(pair_key)
        indicators["beacon_connections"] = len(beacon_pairs)

        # --- 检测逻辑 ---

        # 端口扫描
        if port_scan_detected:
            results.append(self._make_detection(
                title=f"疑似端口扫描行为 (源: {src_ip})",
                description=(
                    f"源 IP {src_ip} 在短时间内访问了 {len(dst_ports)} 个不同端口，"
                    f"超过阈值 {CONNECTION_THRESHOLDS.port_scan_threshold}"
                ),
                detection_type="suspicious_behavior",
                severity="medium",
                confidence=min(
                    CONNECTION_THRESHOLDS.base_confidence + 0.1,
                    CONNECTION_THRESHOLDS.max_confidence,
                ),
                evidence={
                    "src_ip": src_ip,
                    "unique_dst_ports": len(dst_ports),
                    "scanned_ports": sorted(list(dst_ports))[:30],
                    "threshold": CONNECTION_THRESHOLDS.port_scan_threshold,
                },
                related_event_ids=event_ids[:50],
                tags=["connection", "port_scan"],
                attack_technique_id="T1046",  # Network Service Scanning
            ))

        # 大量目标连接
        if mass_connection_detected:
            results.append(self._make_detection(
                title=f"疑似大范围连接行为 (源: {src_ip})",
                description=(
                    f"源 IP {src_ip} 在短时间内连接了 {len(dst_ips)} 个不同目标 IP，"
                    f"超过阈值 {CONNECTION_THRESHOLDS.mass_connection_threshold}"
                ),
                detection_type="suspicious_behavior",
                severity="medium",
                confidence=CONNECTION_THRESHOLDS.base_confidence,
                evidence={
                    "src_ip": src_ip,
                    "unique_dst_ips": len(dst_ips),
                    "threshold": CONNECTION_THRESHOLDS.mass_connection_threshold,
                },
                related_event_ids=event_ids[:50],
                tags=["connection", "mass_connection"],
            ))

        # 非常用端口
        if len(uncommon_port_conns) >= 5:
            results.append(self._make_detection(
                title=f"非常用端口通信 (源: {src_ip})",
                description=(
                    f"源 IP {src_ip} 访问了 {len(uncommon_port_conns)} 个非常用端口"
                ),
                detection_type="anomaly",
                severity="low",
                confidence=CONNECTION_THRESHOLDS.base_confidence,
                evidence={
                    "src_ip": src_ip,
                    "uncommon_ports": sorted(uncommon_port_conns)[:20],
                },
                related_event_ids=event_ids[:50],
                tags=["connection", "uncommon_port"],
            ))

        # 长连接
        if long_connections:
            results.append(self._make_detection(
                title=f"长连接检测 (源: {src_ip})",
                description=(
                    f"源 IP {src_ip} 存在 {len(long_connections)} 个长连接，"
                    f"持续时间超过 {CONNECTION_THRESHOLDS.long_connection_threshold} 秒"
                ),
                detection_type="anomaly",
                severity="medium",
                confidence=CONNECTION_THRESHOLDS.base_confidence,
                evidence={
                    "src_ip": src_ip,
                    "long_connections": long_connections[:10],
                    "threshold_sec": CONNECTION_THRESHOLDS.long_connection_threshold,
                },
                related_event_ids=event_ids[:50],
                tags=["connection", "long_connection"],
            ))

        # Beacon-like 行为
        if beacon_pairs:
            results.append(self._make_detection(
                title=f"疑似 Beacon 通信 (源: {src_ip})",
                description=(
                    f"源 IP {src_ip} 存在 {len(beacon_pairs)} 组周期性连接，"
                    f"间隔规律性高，疑似 C2 Beacon 通信"
                ),
                detection_type="suspicious_behavior",
                severity="high",
                confidence=min(
                    CONNECTION_THRESHOLDS.base_confidence + 0.2,
                    CONNECTION_THRESHOLDS.max_confidence,
                ),
                evidence={
                    "src_ip": src_ip,
                    "beacon_connections": beacon_pairs[:10],
                },
                related_event_ids=event_ids[:50],
                tags=["connection", "beacon", "c2"],
                attack_technique_id="T1071.001",
            ))

        # 高频连接
        if (
            max_rate > CONNECTION_THRESHOLDS.high_connection_rate_per_min
            and total_connections >= CONNECTION_THRESHOLDS.min_connections_for_rate_check
            and not port_scan_detected
            and not mass_connection_detected
        ):
            results.append(self._make_detection(
                title=f"高频连接行为 (源: {src_ip})",
                description=(
                    f"源 IP {src_ip} 连接速率 {max_rate:.0f}/min，"
                    f"超过阈值 {CONNECTION_THRESHOLDS.high_connection_rate_per_min}/min"
                ),
                detection_type="anomaly",
                severity="low",
                confidence=CONNECTION_THRESHOLDS.base_confidence,
                evidence={
                    "src_ip": src_ip,
                    "max_connection_rate_per_min": round(max_rate, 1),
                    "total_connections": total_connections,
                },
                related_event_ids=event_ids[:50],
                tags=["connection", "high_frequency"],
            ))

        return results
