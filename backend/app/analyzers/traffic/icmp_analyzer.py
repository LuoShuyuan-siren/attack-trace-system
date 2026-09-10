"""ICMP 流量分析器。

检测能力：
- 高频 ICMP
- payload 异常大
- payload 长度异常稳定
- payload 高熵
- 周期性 ICMP
- ICMP 隧道综合判定
- 双向 ICMP 通信
"""

import math
from collections import defaultdict
from datetime import datetime

from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent
from app.parsers.traffic.config import ICMP_THRESHOLDS
from app.parsers.traffic.utils import (
    detect_periodicity,
    rate_per_minute,
    safe_int,
    shannon_entropy,
)
from app.analyzers.traffic.base import TrafficAnalyzerBase


class IcmpAnalyzer(TrafficAnalyzerBase):
    """ICMP 网络行为分析器。

    消费 NormalizedEvent 中的 ICMP 包事件，
    输出 DetectionResult。
    """

    @property
    def name(self) -> str:
        return "icmp_analyzer"

    def analyze(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        """分析 ICMP 事件，输出检测结果。"""
        traffic_events = self._filter_traffic_events(events)
        icmp_events = [
            e for e in traffic_events
            if e.event_type == "icmp_packet"
        ]

        if not icmp_events:
            return []

        results: list[DetectionResult] = []

        # 按源/目标 IP 对分组
        by_pair: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in icmp_events:
            pair_key = self._pair_key(e)
            by_pair[pair_key].append(e)

        for pair_key, pair_events in by_pair.items():
            results.extend(self._analyze_pair(pair_key, pair_events))

        return results

    def _pair_key(self, event: NormalizedEvent) -> str:
        """生成 IP 对分组键（双向归一化）。"""
        net = event.network
        if net is None or not net.src_ip or not net.dst_ip:
            return "unknown"
        # 归一化：小的 IP 在前
        ip_pair = tuple(sorted([net.src_ip, net.dst_ip]))
        return f"{ip_pair[0]}-{ip_pair[1]}"

    def _analyze_pair(
        self,
        pair_key: str,
        events: list[NormalizedEvent],
    ) -> list[DetectionResult]:
        """分析一组 ICMP 通信。"""
        results: list[DetectionResult] = []

        payloads: list[int] = []  # payload 长度
        payload_bytes: list[bytes] = []
        timestamps: list[datetime] = []
        event_ids: list[str] = []
        icmp_types: list[int] = []
        icmp_codes: list[int] = []

        src_ips: set[str] = set()
        dst_ips: set[str] = set()

        for e in events:
            raw = e.raw_data or {}
            payload_len = safe_int(raw.get("payload_length"))
            payloads.append(payload_len)

            # 从 hex payload 提取实际字节
            hex_payload = raw.get("payload_hex")
            if hex_payload:
                try:
                    payload_bytes.append(bytes.fromhex(hex_payload))
                except (ValueError, TypeError):
                    pass

            timestamps.append(e.timestamp)
            event_ids.append(e.event_id)
            icmp_types.append(safe_int(raw.get("icmp_type")))
            icmp_codes.append(safe_int(raw.get("icmp_code")))

            if e.network:
                if e.network.src_ip:
                    src_ips.add(e.network.src_ip)
                if e.network.dst_ip:
                    dst_ips.add(e.network.dst_ip)

        total_packets = len(events)
        if total_packets == 0:
            return []

        # 统计指标
        indicators: dict[str, object] = {
            "total_packets": total_packets,
        }

        # 1. 高频 ICMP
        max_rate = rate_per_minute(timestamps) if timestamps else 0.0
        indicators["max_frequency_per_min"] = round(max_rate, 1)

        # 2. payload 异常大
        max_payload = max(payloads) if payloads else 0
        avg_payload = sum(payloads) / len(payloads) if payloads else 0.0
        indicators["max_payload_size"] = max_payload
        indicators["avg_payload_size"] = round(avg_payload, 1)
        large_payloads = [p for p in payloads if p > ICMP_THRESHOLDS.large_payload_threshold]

        # 3. payload 长度稳定性
        payload_std = 0.0
        if len(payloads) >= ICMP_THRESHOLDS.min_packets_for_stability_check:
            mean_pl = avg_payload
            variance = sum((p - mean_pl) ** 2 for p in payloads) / len(payloads)
            payload_std = math.sqrt(variance)
        indicators["payload_size_std"] = round(payload_std, 2)

        # 4. payload 高熵
        max_entropy = 0.0
        if payload_bytes:
            entropies = [shannon_entropy(b) for b in payload_bytes if b]
            if entropies:
                max_entropy = max(entropies)
        indicators["max_payload_entropy"] = round(max_entropy, 2)

        # 5. 周期性检测
        periodic_score = 0
        periodic_interval = 0.0
        is_periodic, avg_interval, jitter = detect_periodicity(
            timestamps,
            min_intervals=ICMP_THRESHOLDS.periodic_min_intervals,
            max_jitter_ratio=ICMP_THRESHOLDS.periodic_max_jitter_ratio,
        )
        if is_periodic:
            periodic_score = 1
            periodic_interval = avg_interval
            indicators["periodic_jitter_ratio"] = round(jitter, 3)
            indicators["periodic_interval_sec"] = round(periodic_interval, 1)

        # 6. 双向通信
        is_bidirectional = len(src_ips) > 1 and len(dst_ips) > 1
        indicators["is_bidirectional"] = is_bidirectional

        # --- 检测逻辑 ---

        # ICMP 隧道综合检测
        tunnel_score = 0
        tunnel_reasons: list[str] = []

        if (
            max_rate > ICMP_THRESHOLDS.high_frequency_per_min
            and total_packets >= ICMP_THRESHOLDS.min_packets_for_frequency_check
        ):
            tunnel_score += 1
            tunnel_reasons.append(
                f"高频 ICMP ({max_rate:.0f}/min > {ICMP_THRESHOLDS.high_frequency_per_min}/min)"
            )

        if large_payloads:
            tunnel_score += 2
            tunnel_reasons.append(
                f"payload 异常大 (max={max_payload} > {ICMP_THRESHOLDS.large_payload_threshold})"
            )

        if (
            payload_std < ICMP_THRESHOLDS.stable_payload_max_std
            and len(payloads) >= ICMP_THRESHOLDS.min_packets_for_stability_check
            and avg_payload > 0
        ):
            tunnel_score += 1
            tunnel_reasons.append(
                f"payload 长度异常稳定 (std={payload_std:.2f} < {ICMP_THRESHOLDS.stable_payload_max_std})"
            )

        if max_entropy > ICMP_THRESHOLDS.high_entropy_threshold:
            tunnel_score += 2
            tunnel_reasons.append(
                f"payload 高熵 (entropy={max_entropy:.2f} > {ICMP_THRESHOLDS.high_entropy_threshold})"
            )

        if periodic_score:
            tunnel_score += 1
            tunnel_reasons.append(
                f"周期性 ICMP (interval={periodic_interval:.1f}s, 低抖动)"
            )

        if is_bidirectional and total_packets >= ICMP_THRESHOLDS.bidirectional_min_packets:
            tunnel_score += 1
            tunnel_reasons.append(
                f"双向 ICMP 通信 ({total_packets} 包)"
            )

        if tunnel_score >= 3:
            confidence = min(
                ICMP_THRESHOLDS.base_confidence + tunnel_score * ICMP_THRESHOLDS.confidence_increment,
                ICMP_THRESHOLDS.max_confidence,
            )
            severity = "high" if tunnel_score >= 5 else "medium"

            src_ip = list(src_ips)[0] if src_ips else "unknown"
            dst_ip = list(dst_ips)[0] if dst_ips else "unknown"

            results.append(self._make_detection(
                title=f"疑似 ICMP 隧道通信 ({src_ip} <-> {dst_ip})",
                description=(
                    f"ICMP 通信触发 {tunnel_score} 项隧道特征: "
                    + "; ".join(tunnel_reasons)
                ),
                detection_type="suspicious_behavior",
                severity=severity,
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "indicators": indicators,
                    "triggered_rules": tunnel_reasons,
                    "score": tunnel_score,
                },
                related_event_ids=event_ids[:50],
                tags=["icmp", "icmp_tunnel", "covert_channel"],
                attack_technique_id="T1571.004",  # ICMP Tunneling
            ))

        # 单独高频检测（非隧道）
        if tunnel_score < 3 and max_rate > ICMP_THRESHOLDS.high_frequency_per_min:
            src_ip = list(src_ips)[0] if src_ips else "unknown"
            results.append(self._make_detection(
                title=f"高频 ICMP 通信 (源: {src_ip})",
                description=(
                    f"ICMP 通信速率 {max_rate:.0f}/min，"
                    f"超过阈值 {ICMP_THRESHOLDS.high_frequency_per_min}/min"
                ),
                detection_type="anomaly",
                severity="low",
                confidence=ICMP_THRESHOLDS.base_confidence,
                evidence={
                    "src_ip": src_ip,
                    "max_frequency_per_min": round(max_rate, 1),
                    "total_packets": total_packets,
                    "threshold": ICMP_THRESHOLDS.high_frequency_per_min,
                },
                related_event_ids=event_ids[:50],
                tags=["icmp", "high_frequency"],
            ))

        return results
