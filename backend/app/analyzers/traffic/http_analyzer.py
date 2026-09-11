"""HTTP 流量分析器。

检测能力：
- 异常长 URI
- 高频周期请求（Beacon-like）
- 可疑 User-Agent
- 大量数据上传
- 异常 POST 频率
- 编码 / 高熵参数
- HTTP 隐蔽信道综合判定
"""

from collections import defaultdict
from datetime import datetime

from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent
from app.parsers.traffic.config import HTTP_THRESHOLDS
from app.parsers.traffic.utils import (
    detect_periodicity,
    rate_per_minute,
    safe_int,
    safe_str,
    shannon_entropy,
)
from app.analyzers.traffic.base import TrafficAnalyzerBase


class HttpAnalyzer(TrafficAnalyzerBase):
    """HTTP 网络行为分析器。

    消费 NormalizedEvent 中的 HTTP 通信事件，
    输出 DetectionResult。
    """

    @property
    def name(self) -> str:
        return "http_analyzer"

    def analyze(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        """分析 HTTP 事件，输出检测结果。"""
        traffic_events = self._filter_traffic_events(events)
        http_events = [
            e for e in traffic_events
            if e.event_type in ("http_request", "http_response", "http_communication")
            and self._extract_http_info(e) is not None
        ]

        if not http_events:
            return []

        results: list[DetectionResult] = []

        # 按 (src_ip, dst_ip, dst_port) 分组
        groups: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in http_events:
            key = self._group_key(e)
            groups[key].append(e)

        for key, group_events in groups.items():
            results.extend(self._analyze_group(key, group_events))

        return results

    def _group_key(self, event: NormalizedEvent) -> str:
        """生成分组键。"""
        net = event.network
        if net is None:
            return "unknown"
        return f"{net.src_ip}:{net.dst_ip}:{net.dst_port}"

    def _analyze_group(
        self,
        group_key: str,
        events: list[NormalizedEvent],
    ) -> list[DetectionResult]:
        """分析一个 HTTP 通信组。"""
        results: list[DetectionResult] = []

        uris: list[str] = []
        methods: list[str] = []
        user_agents: list[str] = []
        status_codes: list[int] = []
        timestamps: list[datetime] = []
        event_ids: list[str] = []
        content_lengths: list[int] = []

        for e in events:
            http = self._extract_http_info(e)
            if not http:
                continue

            uris.append(safe_str(http.get("uri") or http.get("url") or http.get("path")))
            methods.append(safe_str(http.get("method")))
            ua = safe_str(http.get("user_agent"))
            if ua:
                user_agents.append(ua)
            status = safe_int(http.get("status_code"))
            if status:
                status_codes.append(status)
            cl = safe_int(http.get("content_length") or http.get("request_body_len"))
            if cl:
                content_lengths.append(cl)
            timestamps.append(e.timestamp)
            event_ids.append(e.event_id)

        total_requests = len(events)
        if total_requests == 0:
            return []

        indicators: dict[str, object] = {
            "total_requests": total_requests,
        }

        # 1. 异常长 URI
        max_uri_len = max(len(u) for u in uris if u) if uris else 0
        indicators["max_uri_length"] = max_uri_len
        long_uris = [u for u in uris if len(u) > HTTP_THRESHOLDS.max_normal_uri_length]

        # 2. URI 熵
        max_uri_entropy = 0.0
        if uris:
            entropies = [shannon_entropy(u) for u in uris if u]
            if entropies:
                max_uri_entropy = max(entropies)
        indicators["max_uri_entropy"] = round(max_uri_entropy, 2)

        # 3. 高频请求
        max_rate = rate_per_minute(timestamps) if timestamps else 0.0
        indicators["max_request_rate_per_min"] = round(max_rate, 1)

        # 4. 可疑 User-Agent
        suspicious_uas: list[str] = []
        for ua in user_agents:
            ua_lower = ua.lower()
            for keyword in HTTP_THRESHOLDS.suspicious_user_agents:
                if keyword in ua_lower:
                    suspicious_uas.append(ua)
                    break
        indicators["suspicious_user_agents"] = len(suspicious_uas)

        # 5. 大数据上传
        large_uploads = [cl for cl in content_lengths if cl > HTTP_THRESHOLDS.large_upload_threshold]
        indicators["large_uploads"] = len(large_uploads)

        # 6. 异常 POST 频率
        post_count = sum(1 for m in methods if m.upper() == "POST")
        post_ratio = post_count / total_requests if total_requests else 0.0
        indicators["post_ratio"] = round(post_ratio, 2)

        # 7. Beacon-like 检测（周期性请求）
        beacon_score = 0
        beacon_interval = 0.0
        is_periodic, avg_interval, jitter = detect_periodicity(
            timestamps,
            min_intervals=HTTP_THRESHOLDS.beacon_min_intervals,
            max_jitter_ratio=HTTP_THRESHOLDS.beacon_max_jitter_ratio,
        )
        if is_periodic:
            beacon_score = 1
            beacon_interval = avg_interval
            indicators["beacon_jitter_ratio"] = round(jitter, 3)
            indicators["beacon_interval_sec"] = round(beacon_interval, 1)

        # --- 检测逻辑 ---

        # HTTP 隐蔽信道综合检测
        covert_score = 0
        covert_reasons: list[str] = []

        if long_uris:
            covert_score += 1
            covert_reasons.append(
                f"异常长 URI (max={max_uri_len} > {HTTP_THRESHOLDS.max_normal_uri_length})"
            )

        if max_uri_entropy > HTTP_THRESHOLDS.high_uri_entropy_threshold:
            covert_score += 1
            covert_reasons.append(
                f"URI 高熵 (entropy={max_uri_entropy:.2f} > {HTTP_THRESHOLDS.high_uri_entropy_threshold})"
            )

        if suspicious_uas:
            covert_score += 1
            covert_reasons.append(
                f"可疑 User-Agent ({suspicious_uas[0][:50]})"
            )

        if (
            post_ratio > HTTP_THRESHOLDS.high_post_ratio
            and total_requests >= HTTP_THRESHOLDS.min_requests_for_post_check
        ):
            covert_score += 1
            covert_reasons.append(
                f"异常 POST 频率 (ratio={post_ratio:.2f} > {HTTP_THRESHOLDS.high_post_ratio})"
            )

        if beacon_score:
            covert_score += 2
            covert_reasons.append(
                f"Beacon-like 通信 (interval={beacon_interval:.1f}s, 低抖动)"
            )

        if large_uploads:
            covert_score += 1
            covert_reasons.append(
                f"大数据上传 ({len(large_uploads)} 次 > {HTTP_THRESHOLDS.large_upload_threshold} bytes)"
            )

        if covert_score >= 3:
            confidence = min(
                HTTP_THRESHOLDS.base_confidence + covert_score * HTTP_THRESHOLDS.confidence_increment,
                HTTP_THRESHOLDS.max_confidence,
            )
            severity = "high" if covert_score >= 5 else "medium"

            src_ip = events[0].network.src_ip if events[0].network else "unknown"
            dst_ip = events[0].network.dst_ip if events[0].network else "unknown"

            results.append(self._make_detection(
                title=f"疑似 HTTP 隐蔽信道通信 (源: {src_ip} -> 目标: {dst_ip})",
                description=(
                    f"HTTP 通信触发 {covert_score} 项隐蔽信道特征: "
                    + "; ".join(covert_reasons)
                ),
                detection_type="suspicious_behavior",
                severity=severity,
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "indicators": indicators,
                    "triggered_rules": covert_reasons,
                    "score": covert_score,
                },
                related_event_ids=event_ids[:50],
                tags=["http", "covert_channel", "http_tunnel"],
                attack_technique_id="T1071.001",  # HTTP 隧道是明确技术
            ))

        # 单独 Beacon-like 检测
        if beacon_score and covert_score < 3:
            src_ip = events[0].network.src_ip if events[0].network else "unknown"
            dst_ip = events[0].network.dst_ip if events[0].network else "unknown"
            results.append(self._make_detection(
                title=f"疑似 HTTP Beacon 行为 (源: {src_ip} -> 目标: {dst_ip})",
                description=(
                    f"HTTP 通信呈现周期性特征，间隔 {beacon_interval:.1f}s，"
                    f"低抖动，疑似 C2 Beacon 通信"
                ),
                detection_type="suspicious_behavior",
                severity="medium",
                confidence=min(
                    HTTP_THRESHOLDS.base_confidence + 0.1,
                    HTTP_THRESHOLDS.max_confidence,
                ),
                evidence=indicators,
                related_event_ids=event_ids[:50],
                tags=["http", "beacon", "c2"],
                attack_technique_id="T1071.001",
            ))

        # 异常高频请求（非隐蔽信道）
        if covert_score < 3 and max_rate > HTTP_THRESHOLDS.high_request_rate_per_min:
            src_ip = events[0].network.src_ip if events[0].network else "unknown"
            results.append(self._make_detection(
                title=f"高频 HTTP 请求 (源: {src_ip})",
                description=(
                    f"HTTP 请求速率 {max_rate:.0f}/min，"
                    f"超过阈值 {HTTP_THRESHOLDS.high_request_rate_per_min}/min"
                ),
                detection_type="anomaly",
                severity="low",
                confidence=HTTP_THRESHOLDS.base_confidence,
                evidence={
                    "src_ip": src_ip,
                    "max_request_rate_per_min": round(max_rate, 1),
                    "total_requests": total_requests,
                    "threshold": HTTP_THRESHOLDS.high_request_rate_per_min,
                },
                related_event_ids=event_ids[:50],
                tags=["http", "high_frequency"],
            ))

        return results
