"""DNS 流量分析器。

检测能力：
- 高频 DNS 查询
- 异常长域名
- 子域随机性 / 高熵
- 大量唯一子域
- TXT 查询异常
- NXDOMAIN 比例
- DNS 隧道综合判定

采用多指标组合 + 统计特征 + 可解释 evidence + confidence。
"""

from collections import defaultdict
from datetime import datetime

from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent
from app.parsers.traffic.config import DNS_THRESHOLDS
from app.parsers.traffic.utils import (
    extract_subdomain,
    rate_per_minute,
    safe_str,
    shannon_entropy,
)
from app.analyzers.traffic.base import TrafficAnalyzerBase


class DnsAnalyzer(TrafficAnalyzerBase):
    """DNS 网络行为分析器。

    消费 NormalizedEvent 中的 DNS 查询事件，
    输出 DetectionResult。
    """

    @property
    def name(self) -> str:
        return "dns_analyzer"

    def analyze(self, events: list[NormalizedEvent]) -> list[DetectionResult]:
        """分析 DNS 事件，输出检测结果。"""
        traffic_events = self._filter_traffic_events(events)
        dns_events = [
            e for e in traffic_events
            if e.event_type == "dns_query"
            and self._extract_dns_info(e) is not None
        ]

        if not dns_events:
            return []

        results: list[DetectionResult] = []

        # 按源 IP 分组
        by_src: dict[str, list[NormalizedEvent]] = defaultdict(list)
        for e in dns_events:
            src_ip = e.network.src_ip if e.network else "unknown"
            by_src[src_ip].append(e)

        for src_ip, src_events in by_src.items():
            results.extend(self._analyze_per_source(src_ip, src_events))

        return results

    def _analyze_per_source(
        self,
        src_ip: str,
        events: list[NormalizedEvent],
    ) -> list[DetectionResult]:
        """分析单个源 IP 的 DNS 查询。"""
        results: list[DetectionResult] = []

        # 收集统计指标
        domains: list[str] = []
        subdomains: list[str] = []
        query_types: list[str] = []
        nxdomains: int = 0
        timestamps: list[datetime] = []
        event_ids: list[str] = []

        for e in events:
            dns = self._extract_dns_info(e)
            if not dns:
                continue

            query = safe_str(dns.get("query") or dns.get("query_name"))
            qtype = safe_str(dns.get("query_type"))
            rcode = safe_str(dns.get("rcode") or dns.get("rcode_name") or dns.get("rcode_num"))

            domains.append(query)
            sub = extract_subdomain(query)
            if sub:
                subdomains.append(sub)
            query_types.append(qtype)
            timestamps.append(e.timestamp)
            event_ids.append(e.event_id)

            # NXDOMAIN 检测
            rcode_lower = rcode.lower()
            if "nxdomain" in rcode_lower or rcode == "3":
                nxdomains += 1

        total_queries = len(domains)
        if total_queries == 0:
            return []

        unique_subdomains = set(subdomains)

        # 指标计算
        indicators: dict[str, object] = {}

        # 1. 高频查询
        max_rate = rate_per_minute(timestamps) if timestamps else 0.0
        indicators["max_query_rate_per_min"] = round(max_rate, 1)

        # 2. 异常长域名
        max_domain_len = max(len(d) for d in domains) if domains else 0
        indicators["max_domain_length"] = max_domain_len
        long_domains = [d for d in domains if len(d) > DNS_THRESHOLDS.max_normal_domain_length]

        # 3. 子域熵值
        max_subdomain_len = max(len(s) for s in subdomains) if subdomains else 0
        indicators["max_subdomain_length"] = max_subdomain_len
        avg_entropy = 0.0
        if subdomains:
            entropies = [shannon_entropy(s) for s in subdomains]
            avg_entropy = sum(entropies) / len(entropies)
            max_entropy = max(entropies)
            indicators["max_subdomain_entropy"] = round(max_entropy, 2)
        indicators["avg_subdomain_entropy"] = round(avg_entropy, 2)

        # 4. 唯一子域数量
        indicators["unique_subdomains"] = len(unique_subdomains)

        # 5. TXT 查询比例
        txt_count = sum(1 for q in query_types if q.upper() == "TXT")
        txt_ratio = txt_count / total_queries if total_queries else 0.0
        indicators["txt_query_ratio"] = round(txt_ratio, 2)

        # 6. NXDOMAIN 比例
        nxdomain_ratio = nxdomains / total_queries if total_queries else 0.0
        indicators["nxdomain_ratio"] = round(nxdomain_ratio, 2)
        indicators["total_queries"] = total_queries

        # --- 检测逻辑 ---

        # 检测 DNS 隧道
        tunnel_score = 0
        tunnel_reasons: list[str] = []

        if total_queries >= DNS_THRESHOLDS.min_queries_for_rate_check:
            if max_rate > DNS_THRESHOLDS.high_query_rate_per_min:
                tunnel_score += 2
                tunnel_reasons.append(
                    f"高频查询 ({max_rate:.0f}/min > {DNS_THRESHOLDS.high_query_rate_per_min}/min)"
                )

        if long_domains:
            tunnel_score += 1
            tunnel_reasons.append(
                f"异常长域名 (max={max_domain_len} > {DNS_THRESHOLDS.max_normal_domain_length})"
            )

        if avg_entropy > DNS_THRESHOLDS.high_entropy_threshold:
            tunnel_score += 2
            tunnel_reasons.append(
                f"子域高熵 (avg={avg_entropy:.2f} > {DNS_THRESHOLDS.high_entropy_threshold})"
            )

        if len(unique_subdomains) > DNS_THRESHOLDS.max_normal_unique_subdomains:
            tunnel_score += 1
            tunnel_reasons.append(
                f"大量唯一子域 ({len(unique_subdomains)} > {DNS_THRESHOLDS.max_normal_unique_subdomains})"
            )

        if txt_ratio > DNS_THRESHOLDS.max_normal_txt_ratio and total_queries >= 5:
            tunnel_score += 1
            tunnel_reasons.append(
                f"TXT 查询异常 (ratio={txt_ratio:.2f} > {DNS_THRESHOLDS.max_normal_txt_ratio})"
            )

        if (
            nxdomain_ratio > DNS_THRESHOLDS.high_nxdomain_ratio
            and total_queries >= DNS_THRESHOLDS.min_queries_for_nxdomain_check
        ):
            tunnel_score += 1
            tunnel_reasons.append(
                f"高 NXDOMAIN 比例 (ratio={nxdomain_ratio:.2f} > {DNS_THRESHOLDS.high_nxdomain_ratio})"
            )

        if tunnel_score >= 3:
            confidence = min(
                DNS_THRESHOLDS.base_confidence + tunnel_score * DNS_THRESHOLDS.confidence_increment,
                DNS_THRESHOLDS.max_confidence,
            )
            severity = "high" if tunnel_score >= 5 else "medium"

            results.append(self._make_detection(
                title=f"疑似 DNS 隧道通信 (源: {src_ip})",
                description=(
                    f"源 IP {src_ip} 的 DNS 查询触发 {tunnel_score} 项隧道特征: "
                    + "; ".join(tunnel_reasons)
                ),
                detection_type="suspicious_behavior",
                severity=severity,
                confidence=confidence,
                evidence={
                    "src_ip": src_ip,
                    "indicators": indicators,
                    "triggered_rules": tunnel_reasons,
                    "score": tunnel_score,
                },
                related_event_ids=event_ids[:50],
                tags=["dns", "dns_tunnel", "covert_channel"],
                attack_technique_id="T1071.004",  # DNS 隧道是明确的技术，可标注
            ))

        # 检测异常高频 DNS 查询（非隧道特征）
        if tunnel_score < 3 and max_rate > DNS_THRESHOLDS.high_query_rate_per_min:
            results.append(self._make_detection(
                title=f"高频 DNS 查询 (源: {src_ip})",
                description=(
                    f"源 IP {src_ip} DNS 查询速率 {max_rate:.0f}/min，"
                    f"超过阈值 {DNS_THRESHOLDS.high_query_rate_per_min}/min"
                ),
                detection_type="anomaly",
                severity="low",
                confidence=min(
                    DNS_THRESHOLDS.base_confidence,
                    DNS_THRESHOLDS.max_confidence,
                ),
                evidence={
                    "src_ip": src_ip,
                    "max_query_rate_per_min": round(max_rate, 1),
                    "total_queries": total_queries,
                    "threshold": DNS_THRESHOLDS.high_query_rate_per_min,
                },
                related_event_ids=event_ids[:50],
                tags=["dns", "high_frequency"],
            ))

        return results
