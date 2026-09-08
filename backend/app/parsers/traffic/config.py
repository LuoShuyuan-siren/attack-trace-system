"""网络流量分析集中配置 —— 所有检测阈值集中管理，不散落在代码中。"""

from dataclasses import dataclass


@dataclass(frozen=True)
class DNSThresholds:
    """DNS 检测阈值配置。"""

    # 域名长度
    max_normal_domain_length: int = 50
    max_normal_subdomain_length: int = 30

    # 子域熵值（Shannon entropy）
    high_entropy_threshold: float = 3.5

    # 高频查询
    high_query_rate_per_min: int = 30
    min_queries_for_rate_check: int = 10

    # 唯一子域数量
    max_normal_unique_subdomains: int = 20

    # TXT 查询异常
    max_normal_txt_ratio: float = 0.1

    # NXDOMAIN 比例
    high_nxdomain_ratio: float = 0.5
    min_queries_for_nxdomain_check: int = 5

    # 置信度基线
    base_confidence: float = 0.6
    confidence_increment: float = 0.1
    max_confidence: float = 0.95


@dataclass(frozen=True)
class HTTPThresholds:
    """HTTP 检测阈值配置。"""

    # URI 长度
    max_normal_uri_length: int = 500

    # URI 熵值
    high_uri_entropy_threshold: float = 4.0

    # 高频请求
    high_request_rate_per_min: int = 60
    min_requests_for_rate_check: int = 10

    # 可疑 User-Agent 关键词
    suspicious_user_agents: tuple[str, ...] = (
        "curl",
        "python-requests",
        "wget",
        "nikto",
        "sqlmap",
        "nmap",
        "metasploit",
        "powershell",
    )

    # 大数据上传（bytes）
    large_upload_threshold: int = 10 * 1024 * 1024  # 10MB

    # 异常 POST 频率
    high_post_ratio: float = 0.8
    min_requests_for_post_check: int = 10

    # Beacon-like 检测
    beacon_min_intervals: int = 5
    beacon_max_jitter_ratio: float = 0.3  # 间隔变异系数

    # 置信度
    base_confidence: float = 0.5
    confidence_increment: float = 0.1
    max_confidence: float = 0.95


@dataclass(frozen=True)
class ICMPThresholds:
    """ICMP 检测阈值配置。"""

    # 高频 ICMP
    high_frequency_per_min: int = 20
    min_packets_for_frequency_check: int = 10

    # payload 异常大
    large_payload_threshold: int = 64  # 正常 ping payload 通常 ≤ 64 bytes

    # payload 长度异常稳定（标准差）
    stable_payload_max_std: float = 5.0
    min_packets_for_stability_check: int = 5

    # payload 高熵
    high_entropy_threshold: float = 3.5

    # 周期性检测
    periodic_min_intervals: int = 5
    periodic_max_jitter_ratio: float = 0.3

    # 双向通信检测
    bidirectional_min_packets: int = 10

    # 置信度
    base_confidence: float = 0.5
    confidence_increment: float = 0.1
    max_confidence: float = 0.9


@dataclass(frozen=True)
class ConnectionThresholds:
    """网络连接 / 异常连接检测阈值配置。"""

    # 短时间大量连接
    high_connection_rate_per_min: int = 50
    min_connections_for_rate_check: int = 20

    # 同一源访问大量端口
    port_scan_threshold: int = 20  # 同一源在短时间内访问的不同端口数

    # 同一源访问大量目标
    mass_connection_threshold: int = 30  # 同一源在短时间内访问的不同目标 IP 数

    # 非常用端口
    uncommon_ports: frozenset[int] = frozenset({
        22, 23, 25, 53, 80, 110, 143, 443, 445,
        993, 995, 1433, 1521, 3306, 3389, 5432,
        5900, 6379, 8080, 8443, 9200, 27017,
    })

    # 长连接（秒）
    long_connection_threshold: int = 3600  # 1 hour

    # 周期性连接
    periodic_min_intervals: int = 5
    periodic_max_jitter_ratio: float = 0.3

    # Beacon-like
    beacon_min_intervals: int = 5
    beacon_max_jitter_ratio: float = 0.3

    # 置信度
    base_confidence: float = 0.5
    confidence_increment: float = 0.1
    max_confidence: float = 0.95


# 全局单例
DNS_THRESHOLDS = DNSThresholds()
HTTP_THRESHOLDS = HTTPThresholds()
ICMP_THRESHOLDS = ICMPThresholds()
CONNECTION_THRESHOLDS = ConnectionThresholds()
