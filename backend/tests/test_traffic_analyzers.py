"""网络流量 Analyzer 测试。

覆盖：
- 正常 DNS（无告警）
- 可疑 DNS Tunnel
- 正常 HTTP（无告警）
- 可疑 HTTP 行为
- 正常 ICMP（无告警）
- 可疑 ICMP Tunnel
- 异常连接
- 边界输入
- 空输入
- 损坏/缺字段输入
"""

import random
import string
from datetime import datetime, timezone, timedelta
from pathlib import Path

from app.schemas.event import NetworkInfo, NormalizedEvent
from app.analyzers.traffic.dns_analyzer import DnsAnalyzer
from app.analyzers.traffic.http_analyzer import HttpAnalyzer
from app.analyzers.traffic.icmp_analyzer import IcmpAnalyzer
from app.analyzers.traffic.connection_analyzer import ConnectionAnalyzer

from tests.fixtures.suricata_generator import create_eve_json, create_dns_tunnel_eve
from app.parsers.traffic.zeek_parser import ZeekParser
from app.parsers.traffic.suricata_parser import SuricataParser


def _make_dns_event(
    src_ip: str,
    dst_ip: str,
    query: str,
    qtype: str = "A",
    rcode: str = "NOERROR",
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    """构造一个 DNS NormalizedEvent。"""
    return NormalizedEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        source_type="network_traffic",
        source="test",
        event_type="dns_query",
        network=NetworkInfo(
            src_ip=src_ip,
            src_port=54321,
            dst_ip=dst_ip,
            dst_port=53,
            protocol="UDP",
        ),
        action="dns_query",
        raw_data={
            "dns": {
                "query": query,
                "query_type": qtype,
                "rcode": rcode,
            }
        },
        tags=["dns"],
    )


def _make_http_event(
    src_ip: str,
    dst_ip: str,
    method: str = "GET",
    uri: str = "/",
    host: str = "example.com",
    user_agent: str = "Mozilla/5.0",
    status_code: int = 200,
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    """构造一个 HTTP NormalizedEvent。"""
    return NormalizedEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        source_type="network_traffic",
        source="test",
        event_type="http_request",
        network=NetworkInfo(
            src_ip=src_ip,
            src_port=12345,
            dst_ip=dst_ip,
            dst_port=80,
            protocol="TCP",
        ),
        action="http_communication",
        raw_data={
            "http": {
                "method": method,
                "host": host,
                "uri": uri,
                "user_agent": user_agent,
                "status_code": status_code,
            }
        },
        tags=["http"],
    )


def _make_icmp_event(
    src_ip: str,
    dst_ip: str,
    payload_length: int = 32,
    payload_hex: str = "",
    icmp_type: int = 8,
    icmp_code: int = 0,
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    """构造一个 ICMP NormalizedEvent。"""
    if not payload_hex:
        payload_hex = "ab" * payload_length
    return NormalizedEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        source_type="network_traffic",
        source="test",
        event_type="icmp_packet",
        network=NetworkInfo(
            src_ip=src_ip,
            dst_ip=dst_ip,
            protocol="ICMP",
        ),
        action="icmp_packet",
        raw_data={
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "payload_length": payload_length,
            "payload_hex": payload_hex[:200],
        },
        tags=["icmp"],
    )


def _make_conn_event(
    src_ip: str,
    dst_ip: str,
    dst_port: int = 80,
    protocol: str = "TCP",
    timestamp: datetime | None = None,
) -> NormalizedEvent:
    """构造一个网络连接 NormalizedEvent。"""
    return NormalizedEvent(
        timestamp=timestamp or datetime.now(timezone.utc),
        source_type="network_traffic",
        source="test",
        event_type="network_connection",
        network=NetworkInfo(
            src_ip=src_ip,
            src_port=12345,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
        ),
        action="connection_established",
        tags=["conn"],
    )


# ==================== DNS Analyzer 测试 ====================


class TestDnsAnalyzer:
    """DNS 分析器测试。"""

    def test_name(self) -> None:
        assert DnsAnalyzer().name == "dns_analyzer"

    def test_normal_dns_no_alert(self) -> None:
        """正常 DNS 查询不应触发告警。"""
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_dns_event("192.168.1.1", "8.8.8.8", "example.com", timestamp=base_time),
            _make_dns_event("192.168.1.1", "8.8.8.8", "google.com", timestamp=base_time + timedelta(seconds=30)),
            _make_dns_event("192.168.1.1", "8.8.8.8", "github.com", timestamp=base_time + timedelta(seconds=60)),
        ]
        results = DnsAnalyzer().analyze(events)
        assert len(results) == 0

    def test_dns_tunnel_detection(self) -> None:
        """可疑 DNS 隧道检测。"""
        # 生成高频、高熵、长子域的 DNS 查询
        events = []
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(40):
            random.seed(i)
            subdomain = "".join(random.choices(string.ascii_lowercase + string.digits, k=50))
            events.append(
                _make_dns_event(
                    "192.168.1.100",
                    "8.8.8.8",
                    f"{subdomain}.evil-domain.com",
                    qtype="TXT",
                    timestamp=base_time + timedelta(seconds=i),
                )
            )

        results = DnsAnalyzer().analyze(events)
        assert len(results) > 0
        tunnel_result = [r for r in results if "dns_tunnel" in r.tags]
        assert len(tunnel_result) > 0
        assert tunnel_result[0].confidence > 0.5
        assert "indicators" in tunnel_result[0].evidence

    def test_high_nxdomain_ratio(self) -> None:
        """高 NXDOMAIN 比例检测。"""
        events = []
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(10):
            events.append(
                _make_dns_event(
                    "192.168.1.50",
                    "8.8.8.8",
                    f"nonexistent{i}.example.com",
                    rcode="NXDOMAIN",
                    timestamp=base_time + timedelta(seconds=i),
                )
            )

        results = DnsAnalyzer().analyze(events)
        # 应检测到某种异常
        assert len(results) > 0

    def test_empty_input(self) -> None:
        """空输入测试。"""
        results = DnsAnalyzer().analyze([])
        assert results == []

    def test_no_dns_events(self) -> None:
        """无 DNS 事件测试。"""
        events = [_make_http_event("192.168.1.1", "10.0.0.1")]
        results = DnsAnalyzer().analyze(events)
        assert results == []

    def test_missing_dns_info(self) -> None:
        """缺少 DNS 信息的 DNS 事件测试。"""
        event = NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="network_traffic",
            source="test",
            event_type="dns_query",
            action="dns_query",
            network=NetworkInfo(src_ip="192.168.1.1", dst_ip="8.8.8.8"),
            raw_data={},  # 没有 dns 字段
        )
        results = DnsAnalyzer().analyze([event])
        assert results == []


# ==================== HTTP Analyzer 测试 ====================


class TestHttpAnalyzer:
    """HTTP 分析器测试。"""

    def test_name(self) -> None:
        assert HttpAnalyzer().name == "http_analyzer"

    def test_normal_http_no_alert(self) -> None:
        """正常 HTTP 请求不应触发告警。"""
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_http_event("192.168.1.1", "10.0.0.1", method="GET", uri="/", timestamp=base_time),
            _make_http_event("192.168.1.1", "10.0.0.1", method="GET", uri="/about", timestamp=base_time + timedelta(seconds=30)),
            _make_http_event("192.168.1.1", "10.0.0.1", method="GET", uri="/contact", timestamp=base_time + timedelta(seconds=60)),
        ]
        results = HttpAnalyzer().analyze(events)
        assert len(results) == 0

    def test_suspicious_http_behavior(self) -> None:
        """可疑 HTTP 行为检测。"""
        # 异常长 URI + 可疑 UA + 大量 POST
        events = []
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        long_uri = "/api/upload/" + "A" * 600  # 超长 URI
        for i in range(20):
            events.append(
                _make_http_event(
                    "192.168.1.1",
                    "10.0.0.1",
                    method="POST",
                    uri=long_uri,
                    user_agent="python-requests/2.25.1",
                    timestamp=base_time + timedelta(seconds=i),
                )
            )

        results = HttpAnalyzer().analyze(events)
        assert len(results) > 0
        # 应检测到隐蔽信道或可疑行为
        suspicious = [r for r in results if r.detection_type == "suspicious_behavior"]
        assert len(suspicious) > 0

    def test_beacon_behavior(self) -> None:
        """Beacon-like 周期性请求检测。"""
        events = []
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(10):
            events.append(
                _make_http_event(
                    "192.168.1.1",
                    "10.0.0.1",
                    method="GET",
                    uri="/check",
                    user_agent="Mozilla/5.0",
                    timestamp=base_time + timedelta(seconds=i * 60),  # 精确 60 秒间隔
                )
            )

        results = HttpAnalyzer().analyze(events)
        # 应检测到 beacon 行为
        beacon_results = [r for r in results if "beacon" in r.tags]
        assert len(beacon_results) > 0

    def test_empty_input(self) -> None:
        """空输入测试。"""
        results = HttpAnalyzer().analyze([])
        assert results == []

    def test_no_http_events(self) -> None:
        """无 HTTP 事件测试。"""
        events = [_make_dns_event("192.168.1.1", "8.8.8.8", "example.com")]
        results = HttpAnalyzer().analyze(events)
        assert results == []

    def test_missing_http_info(self) -> None:
        """缺少 HTTP 信息的 HTTP 事件测试。"""
        event = NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="network_traffic",
            source="test",
            event_type="http_request",
            action="http_communication",
            network=NetworkInfo(src_ip="192.168.1.1", dst_ip="10.0.0.1"),
            raw_data={},  # 没有 http 字段
        )
        results = HttpAnalyzer().analyze([event])
        assert results == []


# ==================== ICMP Analyzer 测试 ====================


class TestIcmpAnalyzer:
    """ICMP 分析器测试。"""

    def test_name(self) -> None:
        assert IcmpAnalyzer().name == "icmp_analyzer"

    def test_normal_icmp_no_alert(self) -> None:
        """正常 ICMP 不应触发告警。"""
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_icmp_event("192.168.1.1", "10.0.0.2", payload_length=32, timestamp=base_time),
            _make_icmp_event("192.168.1.1", "10.0.0.2", payload_length=32, timestamp=base_time + timedelta(seconds=30)),
            _make_icmp_event("192.168.1.1", "10.0.0.2", payload_length=32, timestamp=base_time + timedelta(seconds=60)),
        ]
        results = IcmpAnalyzer().analyze(events)
        assert len(results) == 0

    def test_icmp_tunnel_detection(self) -> None:
        """ICMP 隧道检测。"""
        # 高频 + 大 payload + 高熵 payload
        events = []
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        random.seed(42)
        for i in range(30):
            # 生成高熵随机 payload (128 bytes)
            random_bytes = bytes(random.randint(0, 255) for _ in range(128))
            payload_hex = random_bytes.hex()
            events.append(
                _make_icmp_event(
                    "192.168.1.1",
                    "10.0.0.2",
                    payload_length=128,
                    payload_hex=payload_hex,
                    timestamp=base_time + timedelta(seconds=i),
                )
            )

        results = IcmpAnalyzer().analyze(events)
        assert len(results) > 0
        tunnel_results = [r for r in results if "icmp_tunnel" in r.tags]
        assert len(tunnel_results) > 0
        assert tunnel_results[0].confidence > 0.5

    def test_high_frequency_icmp(self) -> None:
        """高频 ICMP 检测。"""
        events = []
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(25):
            events.append(
                _make_icmp_event(
                    "192.168.1.1",
                    "10.0.0.2",
                    payload_length=32,
                    timestamp=base_time + timedelta(seconds=i * 2),
                )
            )

        results = IcmpAnalyzer().analyze(events)
        assert len(results) > 0

    def test_empty_input(self) -> None:
        """空输入测试。"""
        results = IcmpAnalyzer().analyze([])
        assert results == []

    def test_no_icmp_events(self) -> None:
        """无 ICMP 事件测试。"""
        events = [_make_dns_event("192.168.1.1", "8.8.8.8", "example.com")]
        results = IcmpAnalyzer().analyze(events)
        assert results == []

    def test_bidirectional_icmp(self) -> None:
        """双向 ICMP 通信检测。"""
        events = []
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        # 请求 + 回复
        for i in range(15):
            events.append(
                _make_icmp_event(
                    "192.168.1.1", "10.0.0.2",
                    payload_length=128,
                    icmp_type=8,
                    timestamp=base_time + timedelta(seconds=i),
                )
            )
            events.append(
                _make_icmp_event(
                    "10.0.0.2", "192.168.1.1",
                    payload_length=128,
                    icmp_type=0,
                    timestamp=base_time + timedelta(seconds=i, milliseconds=500),
                )
            )

        results = IcmpAnalyzer().analyze(events)
        assert len(results) > 0


# ==================== Connection Analyzer 测试 ====================


class TestConnectionAnalyzer:
    """网络连接分析器测试。"""

    def test_name(self) -> None:
        assert ConnectionAnalyzer().name == "connection_analyzer"

    def test_normal_connection_no_alert(self) -> None:
        """正常连接不应触发告警。"""
        events = [
            _make_conn_event("192.168.1.1", "10.0.0.1", dst_port=80),
            _make_conn_event("192.168.1.1", "10.0.0.1", dst_port=443),
            _make_conn_event("192.168.1.1", "10.0.0.2", dst_port=80),
        ]
        results = ConnectionAnalyzer().analyze(events)
        assert len(results) == 0

    def test_port_scan_detection(self) -> None:
        """端口扫描检测。"""
        events = []
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        for port in range(1, 30):
            events.append(
                _make_conn_event(
                    "192.168.1.100",
                    "10.0.0.1",
                    dst_port=port,
                    timestamp=base_time + timedelta(seconds=port),
                )
            )

        results = ConnectionAnalyzer().analyze(events)
        scan_results = [r for r in results if "port_scan" in r.tags]
        assert len(scan_results) > 0

    def test_mass_connection_detection(self) -> None:
        """大范围连接检测。"""
        events = []
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(40):
            events.append(
                _make_conn_event(
                    "192.168.1.100",
                    f"10.0.0.{i + 1}",
                    dst_port=80,
                    timestamp=base_time + timedelta(seconds=i),
                )
            )

        results = ConnectionAnalyzer().analyze(events)
        mass_results = [r for r in results if "mass_connection" in r.tags]
        assert len(mass_results) > 0

    def test_beacon_connection(self) -> None:
        """Beacon 连接检测。"""
        events = []
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        for i in range(10):
            events.append(
                _make_conn_event(
                    "192.168.1.1",
                    "10.0.0.1",
                    dst_port=443,
                    timestamp=base_time + timedelta(seconds=i * 60),
                )
            )

        results = ConnectionAnalyzer().analyze(events)
        beacon_results = [r for r in results if "beacon" in r.tags]
        assert len(beacon_results) > 0

    def test_long_connection(self) -> None:
        """长连接检测。"""
        base_time = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
        events = [
            _make_conn_event(
                "192.168.1.1", "10.0.0.1", dst_port=443,
                timestamp=base_time,
            ),
            _make_conn_event(
                "192.168.1.1", "10.0.0.1", dst_port=443,
                timestamp=base_time + timedelta(seconds=3700),  # > 1 hour
            ),
        ]

        results = ConnectionAnalyzer().analyze(events)
        long_results = [r for r in results if "long_connection" in r.tags]
        assert len(long_results) > 0

    def test_empty_input(self) -> None:
        """空输入测试。"""
        results = ConnectionAnalyzer().analyze([])
        assert results == []

    def test_no_network_events(self) -> None:
        """无网络事件测试。"""
        event = NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="host_log",
            source="test",
            event_type="process_create",
            action="create_process",
        )
        results = ConnectionAnalyzer().analyze([event])
        assert results == []


# ==================== 边界/集成测试 ====================


class TestEdgeCases:
    """边界和集成测试。"""

    def test_all_analyzers_empty_input(self) -> None:
        """所有分析器空输入测试。"""
        analyzers = [DnsAnalyzer(), HttpAnalyzer(), IcmpAnalyzer(), ConnectionAnalyzer()]
        for analyzer in analyzers:
            results = analyzer.analyze([])
            assert results == []

    def test_all_analyzers_no_traffic_events(self) -> None:
        """所有分析器无网络流量事件测试。"""
        event = NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="host_log",
            source="test",
            event_type="process_create",
            action="create_process",
        )
        analyzers = [DnsAnalyzer(), HttpAnalyzer(), IcmpAnalyzer(), ConnectionAnalyzer()]
        for analyzer in analyzers:
            results = analyzer.analyze([event])
            assert results == []

    def test_corrupted_event_with_none_network(self) -> None:
        """缺少 network 字段的事件测试。"""
        event = NormalizedEvent(
            timestamp=datetime.now(timezone.utc),
            source_type="network_traffic",
            source="test",
            event_type="dns_query",
            action="dns_query",
            raw_data={"dns": {"query": "test.com", "query_type": "A"}},
            # network=None
        )
        # 不应崩溃
        results = DnsAnalyzer().analyze([event])
        # 应正常处理，不崩溃
        assert isinstance(results, list)

    def test_zeek_to_dns_analyzer_integration(self, tmp_path: Path) -> None:
        """Zeek DNS 日志解析后接入 DNS 分析器的集成测试。"""
        from tests.fixtures.zeek_generator import create_dns_log
        dns_file = tmp_path / "dns.log"
        create_dns_log(dns_file)

        parser = ZeekParser()
        events = parser.parse(dns_file)
        assert len(events) > 0

        analyzer = DnsAnalyzer()
        results = analyzer.analyze(events)
        # 4 条记录中有一条长子域、一条 TXT、一条 NXDOMAIN，不一定够触发阈值
        # 但不应崩溃
        assert isinstance(results, list)

    def test_suricata_to_analyzer_integration(self, tmp_path: Path) -> None:
        """Suricata eve.json 解析后接入分析器的集成测试。"""
        eve_file = tmp_path / "eve.json"
        create_eve_json(eve_file)

        parser = SuricataParser()
        events = parser.parse(eve_file)
        assert len(events) > 0

        # 测试所有 analyzer 都能处理 Suricata 事件
        analyzers = [DnsAnalyzer(), HttpAnalyzer(), ConnectionAnalyzer()]
        for analyzer in analyzers:
            results = analyzer.analyze(events)
            assert isinstance(results, list)

    def test_dns_tunnel_full_pipeline(self, tmp_path: Path) -> None:
        """DNS 隧道完整管道测试：Suricata 解析 -> DNS 分析器。"""
        eve_file = tmp_path / "dns_tunnel_eve.json"
        create_dns_tunnel_eve(eve_file)

        parser = SuricataParser()
        events = parser.parse(eve_file)
        assert len(events) == 40

        analyzer = DnsAnalyzer()
        results = analyzer.analyze(events)
        tunnel_results = [r for r in results if "dns_tunnel" in r.tags]
        assert len(tunnel_results) > 0
        assert tunnel_results[0].confidence > 0.5
        assert "evidence" in tunnel_results[0].model_dump()
