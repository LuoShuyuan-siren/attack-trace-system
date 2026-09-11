"""网络流量 Parser 测试。

覆盖：
- PCAP 基础解析（TCP/UDP-DNS/ICMP）
- Zeek conn.log
- Zeek dns.log
- Zeek http.log
- Zeek ssl.log
- Suricata eve.json (flow/dns/http/alert/tls)
- 边界输入（空文件、损坏文件）
"""

import json
from pathlib import Path

from app.parsers.traffic.pcap_parser import PcapParser
from app.parsers.traffic.zeek_parser import ZeekParser
from app.parsers.traffic.suricata_parser import SuricataParser

from tests.fixtures.pcap_generator import create_minimal_pcap
from tests.fixtures.zeek_generator import create_all_zeek_logs
from tests.fixtures.suricata_generator import create_eve_json


# ==================== PCAP Parser 测试 ====================


class TestPcapParser:
    """PCAP 解析器测试。"""

    def test_name_and_source_type(self) -> None:
        parser = PcapParser()
        assert parser.name == "pcap"
        assert parser.source_type == "network_traffic"

    def test_parse_basic_pcap(self, tmp_path: Path) -> None:
        """测试 PCAP 基础解析。"""
        pcap_file = tmp_path / "test.pcap"
        create_minimal_pcap(pcap_file)

        parser = PcapParser()
        events = parser.parse(pcap_file)

        assert len(events) == 3

        # TCP 包
        tcp_event = events[0]
        assert tcp_event.source_type == "network_traffic"
        assert tcp_event.source == "pcap"
        assert tcp_event.network is not None
        assert tcp_event.network.src_ip == "192.168.1.1"
        assert tcp_event.network.dst_ip == "10.0.0.1"
        assert tcp_event.network.src_port == 12345
        assert tcp_event.network.dst_port == 80
        assert tcp_event.network.protocol == "TCP"
        assert "tcp" in tcp_event.tags

    def test_parse_udp_dns_packet(self, tmp_path: Path) -> None:
        """测试 PCAP 中 UDP/DNS 包解析。"""
        pcap_file = tmp_path / "test.pcap"
        create_minimal_pcap(pcap_file)

        parser = PcapParser()
        events = parser.parse(pcap_file)

        # 第二个包是 UDP/DNS
        dns_event = events[1]
        assert dns_event.network.protocol == "UDP"
        assert dns_event.network.src_ip == "192.168.1.1"
        assert dns_event.network.dst_ip == "8.8.8.8"
        assert dns_event.network.dst_port == 53
        assert dns_event.event_type == "dns_query"
        assert "dns" in dns_event.tags

        # 检查 DNS 信息
        dns_info = dns_event.raw_data.get("dns")
        assert isinstance(dns_info, dict)
        assert "example.com" in dns_info.get("query_name", "")

    def test_parse_icmp_packet(self, tmp_path: Path) -> None:
        """测试 PCAP 中 ICMP 包解析。"""
        pcap_file = tmp_path / "test.pcap"
        create_minimal_pcap(pcap_file)

        parser = PcapParser()
        events = parser.parse(pcap_file)

        # 第三个包是 ICMP
        icmp_event = events[2]
        assert icmp_event.event_type == "icmp_packet"
        assert icmp_event.network.protocol == "ICMP"
        assert icmp_event.network.src_ip == "192.168.1.1"
        assert icmp_event.network.dst_ip == "10.0.0.2"
        assert "icmp" in icmp_event.tags

        # ICMP 信息
        assert "icmp_type" in icmp_event.raw_data
        assert icmp_event.raw_data["icmp_type"] == 8  # Echo Request

    def test_parse_nonexistent_file(self, tmp_path: Path) -> None:
        """测试解析不存在的文件。"""
        parser = PcapParser()
        events = parser.parse(tmp_path / "nonexistent.pcap")
        assert events == []

    def test_parse_empty_file(self, tmp_path: Path) -> None:
        """测试解析空文件。"""
        empty_file = tmp_path / "empty.pcap"
        empty_file.write_bytes(b"")

        parser = PcapParser()
        events = parser.parse(empty_file)
        assert events == []

    def test_parse_corrupted_file(self, tmp_path: Path) -> None:
        """测试解析损坏的文件。"""
        bad_file = tmp_path / "bad.pcap"
        bad_file.write_bytes(b"\x00\x01\x02\x03not-a-valid-pcap-file-content")

        parser = PcapParser()
        events = parser.parse(bad_file)
        assert events == []

    def test_parse_directory(self, tmp_path: Path) -> None:
        """测试解析目录。"""
        pcap_dir = tmp_path / "pcaps"
        pcap_dir.mkdir()
        create_minimal_pcap(pcap_dir / "a.pcap")
        create_minimal_pcap(pcap_dir / "b.pcap")

        parser = PcapParser()
        events = parser.parse(pcap_dir)
        assert len(events) == 6  # 2 files × 3 packets each


# ==================== Zeek Parser 测试 ====================


class TestZeekParser:
    """Zeek 日志解析器测试。"""

    def test_name_and_source_type(self) -> None:
        parser = ZeekParser()
        assert parser.name == "zeek"
        assert parser.source_type == "network_traffic"

    def test_parse_conn_log(self, tmp_path: Path) -> None:
        """测试 Zeek conn.log 解析。"""
        from tests.fixtures.zeek_generator import create_conn_log
        conn_file = tmp_path / "conn.log"
        create_conn_log(conn_file)

        parser = ZeekParser()
        events = parser.parse(conn_file)

        assert len(events) == 3
        conn_event = events[0]
        assert conn_event.source == "zeek"
        assert conn_event.event_type == "network_connection"
        assert conn_event.network is not None
        assert conn_event.network.src_ip == "192.168.1.1"
        assert conn_event.network.dst_ip == "10.0.0.1"
        assert conn_event.network.src_port == 12345
        assert conn_event.network.dst_port == 80
        assert conn_event.network.protocol == "TCP"
        assert "conn" in conn_event.tags

    def test_parse_dns_log(self, tmp_path: Path) -> None:
        """测试 Zeek dns.log 解析。"""
        from tests.fixtures.zeek_generator import create_dns_log
        dns_file = tmp_path / "dns.log"
        create_dns_log(dns_file)

        parser = ZeekParser()
        events = parser.parse(dns_file)

        assert len(events) == 4
        dns_event = events[0]
        assert dns_event.event_type == "dns_query"
        assert dns_event.network.src_ip == "192.168.1.1"
        assert dns_event.network.dst_ip == "8.8.8.8"
        assert dns_event.network.dst_port == 53
        assert "dns" in dns_event.tags

        dns_info = dns_event.raw_data.get("dns")
        assert isinstance(dns_info, dict)
        assert dns_info["query"] == "example.com"
        assert dns_info["query_type"] == "A"

    def test_parse_http_log(self, tmp_path: Path) -> None:
        """测试 Zeek http.log 解析。"""
        from tests.fixtures.zeek_generator import create_http_log
        http_file = tmp_path / "http.log"
        create_http_log(http_file)

        parser = ZeekParser()
        events = parser.parse(http_file)

        assert len(events) == 3
        http_event = events[0]
        assert http_event.event_type == "http_request"
        assert http_event.network.src_ip == "192.168.1.1"
        assert http_event.network.dst_ip == "10.0.0.1"
        assert http_event.network.dst_port == 80
        assert "http" in http_event.tags

        http_info = http_event.raw_data.get("http")
        assert isinstance(http_info, dict)
        assert http_info["method"] == "GET"
        assert http_info["host"] == "example.com"

    def test_parse_ssl_log(self, tmp_path: Path) -> None:
        """测试 Zeek ssl.log 解析。"""
        from tests.fixtures.zeek_generator import create_ssl_log
        ssl_file = tmp_path / "ssl.log"
        create_ssl_log(ssl_file)

        parser = ZeekParser()
        events = parser.parse(ssl_file)

        assert len(events) == 1
        ssl_event = events[0]
        assert ssl_event.event_type == "ssl_handshake"
        assert "ssl" in ssl_event.tags

        ssl_info = ssl_event.raw_data.get("ssl")
        assert isinstance(ssl_info, dict)
        assert ssl_info["server_name"] == "www.example.com"

    def test_parse_directory(self, tmp_path: Path) -> None:
        """测试解析包含多个日志的目录。"""
        zeek_dir = tmp_path / "zeek_logs"
        create_all_zeek_logs(zeek_dir)

        parser = ZeekParser()
        events = parser.parse(zeek_dir)

        # conn(3) + dns(4) + http(3) + ssl(1) = 11
        assert len(events) == 11

    def test_parse_nonexistent_file(self, tmp_path: Path) -> None:
        """测试解析不存在的文件。"""
        parser = ZeekParser()
        events = parser.parse(tmp_path / "nonexistent.log")
        assert events == []

    def test_parse_empty_file(self, tmp_path: Path) -> None:
        """测试解析空文件。"""
        empty_file = tmp_path / "empty.log"
        empty_file.write_text("")

        parser = ZeekParser()
        events = parser.parse(empty_file)
        assert events == []

    def test_parse_missing_fields(self, tmp_path: Path) -> None:
        """测试解析缺字段的记录。"""
        log_file = tmp_path / "incomplete.log"
        log_file.write_text(
            "#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
            "1000000000.000000\t-\t-\t10.0.0.1\t-\t-\n"  # 多个缺失字段
        )

        parser = ZeekParser()
        events = parser.parse(log_file)
        assert len(events) == 1
        # 不应因缺失字段而崩溃
        assert events[0].network is not None


# ==================== Suricata Parser 测试 ====================


class TestSuricataParser:
    """Suricata eve.json 解析器测试。"""

    def test_name_and_source_type(self) -> None:
        parser = SuricataParser()
        assert parser.name == "suricata"
        assert parser.source_type == "network_traffic"

    def test_parse_eve_json(self, tmp_path: Path) -> None:
        """测试 Suricata eve.json 解析。"""
        eve_file = tmp_path / "eve.json"
        create_eve_json(eve_file)

        parser = SuricataParser()
        events = parser.parse(eve_file)

        assert len(events) == 5

        # flow 事件
        flow_event = events[0]
        assert flow_event.event_type == "network_flow"
        assert flow_event.network.src_ip == "192.168.1.1"
        assert flow_event.network.dst_ip == "10.0.0.1"
        assert flow_event.network.dst_port == 80
        assert "flow" in flow_event.tags

        # dns 事件
        dns_event = events[1]
        assert dns_event.event_type == "dns_query"
        assert "dns" in dns_event.tags

        # http 事件
        http_event = events[2]
        assert http_event.event_type == "http_request"
        assert "http" in http_event.tags

        # alert 事件
        alert_event = events[3]
        assert alert_event.event_type == "alert"
        assert alert_event.severity == "high"  # severity=1 → high
        assert "alert" in alert_event.tags

        # tls 事件
        tls_event = events[4]
        assert tls_event.event_type == "tls_handshake"
        assert "tls" in tls_event.tags

    def test_parse_nonexistent_file(self, tmp_path: Path) -> None:
        """测试解析不存在的文件。"""
        parser = SuricataParser()
        events = parser.parse(tmp_path / "nonexistent.json")
        assert events == []

    def test_parse_empty_file(self, tmp_path: Path) -> None:
        """测试解析空文件。"""
        empty_file = tmp_path / "empty.json"
        empty_file.write_text("")

        parser = SuricataParser()
        events = parser.parse(empty_file)
        assert events == []

    def test_parse_corrupted_json(self, tmp_path: Path) -> None:
        """测试解析损坏的 JSON 行。"""
        bad_file = tmp_path / "bad.json"
        bad_file.write_text(
            '{"timestamp":"2026-09-08T10:00:00Z","event_type":"flow"}\n'
            "this is not valid json\n"
            '{"timestamp":"2026-09-08T10:00:01Z","event_type":"dns"}\n'
        )

        parser = SuricataParser()
        events = parser.parse(bad_file)
        # 跳过损坏行，解析有效行
        assert len(events) == 2

    def test_parse_unknown_event_type(self, tmp_path: Path) -> None:
        """测试解析未知事件类型。"""
        unknown_file = tmp_path / "unknown.json"
        unknown_file.write_text(
            json.dumps({
                "timestamp": "2026-09-08T10:00:00Z",
                "event_type": "fileinfo",
                "src_ip": "192.168.1.1",
                "dest_ip": "10.0.0.1",
            }) + "\n"
        )

        parser = SuricataParser()
        events = parser.parse(unknown_file)
        # 未知事件类型不处理
        assert events == []

    def test_parse_missing_timestamp(self, tmp_path: Path) -> None:
        """测试解析缺少时间戳的记录。"""
        bad_file = tmp_path / "no_ts.json"
        bad_file.write_text(
            json.dumps({
                "event_type": "flow",
                "src_ip": "192.168.1.1",
                "dest_ip": "10.0.0.1",
            }) + "\n"
        )

        parser = SuricataParser()
        events = parser.parse(bad_file)
        # 应使用当前时间作为默认值
        assert len(events) == 1
