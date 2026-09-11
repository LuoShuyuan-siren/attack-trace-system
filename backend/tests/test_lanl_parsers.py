"""LANL Parser 测试。

覆盖：
- LanlFlowParser: 正常 9 字段行、协议映射、端口处理、相对时间、
  异常行、gzip、统计、匿名主机元数据、Analyzer 兼容
- LanlDnsParser: 正常 3 字段行、异常行、gzip、统计、不伪造 DNS 字段、
  DNS 关系标记、Analyzer 忽略原因

测试 fixture 全部动态创建，不依赖本地 1GB 数据集。
"""

from datetime import timezone
from pathlib import Path

import gzip

from app.analyzers.traffic.connection_analyzer import ConnectionAnalyzer
from app.analyzers.traffic.dns_analyzer import DnsAnalyzer
from app.parsers.traffic.lanl_parser import LanlDnsParser, LanlFlowParser


# ==================== 辅助函数 ====================


def _write_text(path: Path, content: str) -> Path:
    """写入文本文件。"""
    path.write_text(content, encoding="utf-8")
    return path


def _write_gz(path: Path, content: str) -> Path:
    """写入 gzip 文本文件。"""
    with gzip.open(path, "wt", encoding="utf-8") as f:
        f.write(content)
    return path


# ==================== LanlFlowParser 测试 ====================


class TestLanlFlowParser:
    """LanlFlowParser 测试。"""

    def test_name_and_source_type(self) -> None:
        parser = LanlFlowParser()
        assert parser.name == "lanl_flow"
        assert parser.source_type == "network_traffic"

    def test_normal_9_fields(self, tmp_path: Path) -> None:
        """正常 9 字段行。"""
        line = "1,0,C1065,389,C3799,N10451,6,10,5323"
        f = _write_text(tmp_path / "flows.txt", line)
        events = LanlFlowParser().parse(f)
        assert len(events) == 1
        e = events[0]
        assert e.source == "lanl_flow"
        assert e.event_type == "network_connection"
        assert e.network is not None
        assert e.network.src_ip == "C1065"
        assert e.network.dst_ip == "C3799"
        assert e.network.src_port == 389
        assert e.network.protocol == "TCP"
        assert e.host.hostname == "C1065"

    def test_protocol_tcp(self, tmp_path: Path) -> None:
        """TCP 协议映射 (6 -> TCP)。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,80,C2,80,6,5,500")
        e = LanlFlowParser().parse(f)[0]
        assert e.network.protocol == "TCP"

    def test_protocol_udp(self, tmp_path: Path) -> None:
        """UDP 协议映射 (17 -> UDP)。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,53,C2,53,17,2,100")
        e = LanlFlowParser().parse(f)[0]
        assert e.network.protocol == "UDP"

    def test_protocol_icmp(self, tmp_path: Path) -> None:
        """ICMP 协议映射 (1 -> ICMP)。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,0,C2,0,1,1,64")
        e = LanlFlowParser().parse(f)[0]
        assert e.network.protocol == "ICMP"

    def test_unknown_protocol(self, tmp_path: Path) -> None:
        """未知协议号保留可追溯值，不导致解析失败。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,80,C2,80,89,5,500")
        events = LanlFlowParser().parse(f)
        assert len(events) == 1
        e = events[0]
        assert "UNKNOWN" in e.network.protocol
        assert "89" in e.network.protocol
        assert e.raw_data["protocol_num"] == 89
        assert e.raw_data["protocol_raw"] == "89"

    def test_missing_protocol(self, tmp_path: Path) -> None:
        """缺失协议不导致解析失败，原始值保留。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,80,C2,80,,5,500")
        events = LanlFlowParser().parse(f)
        assert len(events) == 1
        e = events[0]
        assert e.network.protocol is None
        assert e.raw_data["protocol_num"] is None
        assert e.raw_data["protocol_raw"] == ""

    def test_invalid_protocol(self, tmp_path: Path) -> None:
        """错误协议值不导致解析失败，保留原始值。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,80,C2,80,abc,5,500")
        events = LanlFlowParser().parse(f)
        assert len(events) == 1
        e = events[0]
        assert e.network.protocol == "abc"
        assert e.raw_data["protocol_num"] is None
        assert e.raw_data["protocol_raw"] == "abc"

    def test_numeric_port(self, tmp_path: Path) -> None:
        """数字端口正确转 int。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,12345,C2,80,6,5,500")
        e = LanlFlowParser().parse(f)[0]
        assert e.network.src_port == 12345
        assert e.network.dst_port == 80
        assert e.raw_data["src_port_raw"] == "12345"
        assert e.raw_data["dst_port_raw"] == "80"

    def test_non_numeric_port(self, tmp_path: Path) -> None:
        """N 开头端口保留为 None，原始值存 raw_data。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,N10451,C2,80,6,5,500")
        e = LanlFlowParser().parse(f)[0]
        assert e.network.src_port is None
        assert e.network.dst_port == 80
        assert e.raw_data["src_port_raw"] == "N10451"
        assert e.raw_data["dst_port_raw"] == "80"

    def test_non_numeric_dst_port(self, tmp_path: Path) -> None:
        """目标侧匿名端口同样不得强转 int。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,389,C2,N10451,6,5,500")
        e = LanlFlowParser().parse(f)[0]
        assert e.network.src_port == 389
        assert e.network.dst_port is None
        assert e.raw_data["dst_port_raw"] == "N10451"

    def test_field_count_too_few(self, tmp_path: Path) -> None:
        """字段不足安全跳过。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,80,C2,80,6,5")
        events = LanlFlowParser().parse(f)
        assert len(events) == 0

    def test_field_count_too_many(self, tmp_path: Path) -> None:
        """字段过多安全跳过。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,80,C2,80,6,5,500,extra")
        events = LanlFlowParser().parse(f)
        assert len(events) == 0

    def test_invalid_time(self, tmp_path: Path) -> None:
        """非法 time 值安全跳过。"""
        f = _write_text(tmp_path / "f.txt", "abc,0,C1,80,C2,80,6,5,500")
        events = LanlFlowParser().parse(f)
        assert len(events) == 0

    def test_missing_time(self, tmp_path: Path) -> None:
        """缺失 time 安全跳过。"""
        f = _write_text(tmp_path / "f.txt", ",0,C1,80,C2,80,6,5,500")
        events = LanlFlowParser().parse(f)
        assert len(events) == 0

    def test_time_zero(self, tmp_path: Path) -> None:
        """相对时间 0 秒对应固定基准。"""
        f = _write_text(tmp_path / "f.txt", "0,0,C1,80,C2,80,6,5,500")
        e = LanlFlowParser().parse(f)[0]
        assert e.raw_data["lanl_relative_time"] == 0
        assert e.timestamp.year == 1970
        assert e.timestamp.month == 1
        assert e.timestamp.day == 1
        assert e.timestamp.hour == 0
        assert e.timestamp.minute == 0
        assert e.timestamp.second == 0
        assert e.timestamp.tzinfo is not None
        assert e.timestamp.utcoffset().total_seconds() == 0

    def test_fractional_time(self, tmp_path: Path) -> None:
        """小数秒相对时间可解析。"""
        f = _write_text(tmp_path / "f.txt", "1.5,0,C1,80,C2,80,6,5,500")
        e = LanlFlowParser().parse(f)[0]
        assert e.raw_data["lanl_relative_time"] == 1.5
        assert e.timestamp.year == 1970
        assert e.timestamp.second == 1
        assert e.timestamp.microsecond == 500000
        assert e.timestamp.tzinfo is not None

    def test_invalid_packets_bytes(self, tmp_path: Path) -> None:
        """非法 packets/bytes 值安全跳过。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1,80,C2,80,6,abc,500")
        events = LanlFlowParser().parse(f)
        assert len(events) == 0

    def test_empty_line(self, tmp_path: Path) -> None:
        """空行跳过。"""
        content = "\n1,0,C1,80,C2,80,6,5,500\n\n2,0,C3,80,C4,80,6,3,300"
        f = _write_text(tmp_path / "f.txt", content)
        events = LanlFlowParser().parse(f)
        assert len(events) == 2

    def test_text_file(self, tmp_path: Path) -> None:
        """普通文本文件解析。"""
        f = _write_text(tmp_path / "flows.txt", "1,0,C1,80,C2,80,6,5,500")
        events = LanlFlowParser().parse(f)
        assert len(events) == 1

    def test_gzip_file(self, tmp_path: Path) -> None:
        """gzip 文件解析。"""
        f = _write_gz(tmp_path / "flows.txt.gz", "1,0,C1,80,C2,80,6,5,500")
        events = LanlFlowParser().parse(f)
        assert len(events) == 1
        assert events[0].network.src_ip == "C1"

    def test_bad_lines_mixed_with_good(self, tmp_path: Path) -> None:
        """多行中坏行不影响正确行。"""
        content = "\n".join([
            "1,0,C1,80,C2,80,6,5,500",
            "bad,line,here",
            "",
            "2,0,C3,443,C4,443,6,3,300",
            "3,0,C5,N1,C6,N2,17,1,50",
            "no,fields",
        ])
        f = _write_text(tmp_path / "f.txt", content)
        events = LanlFlowParser().parse(f)
        assert len(events) == 3
        assert events[0].network.src_ip == "C1"
        assert events[1].network.src_ip == "C3"

    def test_relative_time_metadata(self, tmp_path: Path) -> None:
        """相对时间元数据完整。"""
        f = _write_text(tmp_path / "f.txt", "100,5,C1,80,C2,80,6,5,500")
        e = LanlFlowParser().parse(f)[0]
        assert e.raw_data["lanl_relative_time"] == 100
        assert e.raw_data["timestamp_is_relative"] is True
        assert e.raw_data["timestamp_base"] == "1970-01-01T00:00:00+00:00"
        assert e.timestamp.tzinfo is not None
        assert e.timestamp.utcoffset().total_seconds() == 0

    def test_anonymous_id_preserved(self, tmp_path: Path) -> None:
        """匿名计算机标识原样保留，不丢失。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1065,N10451,C3799,389,6,10,5323")
        e = LanlFlowParser().parse(f)[0]
        assert e.raw_data["src_comp"] == "C1065"
        assert e.raw_data["dst_comp"] == "C3799"
        assert e.raw_data["src_port_raw"] == "N10451"
        assert e.raw_data["network_identifiers_are_anonymized_hosts"] is True
        assert e.network.src_ip == "C1065"
        assert e.network.dst_ip == "C3799"
        assert e.host.hostname == "C1065"

    def test_stats_in_raw_data(self, tmp_path: Path) -> None:
        """统计信息附加到最后一个事件的 raw_data。"""
        content = "\n".join([
            "1,0,C1,80,C2,80,6,5,500",
            "",
            "bad",
            "2,0,C3,80,C4,80,6,3,300",
        ])
        f = _write_text(tmp_path / "f.txt", content)
        events = LanlFlowParser().parse(f)
        assert len(events) == 2
        stats = events[-1].raw_data.get("_lanl_stats")
        assert stats is not None
        assert stats["total_lines"] == 4
        assert stats["parsed_lines"] == 2
        assert stats["skipped_empty_lines"] == 1
        assert stats["skipped_invalid_field_count"] == 1

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        """不存在的文件返回空列表。"""
        events = LanlFlowParser().parse(tmp_path / "noexist.txt")
        assert events == []

    def test_connection_analyzer_accepts_events(self, tmp_path: Path) -> None:
        """Flow 事件可进入 ConnectionAnalyzer，且不抛异常。"""
        f = _write_text(tmp_path / "f.txt", "1,0,C1065,389,C3799,80,6,10,5323")
        events = LanlFlowParser().parse(f)
        results = ConnectionAnalyzer().analyze(events)
        assert isinstance(results, list)


# ==================== LanlDnsParser 测试 ====================


class TestLanlDnsParser:
    """LanlDnsParser 测试。"""

    def test_name_and_source_type(self) -> None:
        parser = LanlDnsParser()
        assert parser.name == "lanl_dns"
        assert parser.source_type == "network_traffic"

    def test_normal_3_fields(self, tmp_path: Path) -> None:
        """正常 3 字段行。"""
        line = "2,C4653,C5030"
        f = _write_text(tmp_path / "dns.txt", line)
        events = LanlDnsParser().parse(f)
        assert len(events) == 1
        e = events[0]
        assert e.source == "lanl_dns"
        assert e.event_type == "dns_query"
        assert e.network is not None
        assert e.network.src_ip == "C4653"
        assert e.network.dst_ip == "C5030"
        assert e.host.hostname == "C4653"

    def test_field_count_too_few(self, tmp_path: Path) -> None:
        """字段不足跳过。"""
        f = _write_text(tmp_path / "d.txt", "2,C4653")
        events = LanlDnsParser().parse(f)
        assert len(events) == 0

    def test_field_count_too_many(self, tmp_path: Path) -> None:
        """字段过多跳过。"""
        f = _write_text(tmp_path / "d.txt", "2,C4653,C5030,extra")
        events = LanlDnsParser().parse(f)
        assert len(events) == 0

    def test_invalid_time(self, tmp_path: Path) -> None:
        """非法 time 跳过。"""
        f = _write_text(tmp_path / "d.txt", "abc,C4653,C5030")
        events = LanlDnsParser().parse(f)
        assert len(events) == 0

    def test_missing_time(self, tmp_path: Path) -> None:
        """缺失 time 跳过。"""
        f = _write_text(tmp_path / "d.txt", ",C4653,C5030")
        events = LanlDnsParser().parse(f)
        assert len(events) == 0

    def test_time_zero(self, tmp_path: Path) -> None:
        """相对时间 0 秒。"""
        f = _write_text(tmp_path / "d.txt", "0,C1,C2")
        e = LanlDnsParser().parse(f)[0]
        assert e.raw_data["lanl_relative_time"] == 0
        assert e.timestamp.tzinfo is not None
        assert e.timestamp.utcoffset().total_seconds() == 0

    def test_fractional_time(self, tmp_path: Path) -> None:
        """小数秒相对时间。"""
        f = _write_text(tmp_path / "d.txt", "2.25,C1,C2")
        e = LanlDnsParser().parse(f)[0]
        assert e.raw_data["lanl_relative_time"] == 2.25
        assert e.timestamp.second == 2
        assert e.timestamp.microsecond == 250000

    def test_empty_line(self, tmp_path: Path) -> None:
        """空行跳过。"""
        content = "\n2,C1,C2\n\n3,C3,C4"
        f = _write_text(tmp_path / "d.txt", content)
        events = LanlDnsParser().parse(f)
        assert len(events) == 2

    def test_text_file(self, tmp_path: Path) -> None:
        """普通文本文件。"""
        f = _write_text(tmp_path / "dns.txt", "2,C4653,C5030")
        events = LanlDnsParser().parse(f)
        assert len(events) == 1

    def test_gzip_file(self, tmp_path: Path) -> None:
        """gzip 文件解析。"""
        f = _write_gz(tmp_path / "dns.txt.gz", "2,C4653,C5030")
        events = LanlDnsParser().parse(f)
        assert len(events) == 1
        assert events[0].network.src_ip == "C4653"

    def test_bad_lines_mixed_with_good(self, tmp_path: Path) -> None:
        """坏行不影响正确行。"""
        content = "\n".join([
            "2,C1,C2",
            "bad",
            "",
            "3,C3,C4",
        ])
        f = _write_text(tmp_path / "d.txt", content)
        events = LanlDnsParser().parse(f)
        assert len(events) == 2

    def test_anonymous_id_preserved(self, tmp_path: Path) -> None:
        """匿名标识完整保留。"""
        f = _write_text(tmp_path / "d.txt", "2,C4653,C5030")
        e = LanlDnsParser().parse(f)[0]
        assert e.raw_data["src_comp"] == "C4653"
        assert e.raw_data["dst_comp"] == "C5030"
        assert e.raw_data["network_identifiers_are_anonymized_hosts"] is True
        assert e.network.src_ip == "C4653"
        assert e.network.dst_ip == "C5030"
        assert e.host.hostname == "C4653"

    def test_no_fabricated_dns_fields(self, tmp_path: Path) -> None:
        """不生成原始数据中不存在的 DNS 字段。"""
        f = _write_text(tmp_path / "d.txt", "2,C4653,C5030")
        e = LanlDnsParser().parse(f)[0]
        assert "dns" not in e.raw_data
        assert "query" not in e.raw_data
        assert "query_type" not in e.raw_data
        assert "rcode" not in e.raw_data
        assert e.raw_data["lanl_dns_relation_only"] is True
        assert e.raw_data["dns_fields_available"] is False

    def test_relative_time_metadata(self, tmp_path: Path) -> None:
        """相对时间元数据。"""
        f = _write_text(tmp_path / "d.txt", "200,C1,C2")
        e = LanlDnsParser().parse(f)[0]
        assert e.raw_data["lanl_relative_time"] == 200
        assert e.raw_data["timestamp_is_relative"] is True
        assert e.raw_data["timestamp_base"] == "1970-01-01T00:00:00+00:00"
        assert e.timestamp.tzinfo is not None
        assert e.timestamp.utcoffset().total_seconds() == 0

    def test_stats_in_raw_data(self, tmp_path: Path) -> None:
        """统计信息。"""
        content = "\n".join([
            "2,C1,C2",
            "",
            "bad",
            "3,C3,C4",
        ])
        f = _write_text(tmp_path / "d.txt", content)
        events = LanlDnsParser().parse(f)
        assert len(events) == 2
        stats = events[-1].raw_data.get("_lanl_stats")
        assert stats is not None
        assert stats["total_lines"] == 4
        assert stats["parsed_lines"] == 2
        assert stats["skipped_empty_lines"] == 1
        assert stats["skipped_invalid_field_count"] == 1

    def test_nonexistent_file(self, tmp_path: Path) -> None:
        """不存在的文件返回空列表。"""
        events = LanlDnsParser().parse(tmp_path / "noexist.txt")
        assert events == []

    def test_dns_analyzer_ignores_relation_only_events(
        self,
        tmp_path: Path,
    ) -> None:
        """LANL DNS 事件可标准化，但因缺少 dns 字段被 DnsAnalyzer 忽略。"""
        f = _write_text(tmp_path / "d.txt", "2,C4653,C5030")
        events = LanlDnsParser().parse(f)
        assert len(events) == 1
        results = DnsAnalyzer().analyze(events)
        assert results == []
