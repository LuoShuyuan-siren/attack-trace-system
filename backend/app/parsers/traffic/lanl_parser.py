"""LANL 网络流量数据解析器。

支持 LANL（Los Alamos National Laboratory）数据集的两种 CSV 格式：
- flows: 网络流记录（9 字段 CSV）
- dns: DNS 查询记录（3 字段 CSV）

文件格式特征：
- 逗号分隔的纯文本 CSV
- 无表头行
- 时间为相对秒数（整数或小数），非绝对 Unix 时间戳
- 实体用 C 前缀（计算机）和 N 前缀（非计算设备）匿名标识
- 无真实 IP 地址、无标准端口号、无域名信息

设计决策：
- 匿名计算机标识（C1065 等）不是实际 IP。优先语义是写入 host.hostname
  以及 raw_data["src_comp"] / raw_data["dst_comp"]。
  同时仍写入 network.src_ip / network.dst_ip，仅为兼容现有
  ConnectionAnalyzer（它按 network.src_ip / dst_ip 分组，若置 None
  则 LANL 流量无法进入该分析器）。禁止将这些值用于真实 IP 校验、
  地理定位或威胁情报查询。
- N 开头的非数字端口值不强制转 int，network 端口字段设为 None，
  原始值保存在 raw_data["src_port_raw"] / raw_data["dst_port_raw"]
- time 为相对秒数，采用固定基准时间 1970-01-01T00:00:00Z + 相对秒数
  生成带 UTC 时区的 timestamp，并在 raw_data 中保留相对时间元数据
- dns 数据没有域名/查询类型/响应码，只完成标准化，
  不伪造 DNS 检测所需字段

内存说明：
- gzip 文件读取过程是流式的（gzip.open 文本模式 + csv.reader 逐行），
  不会先调用 read() / readlines()，也不会一次性解压整个文件。
- 返回值仍遵循 BaseParser.parse(source) -> list[NormalizedEvent]，
  完整解析时事件列表会在内存中累积。超大数据集应由上层进行切片、
  抽样或批量导入。本 Parser 不扩展公共接口，也不引入破坏父类签名
  的必填参数。当前项目没有面向 Parser 的通用批处理机制可复用。
"""

import csv
import gzip
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.parser import BaseParser
from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent

# LANL 数据的固定基准时间（UTC epoch）
# time 字段是相对秒数，需要基准时间来生成可比较的绝对时间戳
_LANL_TIMESTAMP_BASE = datetime(1970, 1, 1, tzinfo=timezone.utc)

# flows.csv 固定 9 字段
_FLOW_FIELDS = 9

# dns.csv 固定 3 字段
_DNS_FIELDS = 3

# IP 协议号到名称的映射
_PROTO_MAP = {
    1: "ICMP",
    6: "TCP",
    17: "UDP",
}


def _open_text(source: Path):
    """打开文件，支持 .gz gzip 流式读取和普通文本文件。

    返回一个文本文件对象，供 csv.reader 逐行消费。
    不一次性加载或解压整个文件到内存。
    """
    if source.suffix.lower() == ".gz":
        return gzip.open(
            source,
            "rt",
            encoding="utf-8",
            errors="replace",
            newline="",
        )
    return open(source, "r", encoding="utf-8", errors="replace", newline="")


def _is_int(value: str) -> bool:
    """检查字符串是否为纯整数。"""
    if not value:
        return False
    return value.lstrip("-").isdigit()


def _safe_int(value: str) -> int | None:
    """安全转换为 int，失败返回 None。"""
    if _is_int(value):
        try:
            return int(value)
        except (ValueError, OverflowError):
            return None
    return None


def _safe_relative_time(value: str) -> int | float | None:
    """解析 LANL 相对秒数，支持整数和小数；非法或缺失返回 None。"""
    if not value:
        return None
    try:
        if _is_int(value):
            return int(value)
        number = float(value)
        if number != number:  # NaN
            return None
        return number
    except (ValueError, OverflowError):
        return None


def _timestamp_from_relative(relative_time: int | float) -> datetime | None:
    """将相对秒数转换为 UTC 时间戳。溢出时返回 None。"""
    try:
        return _LANL_TIMESTAMP_BASE + timedelta(seconds=float(relative_time))
    except (ValueError, OverflowError, OSError):
        return None


def _parse_protocol(proto_str: str) -> tuple[int | None, str | None]:
    """解析协议字段。未知/缺失/非法值不导致解析失败。

    Returns:
        (protocol_num, protocol_name)
        - 已知数字：映射为 ICMP/TCP/UDP
        - 未知数字：UNKNOWN(<num>)，并保留原始数字
        - 缺失：两者均为 None
        - 非数字：protocol_num 为 None，protocol_name 保留原始值
    """
    proto_num = _safe_int(proto_str)
    if proto_num is not None:
        return proto_num, _PROTO_MAP.get(proto_num, f"UNKNOWN({proto_num})")
    if not proto_str:
        return None, None
    return None, proto_str


class _LanlParserStats:
    """Parser 内部统计计数器。

    不通过公共接口返回，在 parse() 内部使用，
    最终附加到最后一个事件的 raw_data 中供测试验证。
    """

    def __init__(self) -> None:
        self.total_lines: int = 0
        self.parsed_lines: int = 0
        self.skipped_empty_lines: int = 0
        self.skipped_invalid_field_count: int = 0
        self.skipped_invalid_value: int = 0

    def to_dict(self) -> dict:
        return {
            "total_lines": self.total_lines,
            "parsed_lines": self.parsed_lines,
            "skipped_empty_lines": self.skipped_empty_lines,
            "skipped_invalid_field_count": self.skipped_invalid_field_count,
            "skipped_invalid_value": self.skipped_invalid_value,
        }


def _anonymized_host_metadata(src_comp: str, dst_comp: str) -> dict[str, object]:
    """匿名计算机标识相关元数据。

    C1065 / C123 等不是实际 IP。写入 NetworkInfo.src_ip / dst_ip
    仅是为了兼容现有 ConnectionAnalyzer 的分组逻辑，
    禁止用于真实 IP 校验、地理定位或威胁情报查询。
    """
    return {
        "src_comp": src_comp,
        "dst_comp": dst_comp,
        "network_identifiers_are_anonymized_hosts": True,
    }


class LanlFlowParser(BaseParser):
    """LANL flows 数据解析器。

    解析 LANL flows CSV 格式（每行 9 字段）：
    time,duration,src_comp,src_port,dst_comp,dst_port,protocol,packets,bytes

    - time: 相对秒数（整数或小数），不是实际 Unix 时间
    - duration: 连接持续时间（秒）
    - src_comp: 源计算机匿名标识（C 前缀），不是真实 IP
    - src_port: 源端口（数字或 N 前缀匿名值）
    - dst_comp: 目标计算机匿名标识（C 前缀），不是真实 IP
    - dst_port: 目标端口（数字或 N 前缀匿名值）
    - protocol: IP 协议号（1=ICMP, 6=TCP, 17=UDP）；未知值不导致失败
    - packets: 数据包数
    - bytes: 字节数

    接口保持 BaseParser.parse(source: Path) -> list[NormalizedEvent]。
    gzip 读取是流式的，但返回的事件列表仍会在内存中累积。
    """

    @property
    def name(self) -> str:
        return "lanl_flow"

    @property
    def source_type(self) -> str:
        return "network_traffic"

    def parse(self, source: Path) -> list[NormalizedEvent]:
        """解析 LANL flows 文件，返回 NormalizedEvent 列表。

        支持普通文本文件和 .gz gzip 文件。
        gzip 文件使用流式读取，不一次性加载或解压到内存。
        返回值仍会在内存中累积完整事件列表；超大数据集应由上层
        进行切片、抽样或批量导入。本方法不增加破坏父类接口的参数。
        """
        if not source.exists():
            return []

        stats = _LanlParserStats()
        events: list[NormalizedEvent] = []

        try:
            with _open_text(source) as f:
                reader = csv.reader(f)
                for row in reader:
                    stats.total_lines += 1

                    # 跳过空行（csv 可能把空行解析为 [] 或 ['']）
                    if not row or (len(row) == 1 and not row[0].strip()):
                        stats.skipped_empty_lines += 1
                        continue

                    if len(row) != _FLOW_FIELDS:
                        stats.skipped_invalid_field_count += 1
                        continue

                    event = self._parse_row(row, stats)
                    if event is not None:
                        events.append(event)
                        stats.parsed_lines += 1

        except OSError:
            return events

        # 将统计信息附加到最后一个事件的 raw_data
        if events:
            events[-1].raw_data["_lanl_stats"] = stats.to_dict()

        return events

    def _parse_row(
        self,
        row: list[str],
        stats: _LanlParserStats,
    ) -> NormalizedEvent | None:
        """解析单行 flows 数据。"""
        try:
            time_str, duration_str, src_comp, src_port_str, \
                dst_comp, dst_port_str, proto_str, \
                packets_str, bytes_str = [c.strip() for c in row]
        except (ValueError, IndexError):
            stats.skipped_invalid_value += 1
            return None

        relative_time = _safe_relative_time(time_str)
        if relative_time is None:
            stats.skipped_invalid_value += 1
            return None

        timestamp = _timestamp_from_relative(relative_time)
        if timestamp is None:
            stats.skipped_invalid_value += 1
            return None

        duration_val = _safe_relative_time(duration_str)

        # 未知 / 缺失 / 非法协议不导致本行解析失败
        proto_num, protocol_name = _parse_protocol(proto_str)

        packets_val = _safe_int(packets_str)
        bytes_val = _safe_int(bytes_str)
        if packets_val is None or bytes_val is None:
            stats.skipped_invalid_value += 1
            return None

        # 端口处理：只有纯数字才转 int，N 开头等非数字保留为 None
        src_port = _safe_int(src_port_str) if _is_int(src_port_str) else None
        dst_port = _safe_int(dst_port_str) if _is_int(dst_port_str) else None

        raw_data: dict[str, object] = {
            "lanl_relative_time": relative_time,
            "timestamp_is_relative": True,
            "timestamp_base": _LANL_TIMESTAMP_BASE.isoformat(),
            "duration": duration_val,
            "src_port_raw": src_port_str,
            "dst_port_raw": dst_port_str,
            "protocol_num": proto_num,
            "protocol_raw": proto_str,
            "packets": packets_val,
            "bytes": bytes_val,
            **_anonymized_host_metadata(src_comp, dst_comp),
        }

        tags = ["lanl", "flow"]
        if protocol_name:
            tags.append(protocol_name.lower())

        # C1065 等匿名主机标识不是实际 IP。
        # 写入 NetworkInfo.src_ip / dst_ip 是为了兼容现有
        # ConnectionAnalyzer（按 src_ip 分组；若为 None 会整组跳过）。
        # 禁止将其用于真实 IP 校验、地理定位或威胁情报查询。
        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="lanl_flow",
            host=HostInfo(hostname=src_comp),
            event_type="network_connection",
            network=NetworkInfo(
                src_ip=src_comp,
                src_port=src_port,
                dst_ip=dst_comp,
                dst_port=dst_port,
                protocol=protocol_name,
            ),
            action="connection_recorded",
            raw_data=raw_data,
            tags=tags,
        )


class LanlDnsParser(BaseParser):
    """LANL dns 数据解析器。

    解析 LANL dns CSV 格式（每行 3 字段）：
    time,src_comp,dst_comp

    - time: 相对秒数（整数或小数），不是实际 Unix 时间
    - src_comp: 源计算机匿名标识（C 前缀），不是真实 IP
    - dst_comp: 目标计算机匿名标识（C 前缀），不是真实 IP

    注意：LANL dns.txt.gz 只记录计算机间的 DNS 查询关系，
    不包含查询域名、query type、rcode 或 DNS 响应内容。
    本 Parser 只完成标准化，不伪造这些字段。
    DnsAnalyzer 依赖 raw_data["dns"] 中的域名等信息，因此 LANL DNS
    事件会被分析器忽略——这是数据字段不足，不是 Parser 异常。

    接口保持 BaseParser.parse(source: Path) -> list[NormalizedEvent]。
    gzip 读取是流式的，但返回的事件列表仍会在内存中累积。
    """

    @property
    def name(self) -> str:
        return "lanl_dns"

    @property
    def source_type(self) -> str:
        return "network_traffic"

    def parse(self, source: Path) -> list[NormalizedEvent]:
        """解析 LANL dns 文件，返回 NormalizedEvent 列表。

        支持普通文本文件和 .gz gzip 文件。
        gzip 文件使用流式读取，不一次性加载或解压到内存。
        返回值仍会在内存中累积完整事件列表；超大数据集应由上层
        进行切片、抽样或批量导入。本方法不增加破坏父类接口的参数。
        """
        if not source.exists():
            return []

        stats = _LanlParserStats()
        events: list[NormalizedEvent] = []

        try:
            with _open_text(source) as f:
                reader = csv.reader(f)
                for row in reader:
                    stats.total_lines += 1

                    # 跳过空行
                    if not row or (len(row) == 1 and not row[0].strip()):
                        stats.skipped_empty_lines += 1
                        continue

                    if len(row) != _DNS_FIELDS:
                        stats.skipped_invalid_field_count += 1
                        continue

                    event = self._parse_row(row, stats)
                    if event is not None:
                        events.append(event)
                        stats.parsed_lines += 1

        except OSError:
            return events

        # 将统计信息附加到最后一个事件的 raw_data
        if events:
            events[-1].raw_data["_lanl_stats"] = stats.to_dict()

        return events

    def _parse_row(
        self,
        row: list[str],
        stats: _LanlParserStats,
    ) -> NormalizedEvent | None:
        """解析单行 dns 数据。"""
        try:
            time_str, src_comp, dst_comp = [c.strip() for c in row]
        except (ValueError, IndexError):
            stats.skipped_invalid_value += 1
            return None

        relative_time = _safe_relative_time(time_str)
        if relative_time is None:
            stats.skipped_invalid_value += 1
            return None

        timestamp = _timestamp_from_relative(relative_time)
        if timestamp is None:
            stats.skipped_invalid_value += 1
            return None

        raw_data: dict[str, object] = {
            "lanl_relative_time": relative_time,
            "timestamp_is_relative": True,
            "timestamp_base": _LANL_TIMESTAMP_BASE.isoformat(),
            "lanl_dns_relation_only": True,
            "dns_fields_available": False,
            **_anonymized_host_metadata(src_comp, dst_comp),
        }

        # Cxxxx 不是实际 IP。写入 NetworkInfo 仅为与现有 Analyzer
        # 的 src_ip 分组逻辑兼容，禁止用于真实 IP 校验/地理定位/情报查询。
        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="lanl_dns",
            host=HostInfo(hostname=src_comp),
            event_type="dns_query",
            network=NetworkInfo(
                src_ip=src_comp,
                dst_ip=dst_comp,
                protocol="DNS",
            ),
            action="dns_query",
            raw_data=raw_data,
            tags=["lanl", "dns"],
        )
