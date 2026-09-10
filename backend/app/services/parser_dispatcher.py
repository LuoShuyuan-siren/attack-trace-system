from pathlib import Path

from app.core.parser import BaseParser
from app.parsers.linux import LinuxLogParser
from app.parsers.traffic import PcapParser, SuricataParser, ZeekParser
from app.parsers.windows_log_parser import WindowsLogParser


def get_parser(source_type: str, source: Path) -> BaseParser:
    """根据数据源类型和文件格式选择对应解析器。"""

    suffix = source.suffix.lower()
    filename = source.name.lower()

    if source_type == "host_log":
        if suffix == ".evtx":
            return WindowsLogParser()

        if suffix in {".txt", ".log"}:
            return LinuxLogParser(hostname="uploaded-host")

        raise ValueError(
            f"host_log 不支持文件格式: {suffix}，"
            "请上传 .txt、.log 或 .evtx"
        )

    if source_type == "network_traffic":
        if suffix in {".pcap", ".pcapng", ".cap"}:
            return PcapParser()

        if suffix == ".json" or "eve" in filename:
            return SuricataParser()

        if suffix == ".log":
            return ZeekParser()

        raise ValueError(
            f"network_traffic 不支持文件格式: {suffix}，"
            "请上传 .log、.json、.pcap、.pcapng 或 .cap"
        )

    if source_type == "host_behavior":
        raise ValueError(
            "host_behavior 当前暂未提供独立原始文件 Parser"
        )

    raise ValueError(f"未知 source_type: {source_type}")