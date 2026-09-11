from pathlib import Path

from app.core.parser import BaseParser
from app.parsers.linux import LinuxLogParser
from app.parsers.host_behavior_json import HostBehaviorJsonParser
from app.parsers.traffic import PcapParser, SuricataParser, ZeekParser
from app.parsers.windows_log_parser import WindowsLogParser


def get_parser(source_type: str, source: Path) -> BaseParser:
    """根据数据源类型和文件格式选择对应解析器。"""

    suffix = source.suffix.lower()
    filename = source.name.lower()

    if source_type == "host_log":
        # ① 原有 EVTX 解析
        if suffix == ".evtx":
            return WindowsLogParser()
            
        # ② 新增支持 BOTS 导出的 .csv.gz 及普通 .gz 文件
        if suffix == ".gz" or filename.endswith(".csv.gz"):
            return WindowsLogParser()

        # ③ 原有 Linux 日志解析
        if suffix in {".txt", ".log"}:
            return LinuxLogParser(hostname="uploaded-host")

        raise ValueError(
            f"host_log 不支持文件格式: {suffix}，"
            "请上传 .txt、.log、.evtx 或 .csv.gz"
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
        if suffix in {".json", ".jsonl", ".ndjson"}:
            return HostBehaviorJsonParser()
        raise ValueError("host_behavior 不支持文件格式，请上传 .json、.jsonl 或 .ndjson")

    raise ValueError(f"未知 source_type: {source_type}")