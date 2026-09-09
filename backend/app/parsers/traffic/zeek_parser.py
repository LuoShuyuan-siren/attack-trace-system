"""Zeek 日志解析器。

支持 Zeek 日志类型：
- conn.log
- dns.log
- http.log
- ssl.log / tls.log（如果架构允许）

Zeek 日志为 TSV（制表符分隔）格式，
首行 #fields 定义字段顺序，#types 定义类型。
"""

from datetime import datetime, timezone
from pathlib import Path

from app.core.parser import BaseParser
from app.schemas.event import NetworkInfo, NormalizedEvent
from app.parsers.traffic.utils import parse_iso_timestamp, safe_int

# Zeek 日志类型到文件名的映射
_ZEEK_LOG_FILES = {
    "conn": "conn.log",
    "dns": "dns.log",
    "http": "http.log",
    "ssl": "ssl.log",
    "tls": "tls.log",
    "files": "files.log",
    "weird": "weird.log",
}

# 时间格式: Zeek 默认使用 Unix 时间戳（浮点秒）
def _parse_zeek_timestamp(ts: str) -> datetime | None:
    """解析 Zeek 时间戳（Unix epoch 或 ISO 8601）。"""
    return parse_iso_timestamp(ts)


class ZeekParser(BaseParser):
    """Zeek 日志解析器。

    自动识别日志类型并解析为 NormalizedEvent。
    支持输入单个日志文件或包含多个 .log 文件的目录。
    """

    @property
    def name(self) -> str:
        return "zeek"

    @property
    def source_type(self) -> str:
        return "network_traffic"

    def parse(self, source: Path) -> list[NormalizedEvent]:
        """解析 Zeek 日志文件或目录。"""
        if not source.exists():
            return []

        if source.is_dir():
            events: list[NormalizedEvent] = []
            for f in sorted(source.iterdir()):
                if f.is_file() and f.suffix == ".log":
                    events.extend(self._parse_log_file(f))
            return events

        return self._parse_log_file(source)

    def _parse_log_file(self, filepath: Path) -> list[NormalizedEvent]:
        """解析单个 Zeek 日志文件。"""
        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return []

        log_type = self._detect_log_type(filepath, lines)
        if log_type is None:
            return []

        fields: list[str] | None = None
        events: list[NormalizedEvent] = []

        for line in lines:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#fields"):
                fields = line.split("\t")[1:]
                continue
            if line.startswith("#"):
                continue
            if fields is None:
                continue

            values = line.split("\t")
            if len(values) < len(fields):
                # 补齐缺失字段
                values.extend(["-"] * (len(fields) - len(values)))

            record = dict(zip(fields, values))

            try:
                event = self._convert_record(record, log_type, filepath)
                if event is not None:
                    events.append(event)
            except Exception:  # noqa: BLE001
                # 单条坏数据不影响整体解析
                continue

        return events

    def _detect_log_type(
        self,
        filepath: Path,
        lines: list[str],
    ) -> str | None:
        """检测 Zeek 日志类型。"""
        # 从文件名检测
        filename = filepath.name.lower()
        for log_type, log_file in _ZEEK_LOG_FILES.items():
            if log_file in filename:
                return log_type

        # 从 #path 行检测
        for line in lines[:20]:
            if line.startswith("#path"):
                parts = line.strip().split("\t")
                if len(parts) >= 2:
                    path_val = parts[1].strip()
                    for log_type, log_file in _ZEEK_LOG_FILES.items():
                        if log_file.replace(".log", "") in path_val:
                            return log_type

        # 从 #fields 行检测
        for line in lines[:20]:
            if line.startswith("#fields"):
                field_str = line.lower()
                if "id.orig_h" in field_str and "id.orig_p" in field_str:
                    if "query" in field_str:
                        return "dns"
                    if "uri" in field_str or "method" in field_str:
                        return "http"
                    if "ssl" in field_str or "tls" in field_str or "server_name" in field_str:
                        return "ssl"
                    if "duration" in field_str or "orig_bytes" in field_str:
                        return "conn"
                return "conn"  # 默认

        return None

    def _convert_record(
        self,
        record: dict[str, str],
        log_type: str,
        filepath: Path,
    ) -> NormalizedEvent | None:
        """将 Zeek 记录转换为 NormalizedEvent。"""
        ts_raw = record.get("ts", "-")
        timestamp = _parse_zeek_timestamp(ts_raw)
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        # "-" 是 Zeek 的空值标记
        def _val(key: str) -> str | None:
            v = record.get(key, "-")
            if v == "-" or v == "":
                return None
            return v

        if log_type == "conn":
            return self._convert_conn(record, timestamp, _val)
        if log_type == "dns":
            return self._convert_dns(record, timestamp, _val)
        if log_type == "http":
            return self._convert_http(record, timestamp, _val)
        if log_type == "ssl":
            return self._convert_ssl(record, timestamp, _val)

        return None

    def _convert_conn(
        self,
        record: dict[str, str],
        timestamp: datetime,
        _val,
    ) -> NormalizedEvent:
        """转换 conn.log 记录。"""
        src_ip = _val("id.orig_h") or ""
        dst_ip = _val("id.resp_h") or ""
        src_port = safe_int(_val("id.orig_p"))
        dst_port = safe_int(_val("id.resp_p"))
        proto = _val("proto") or ""

        raw_data: dict[str, object] = {
            "duration": _val("duration"),
            "orig_bytes": _val("orig_bytes"),
            "resp_bytes": _val("resp_bytes"),
            "orig_pkts": _val("orig_pkts"),
            "resp_pkts": _val("resp_pkts"),
            "service": _val("service"),
            "conn_state": _val("conn_state"),
            "uid": _val("uid"),
        }
        # 清理 None 值
        raw_data = {k: v for k, v in raw_data.items() if v is not None}

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="zeek",
            event_type="network_connection",
            network=NetworkInfo(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol=proto.upper(),
            ),
            action="connection_established",
            raw_data=raw_data,
            tags=["zeek", "conn", proto.lower()] if proto else ["zeek", "conn"],
        )

    def _convert_dns(
        self,
        record: dict[str, str],
        timestamp: datetime,
        _val,
    ) -> NormalizedEvent:
        """转换 dns.log 记录。"""
        src_ip = _val("id.orig_h") or ""
        dst_ip = _val("id.resp_h") or ""
        src_port = safe_int(_val("id.orig_p"))
        dst_port = safe_int(_val("id.resp_p"))

        query = _val("query") or ""
        qtype = _val("qtype_name") or ""
        rcode = _val("rcode_name") or ""
        answer = _val("answers")

        dns_raw: dict[str, object] = {
            "query": query,
            "query_type": qtype,
            "rcode": rcode,
            "rcode_num": _val("rcode"),
            "answer": answer,
            "ttl": _val("TTL"),
            "uid": _val("uid"),
            "trans_id": _val("trans_id"),
        }
        dns_raw = {k: v for k, v in dns_raw.items() if v is not None}

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="zeek",
            event_type="dns_query",
            network=NetworkInfo(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="UDP",
            ),
            action="dns_query",
            raw_data={"dns": dns_raw},
            tags=["zeek", "dns"],
        )

    def _convert_http(
        self,
        record: dict[str, str],
        timestamp: datetime,
        _val,
    ) -> NormalizedEvent:
        """转换 http.log 记录。"""
        src_ip = _val("id.orig_h") or ""
        dst_ip = _val("id.resp_h") or ""
        src_port = safe_int(_val("id.orig_p"))
        dst_port = safe_int(_val("id.resp_p"))

        method = _val("method") or ""
        host = _val("host") or ""
        uri = _val("uri") or ""
        user_agent = _val("user_agent")
        status_code = safe_int(_val("status_code"))
        resp_mime = _val("resp_mime_types")
        req_body_len = _val("request_body_len")
        resp_body_len = _val("response_body_len")

        http_raw: dict[str, object] = {
            "method": method,
            "host": host,
            "uri": uri,
            "user_agent": user_agent,
            "status_code": status_code if status_code else None,
            "content_type": resp_mime,
            "request_body_len": req_body_len,
            "response_body_len": resp_body_len,
            "uid": _val("uid"),
        }
        http_raw = {k: v for k, v in http_raw.items() if v is not None}

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="zeek",
            event_type="http_request",
            network=NetworkInfo(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="TCP",
            ),
            action="http_communication",
            raw_data={"http": http_raw},
            tags=["zeek", "http"],
        )

    def _convert_ssl(
        self,
        record: dict[str, str],
        timestamp: datetime,
        _val,
    ) -> NormalizedEvent:
        """转换 ssl.log 记录。"""
        src_ip = _val("id.orig_h") or ""
        dst_ip = _val("id.resp_h") or ""
        src_port = safe_int(_val("id.orig_p"))
        dst_port = safe_int(_val("id.resp_p"))

        server_name = _val("server_name")
        ssl_version = _val("version")
        ssl_cipher = _val("cipher")

        ssl_raw: dict[str, object] = {
            "server_name": server_name,
            "ssl_version": ssl_version,
            "cipher": ssl_cipher,
            "subject": _val("subject"),
            "issuer": _val("issuer"),
            "uid": _val("uid"),
        }
        ssl_raw = {k: v for k, v in ssl_raw.items() if v is not None}

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="zeek",
            event_type="ssl_handshake",
            network=NetworkInfo(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="TCP",
            ),
            action="ssl_handshake",
            raw_data={"ssl": ssl_raw},
            tags=["zeek", "ssl"],
        )
