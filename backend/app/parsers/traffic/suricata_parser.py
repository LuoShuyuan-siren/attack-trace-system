"""Suricata eve.json 解析器。

支持解析 Suricata eve.json 格式的事件类型：
- flow
- dns
- http
- alert
- tls（如果接口适合）

eve.json 为每行一个 JSON 对象。
"""

import json
from datetime import datetime, timezone
from pathlib import Path

from app.core.parser import BaseParser
from app.schemas.event import NetworkInfo, NormalizedEvent
from app.parsers.traffic.utils import parse_iso_timestamp, safe_int, safe_str


class SuricataParser(BaseParser):
    """Suricata eve.json 解析器。

    解析 eve.json 中的 flow/dns/http/alert/tls 事件，
    统一转换为 NormalizedEvent。
    """

    @property
    def name(self) -> str:
        return "suricata"

    @property
    def source_type(self) -> str:
        return "network_traffic"

    def parse(self, source: Path) -> list[NormalizedEvent]:
        """解析 eve.json 文件或目录。"""
        if not source.exists():
            return []

        if source.is_dir():
            events: list[NormalizedEvent] = []
            for f in sorted(source.iterdir()):
                if f.is_file() and (f.suffix == ".json" or f.name == "eve.json" or "eve" in f.name):
                    events.extend(self._parse_file(f))
            return events

        return self._parse_file(source)

    def _parse_file(self, filepath: Path) -> list[NormalizedEvent]:
        """解析单个 eve.json 文件（JSONL 格式）。"""
        events: list[NormalizedEvent] = []

        try:
            with open(filepath, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    try:
                        event = self._convert_record(record)
                        if event is not None:
                            events.append(event)
                    except Exception:  # noqa: BLE001
                        # 单条坏数据不影响整体
                        continue
        except OSError:
            return []

        return events

    def _convert_record(self, record: dict) -> NormalizedEvent | None:
        """将 Suricata eve.json 记录转换为 NormalizedEvent。"""
        event_type = safe_str(record.get("event_type"))

        # 解析时间戳
        timestamp = parse_iso_timestamp(record.get("timestamp"))
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        if event_type == "flow":
            return self._convert_flow(record, timestamp)
        if event_type == "dns":
            return self._convert_dns(record, timestamp)
        if event_type == "http":
            return self._convert_http(record, timestamp)
        if event_type == "alert":
            return self._convert_alert(record, timestamp)
        if event_type == "tls":
            return self._convert_tls(record, timestamp)

        # 其他类型不处理
        return None

    def _extract_network_info(self, record: dict) -> NetworkInfo:
        """从 eve.json 记录提取网络信息。"""
        return NetworkInfo(
            src_ip=safe_str(record.get("src_ip")),
            src_port=safe_int(record.get("src_port")) or None,
            dst_ip=safe_str(record.get("dest_ip")),
            dst_port=safe_int(record.get("dest_port")) or None,
            protocol=safe_str(record.get("proto")),
        )

    def _convert_flow(self, record: dict, timestamp: datetime) -> NormalizedEvent:
        """转换 flow 事件。"""
        net = self._extract_network_info(record)
        flow_data = record.get("flow", {})

        raw_data: dict[str, object] = {
            "pkts_toserver": flow_data.get("pkts_toserver"),
            "pkts_toclient": flow_data.get("pkts_toclient"),
            "bytes_toserver": flow_data.get("bytes_toserver"),
            "bytes_toclient": flow_data.get("bytes_toclient"),
            "start": flow_data.get("start"),
            "end": flow_data.get("end"),
            "state": flow_data.get("state"),
            "age": flow_data.get("age"),
        }
        raw_data = {k: v for k, v in raw_data.items() if v is not None}

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="suricata",
            event_type="network_flow",
            network=net,
            action="flow_recorded",
            raw_data=raw_data,
            tags=["suricata", "flow"],
        )

    def _convert_dns(self, record: dict, timestamp: datetime) -> NormalizedEvent:
        """转换 dns 事件。"""
        net = self._extract_network_info(record)
        dns_data = record.get("dns", {})

        dns_raw: dict[str, object] = {
            "query": dns_data.get("rrname"),
            "query_type": dns_data.get("rrtype"),
            "rcode": dns_data.get("rcode"),
            "type": dns_data.get("type"),
            "tx_id": dns_data.get("txid"),
            "answers": dns_data.get("answers"),
            "ttl": dns_data.get("ttl"),
        }
        dns_raw = {k: v for k, v in dns_raw.items() if v is not None}

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="suricata",
            event_type="dns_query",
            network=net,
            action="dns_query",
            raw_data={"dns": dns_raw},
            tags=["suricata", "dns"],
        )

    def _convert_http(self, record: dict, timestamp: datetime) -> NormalizedEvent:
        """转换 http 事件。"""
        net = self._extract_network_info(record)
        http_data = record.get("http", {})

        http_raw: dict[str, object] = {
            "method": http_data.get("http_method"),
            "host": http_data.get("hostname"),
            "uri": http_data.get("url") or http_data.get("http_uri") or http_data.get("uri"),
            "user_agent": http_data.get("http_user_agent"),
            "status_code": http_data.get("http_status"),
            "content_type": http_data.get("http_content_type"),
            "request_body": http_data.get("request_body"),
            "response_body": http_data.get("response_body"),
            "protocol": http_data.get("protocol"),
            "length": http_data.get("length"),
        }
        http_raw = {k: v for k, v in http_raw.items() if v is not None}

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="suricata",
            event_type="http_request",
            network=net,
            action="http_communication",
            raw_data={"http": http_raw},
            tags=["suricata", "http"],
        )

    def _convert_alert(self, record: dict, timestamp: datetime) -> NormalizedEvent:
        """转换 alert 事件。"""
        net = self._extract_network_info(record)
        alert_data = record.get("alert", {})

        severity_val = alert_data.get("severity", 3)
        # Suricata severity: 1=high, 2=medium, 3=low
        sev_map = {1: "high", 2: "medium", 3: "low"}
        severity = sev_map.get(severity_val, "low")

        alert_raw: dict[str, object] = {
            "signature": alert_data.get("signature"),
            "category": alert_data.get("category"),
            "severity": severity_val,
            "signature_id": alert_data.get("signature_id"),
            "gid": alert_data.get("gid"),
            "rev": alert_data.get("rev"),
        }
        alert_raw = {k: v for k, v in alert_raw.items() if v is not None}

        # 提取 payload（如有）
        payload = record.get("payload")
        if payload:
            alert_raw["payload"] = payload

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="suricata",
            event_type="alert",
            network=net,
            action="alert_triggered",
            raw_data=alert_raw,
            severity=severity,
            tags=["suricata", "alert"],
        )

    def _convert_tls(self, record: dict, timestamp: datetime) -> NormalizedEvent:
        """转换 tls 事件。"""
        net = self._extract_network_info(record)
        tls_data = record.get("tls", {})

        tls_raw: dict[str, object] = {
            "subject": tls_data.get("subject"),
            "issuer": tls_data.get("issuerdn"),
            "fingerprint": tls_data.get("fingerprint"),
            "sni": tls_data.get("sni"),
            "version": tls_data.get("version"),
        }
        tls_raw = {k: v for k, v in tls_raw.items() if v is not None}

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="suricata",
            event_type="tls_handshake",
            network=net,
            action="tls_handshake",
            raw_data={"tls": tls_raw},
            tags=["suricata", "tls"],
        )
