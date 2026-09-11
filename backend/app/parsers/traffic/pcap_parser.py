"""PCAP / PCAPNG 文件解析器。

使用 Python 标准库（struct, socket）手动解析 PCAP 文件格式，
不引入 scapy 等大型依赖。

支持的格式：
- PCAP (libpcap) 经典格式
- 基础 TCP/UDP/ICMP/DNS/HTTP 协议字段提取

输出 NormalizedEvent 列表。
"""

import socket
import struct
from datetime import datetime, timezone
from pathlib import Path

from app.core.parser import BaseParser
from app.schemas.event import NetworkInfo, NormalizedEvent

# PCAP 魔数
_PCAP_MAGIC_LE = 0xA1B2C3D4
_PCAP_MAGIC_BE = 0xD4C3B2A1
_PCAPNG_MAGIC_BE = 0x0A0D0D0A

# 链路层类型
_LINKTYPE_ETHERNET = 1
_LINKTYPE_RAW = 101  # Raw IP
_LINKTYPE_LINUX_SLL = 113  # Linux cooked capture

# 以太网类型
_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_ETHERTYPE_ARP = 0x0806

# IP 协议号
_PROTO_ICMP = 1
_PROTO_TCP = 6
_PROTO_UDP = 17
_PROTO_ICMPV6 = 58

# DNS 标准端口
_DNS_PORT = 53

# HTTP 标准端口
_HTTP_PORTS = {80, 8080, 8000, 8443}
_HTTPS_PORTS = {443}


class PcapParser(BaseParser):
    """PCAP/PCAPNG 网络抓包文件解析器。

    解析 PCAP 文件并提取网络元数据，
    转换为 NormalizedEvent 输出。
    """

    @property
    def name(self) -> str:
        return "pcap"

    @property
    def source_type(self) -> str:
        return "network_traffic"

    def parse(self, source: Path) -> list[NormalizedEvent]:
        """解析 PCAP 文件，返回 NormalizedEvent 列表。"""
        if not source.exists():
            return []
        if source.is_dir():
            events: list[NormalizedEvent] = []
            for f in sorted(source.iterdir()):
                if f.is_file() and f.suffix.lower() in (".pcap", ".pcapng", ".cap"):
                    events.extend(self._parse_single(f))
            return events
        return self._parse_single(source)

    def _parse_single(self, filepath: Path) -> list[NormalizedEvent]:
        """解析单个 PCAP 文件。"""
        try:
            with open(filepath, "rb") as f:
                data = f.read()
        except OSError:
            return []

        if len(data) < 24:
            return []

        magic = struct.unpack("<I", data[:4])[0]

        if magic in (_PCAP_MAGIC_LE, _PCAP_MAGIC_BE):
            return self._parse_pcap_classic(data, magic)
        if magic == _PCAPNG_MAGIC_BE:
            return self._parse_pcapng(data)

        # 尝试大端经典 PCAP
        magic_be = struct.unpack(">I", data[:4])[0]
        if magic_be in (_PCAP_MAGIC_LE, _PCAP_MAGIC_BE):
            return self._parse_pcap_classic(data, magic_be)

        return []

    def _parse_pcap_classic(
        self,
        data: bytes,
        magic: int,
    ) -> list[NormalizedEvent]:
        """解析经典 PCAP 格式。"""
        events: list[NormalizedEvent] = []

        # 全局头 24 bytes
        if len(data) < 24:
            return []

        endian = "<" if magic == _PCAP_MAGIC_LE else ">"
        # PCAP 全局头: magic(4) + version_major(2) + version_minor(2)
        # + thiszone(4) + sigfigs(4) + snaplen(4) + linktype(4) = 24 bytes
        # 注意: magic 已读取，此处从 data[0] 解包全部 7 个字段
        _magic, _major, _minor, _zone, _sigfigs, _snaplen, linktype = struct.unpack(
            endian + "IHHiIII", data[:24]
        )

        offset = 24

        while offset + 16 <= len(data):
            # 包头 16 bytes: ts_sec, ts_usec, incl_len, orig_len
            ts_sec, ts_usec, incl_len, _orig_len = struct.unpack(
                endian + "IIII", data[offset:offset + 16]
            )
            offset += 16

            if incl_len <= 0 or incl_len > len(data) - offset:
                break

            pkt_data = data[offset:offset + incl_len]
            offset += incl_len

            timestamp = datetime.fromtimestamp(
                ts_sec + ts_usec / 1_000_000,
                tz=timezone.utc,
            )

            event = self._parse_packet(pkt_data, timestamp, linktype)
            if event is not None:
                events.append(event)

        return events

    def _parse_pcapng(
        self,
        data: bytes,
    ) -> list[NormalizedEvent]:
        """解析 PCAPNG 格式（最小支持）。"""
        events: list[NormalizedEvent] = []
        offset = 0
        linktype = _LINKTYPE_ETHERNET
        interface_tsresol: dict[int, int] = {}  # interface_id -> tsresol (us=10^-6 default)

        while offset + 8 <= len(data):
            block_type = struct.unpack("<I", data[offset:offset + 4])[0]
            block_total_len = struct.unpack("<I", data[offset + 4:offset + 8])[0]

            if block_total_len < 12 or block_total_len > len(data) - offset:
                break

            block_data = data[offset:offset + block_total_len]
            offset += block_total_len

            # Interface Description Block (0x00000001)
            if block_type == 1:
                if len(block_data) >= 20:
                    linktype = struct.unpack("<H", block_data[8:10])[0]
                    tsresol = 0  # default microseconds
                    # 可选 TLV 中查找 if_tsresol (option code 9)
                    opt_offset = 16
                    while opt_offset + 4 <= len(block_data):
                        opt_code, opt_len = struct.unpack("<HH", block_data[opt_offset:opt_offset + 4])
                        if opt_code == 0:
                            break
                        if opt_code == 9 and opt_len >= 1:
                            tsresol = block_data[opt_offset + 4]
                        opt_offset += 4 + opt_len
                        # pad to 4 bytes
                        opt_offset = (opt_offset + 3) & ~3
                    interface_tsresol[0] = tsresol  # simplified: only 1 interface

            # Enhanced Packet Block (0x00000006)
            elif block_type == 6:
                if len(block_data) < 28:
                    continue
                iface_id, ts_high, ts_low, cap_len, _orig_len = struct.unpack(
                    "<IIIII", block_data[8:28]
                )
                if cap_len <= 0 or 28 + cap_len > len(block_data):
                    continue
                pkt_data = block_data[28:28 + cap_len]

                tsresol = interface_tsresol.get(0, 0)
                if tsresol == 0:
                    # microseconds
                    total_us = (ts_high << 32) | ts_low
                    timestamp = datetime.fromtimestamp(total_us / 1_000_000, tz=timezone.utc)
                else:
                    # tsresol < 0: negative power of 10
                    power = -tsresol
                    total_ticks = (ts_high << 32) | ts_low
                    seconds = total_ticks / (10 ** power)
                    timestamp = datetime.fromtimestamp(seconds, tz=timezone.utc)

                event = self._parse_packet(pkt_data, timestamp, linktype)
                if event is not None:
                    events.append(event)

        return events

    def _parse_packet(
        self,
        pkt_data: bytes,
        timestamp: datetime,
        linktype: int,
    ) -> NormalizedEvent | None:
        """解析单个数据包，提取协议层信息。"""
        ip_payload, ip_proto, src_ip, dst_ip = self._strip_link_layer(pkt_data, linktype)

        if ip_payload is None:
            return None

        if ip_proto == _PROTO_ICMP or ip_proto == _PROTO_ICMPV6:
            return self._parse_icmp(ip_payload, src_ip, dst_ip, timestamp)
        if ip_proto == _PROTO_TCP:
            return self._parse_tcp(ip_payload, src_ip, dst_ip, timestamp)
        if ip_proto == _PROTO_UDP:
            return self._parse_udp(ip_payload, src_ip, dst_ip, timestamp)

        # 其他协议
        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="pcap",
            event_type="network_packet",
            network=NetworkInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=self._proto_name(ip_proto),
            ),
            action="packet_observed",
            raw_data={
                "protocol_number": ip_proto,
                "packet_length": len(pkt_data),
            },
            tags=["pcap", self._proto_name(ip_proto)],
        )

    def _strip_link_layer(
        self,
        pkt_data: bytes,
        linktype: int,
    ) -> tuple[bytes | None, int, str, str]:
        """剥离链路层，返回 (IP负载, 协议号, src_ip, dst_ip)。

        Returns:
            (ip_payload, ip_proto, src_ip, dst_ip)
            失败返回 (None, 0, "", "")
        """
        if linktype == _LINKTYPE_RAW:
            return self._parse_ip(pkt_data)

        if linktype == _LINKTYPE_LINUX_SLL:
            if len(pkt_data) < 16:
                return None, 0, "", ""
            return self._parse_ip(pkt_data[16:])

        if linktype == _LINKTYPE_ETHERNET:
            if len(pkt_data) < 14:
                return None, 0, "", ""
            ethertype = struct.unpack("!H", pkt_data[12:14])[0]
            if ethertype == _ETHERTYPE_IPV4:
                return self._parse_ip(pkt_data[14:])
            if ethertype == _ETHERTYPE_IPV6:
                return self._parse_ipv6(pkt_data[14:])
            return None, 0, "", ""

        return None, 0, "", ""

    def _parse_ip(self, data: bytes) -> tuple[bytes | None, int, str, str]:
        """解析 IPv4 包。"""
        if len(data) < 20:
            return None, 0, "", ""
        ver_ihl = data[0]
        version = ver_ihl >> 4
        if version != 4:
            return None, 0, "", ""
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(data) < ihl:
            return None, 0, "", ""
        proto = data[9]
        src_ip = socket.inet_ntoa(data[12:16])
        dst_ip = socket.inet_ntoa(data[16:20])
        return data[ihl:], proto, src_ip, dst_ip

    def _parse_ipv6(self, data: bytes) -> tuple[bytes | None, int, str, str]:
        """解析 IPv6 包。"""
        if len(data) < 40:
            return None, 0, "", ""
        proto = data[6]
        src_ip = socket.inet_ntop(socket.AF_INET6, data[8:24])
        dst_ip = socket.inet_ntop(socket.AF_INET6, data[24:40])
        return data[40:], proto, src_ip, dst_ip

    def _parse_tcp(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> NormalizedEvent | None:
        """解析 TCP 段。"""
        if len(payload) < 20:
            return None

        src_port, dst_port, seq, ack = struct.unpack("!HHII", payload[:12])
        data_offset_flags = struct.unpack("!H", payload[12:14])[0]
        data_offset = ((data_offset_flags >> 12) & 0xF) * 4
        flags = data_offset_flags & 0x1FF

        tcp_payload = payload[data_offset:] if data_offset <= len(payload) else b""

        # TCP flags
        flag_names: list[str] = []
        if flags & 0x001:
            flag_names.append("FIN")
        if flags & 0x002:
            flag_names.append("SYN")
        if flags & 0x004:
            flag_names.append("RST")
        if flags & 0x008:
            flag_names.append("PSH")
        if flags & 0x010:
            flag_names.append("ACK")
        if flags & 0x020:
            flag_names.append("URG")

        event_type = "network_packet"
        action = "tcp_packet"
        tags = ["pcap", "tcp"]
        raw_data: dict[str, object] = {
            "packet_length": len(payload),
            "tcp_flags": flag_names,
            "tcp_seq": seq,
            "tcp_ack": ack,
            "tcp_window": struct.unpack("!H", payload[14:16])[0] if len(payload) >= 16 else 0,
            "tcp_payload_length": len(tcp_payload),
        }
        if tcp_payload:
            raw_data["tcp_payload_hex"] = tcp_payload[:4096].hex()

        # HTTP 检测
        if dst_port in _HTTP_PORTS or src_port in _HTTP_PORTS:
            http_info = self._extract_http_info(tcp_payload)
            if http_info:
                event_type = "http_request" if "method" in http_info else "http_response"
                action = "http_communication"
                tags.append("http")
                raw_data["http"] = http_info

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="pcap",
            event_type=event_type,
            network=NetworkInfo(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="TCP",
            ),
            action=action,
            raw_data=raw_data,
            tags=tags,
        )

    def _parse_udp(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> NormalizedEvent | None:
        """解析 UDP 数据报。"""
        if len(payload) < 8:
            return None

        src_port, dst_port, length, _checksum = struct.unpack("!HHHH", payload[:8])
        udp_payload = payload[8:]

        event_type = "network_packet"
        action = "udp_packet"
        tags = ["pcap", "udp"]
        raw_data: dict[str, object] = {
            "packet_length": len(payload),
            "udp_length": length,
        }

        # DNS 检测
        if src_port == _DNS_PORT or dst_port == _DNS_PORT:
            dns_info = self._extract_dns_info(udp_payload)
            if dns_info:
                event_type = "dns_query"
                action = "dns_query"
                tags.append("dns")
                raw_data["dns"] = dns_info

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="pcap",
            event_type=event_type,
            network=NetworkInfo(
                src_ip=src_ip,
                src_port=src_port,
                dst_ip=dst_ip,
                dst_port=dst_port,
                protocol="UDP",
            ),
            action=action,
            raw_data=raw_data,
            tags=tags,
        )

    def _parse_icmp(
        self,
        payload: bytes,
        src_ip: str,
        dst_ip: str,
        timestamp: datetime,
    ) -> NormalizedEvent | None:
        """解析 ICMP 包。"""
        if len(payload) < 4:
            return None

        icmp_type = payload[0]
        icmp_code = payload[1]
        icmp_payload = payload[4:] if len(payload) > 4 else b""

        return NormalizedEvent(
            timestamp=timestamp,
            source_type="network_traffic",
            source="pcap",
            event_type="icmp_packet",
            network=NetworkInfo(
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol="ICMP",
            ),
            action="icmp_packet",
            raw_data={
                "packet_length": len(payload),
                "icmp_type": icmp_type,
                "icmp_code": icmp_code,
                "payload_length": len(icmp_payload),
                "payload_hex": icmp_payload.hex()[:200],  # 截断防止过大
            },
            tags=["pcap", "icmp"],
        )

    def _extract_http_info(self, payload: bytes) -> dict[str, object]:
        """从 TCP payload 中提取基础 HTTP 信息。"""
        if not payload:
            return {}
        try:
            text = payload.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            return {}

        lines = text.split("\r\n")
        if not lines:
            return {}

        first_line = lines[0]
        info: dict[str, object] = {}

        # HTTP 请求行: GET /path HTTP/1.1
        parts = first_line.split(" ", 2)
        if len(parts) >= 3 and parts[2].startswith("HTTP/"):
            info["method"] = parts[0]
            info["uri"] = parts[1]
            info["version"] = parts[2]
        # HTTP 响应行: HTTP/1.1 200 OK
        elif len(parts) >= 2 and parts[0].startswith("HTTP/"):
            info["version"] = parts[0]
            info["status_code"] = int(parts[1]) if parts[1].isdigit() else 0
            if len(parts) >= 3:
                info["status_reason"] = parts[2]
        else:
            return {}

        # 解析 headers
        headers: dict[str, str] = {}
        for line in lines[1:]:
            if not line or ":" not in line:
                if not line:
                    break
                continue
            key, _, val = line.partition(":")
            headers[key.strip().lower()] = val.strip()

        if "host" in headers:
            info["host"] = headers["host"]
        if "user-agent" in headers:
            info["user_agent"] = headers["user-agent"]
        if "content-type" in headers:
            info["content_type"] = headers["content-type"]
        if "content-length" in headers:
            try:
                info["content_length"] = int(headers["content-length"])
            except ValueError:
                pass

        return info

    def _extract_dns_info(self, payload: bytes) -> dict[str, object]:
        """从 UDP payload 中提取基础 DNS 信息。"""
        if len(payload) < 12:
            return {}

        try:
            tid, flags, qdcount, ancount, nscount, arcount = struct.unpack(
                "!HHHHHH", payload[:12]
            )
        except struct.error:
            return {}

        info: dict[str, object] = {
            "transaction_id": tid,
            "flags": flags,
            "is_response": bool(flags & 0x8000),
            "qdcount": qdcount,
            "ancount": ancount,
        }

        # 解析第一个 question
        offset = 12
        question = self._parse_dns_name(payload, offset)
        if question is not None:
            qname, new_offset = question
            info["query_name"] = qname
            offset = new_offset
            if offset + 4 <= len(payload):
                qtype, qclass = struct.unpack("!HH", payload[offset:offset + 4])
                info["query_type"] = self._dns_type_name(qtype)
                info["query_class"] = qclass

        return info

    def _parse_dns_name(
        self,
        data: bytes,
        offset: int,
    ) -> tuple[str, int] | None:
        """解析 DNS 域名（支持指针压缩）。"""
        labels: list[str] = []
        jumped = False
        original_offset = offset
        max_jumps = 10
        jumps = 0

        while offset < len(data) and jumps <= max_jumps:
            length = data[offset]
            if length == 0:
                offset += 1
                break
            if (length & 0xC0) == 0xC0:
                # 指针
                if offset + 1 >= len(data):
                    return None
                pointer = ((length & 0x3F) << 8) | data[offset + 1]
                if not jumped:
                    original_offset = offset + 2
                offset = pointer
                jumped = True
                jumps += 1
                continue
            if offset + length + 1 > len(data):
                return None
            try:
                label = data[offset + 1:offset + 1 + length].decode("ascii", errors="replace")
            except Exception:  # noqa: BLE001
                return None
            labels.append(label)
            offset += length + 1

        if not labels:
            return None

        final_offset = original_offset if jumped else offset
        return ".".join(labels), final_offset

    @staticmethod
    def _dns_type_name(qtype: int) -> str:
        """DNS 查询类型转名称。"""
        types = {
            1: "A", 2: "NS", 5: "CNAME", 6: "SOA",
            12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
            33: "SRV", 65: "HTTPS",
        }
        return types.get(qtype, f"TYPE{qtype}")

    @staticmethod
    def _proto_name(proto: int) -> str:
        """协议号转名称。"""
        names = {
            1: "ICMP", 6: "TCP", 17: "UDP", 58: "ICMPv6",
        }
        return names.get(proto, f"PROTO{proto}")
