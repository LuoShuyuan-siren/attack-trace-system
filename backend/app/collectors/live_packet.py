from __future__ import annotations

import socket
from datetime import datetime, timezone
from uuid import uuid4

from app.schemas.event import NetworkInfo, NormalizedEvent


class LivePacketCollector:
    """Optional live NIC capture using Scapy, normalized like PCAP events."""

    def __init__(self, *, interface: str | None = None, timeout: int = 2, count: int = 100) -> None:
        self.interface = interface
        self.timeout = timeout
        self.count = count

    def collect_once(self) -> list[NormalizedEvent]:
        try:
            from scapy.all import sniff
        except ImportError:
            return []
        try:
            packets = sniff(iface=self.interface, timeout=self.timeout, count=self.count, store=True)
        except (OSError, PermissionError):
            return []
        return [event for packet in packets if (event := self._packet_event(packet))]

    def _packet_event(self, packet: object) -> NormalizedEvent | None:
        try:
            from scapy.layers.inet import ICMP, IP, TCP, UDP
        except ImportError:
            return None
        if not packet.haslayer(IP):
            return None
        ip = packet[IP]
        protocol = "ICMP" if packet.haslayer(ICMP) else "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else str(ip.proto)
        source_port = getattr(packet, "sport", None)
        target_port = getattr(packet, "dport", None)
        event_type = "icmp_packet" if protocol == "ICMP" else "network_connection"
        raw = {"packet_length": len(packet), "capture": "live"}
        if protocol == "TCP":
            tcp = packet[TCP]
            payload = bytes(tcp.payload)
            raw.update({
                "tcp_seq": int(tcp.seq),
                "tcp_ack": int(tcp.ack),
                "tcp_flags": str(tcp.flags),
                "tcp_window": int(tcp.window),
                "tcp_payload_length": len(payload),
            })
            if payload:
                raw["tcp_payload_hex"] = payload[:4096].hex()
        elif protocol == "UDP":
            raw["udp_payload_length"] = len(bytes(packet[UDP].payload))
        if event_type == "icmp_packet":
            raw.update({"icmp_type": int(packet[ICMP].type), "icmp_code": int(packet[ICMP].code), "payload_length": len(bytes(packet[ICMP].payload))})
        return NormalizedEvent(
            event_id=f"evt-live-{uuid4()}",
            timestamp=datetime.now(timezone.utc),
            source_type="network_traffic",
            source="live_capture",
            event_type=event_type,
            network=NetworkInfo(src_ip=ip.src, src_port=source_port, dst_ip=ip.dst, dst_port=target_port, protocol=protocol),
            action="capture_packet",
            raw_data=raw,
            tags=["collector", "live_capture", protocol.lower()],
        )
