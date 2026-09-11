import pytest

from app.collectors.live_packet import LivePacketCollector


scapy = pytest.importorskip("scapy.all")
from scapy.layers.inet import IP, TCP, UDP


def test_live_tcp_packet_contains_reassembly_fields() -> None:
    packet = IP(src="10.0.0.10", dst="10.0.0.20") / TCP(sport=50000, dport=80, seq=100, ack=1, flags="PA") / b"GET / HTTP/1.1\r\n"

    event = LivePacketCollector()._packet_event(packet)

    assert event is not None
    assert event.network.protocol == "TCP"
    assert event.raw_data["tcp_seq"] == 100
    assert event.raw_data["tcp_payload_length"] > 0
    assert bytes.fromhex(event.raw_data["tcp_payload_hex"]).startswith(b"GET")


def test_live_udp_packet_contains_payload_length() -> None:
    packet = IP(src="10.0.0.10", dst="8.8.8.8") / UDP(sport=53000, dport=53) / b"dns"

    event = LivePacketCollector()._packet_event(packet)

    assert event is not None
    assert event.network.protocol == "UDP"
    assert event.raw_data["udp_payload_length"] == 3
