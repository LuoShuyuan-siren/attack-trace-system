from datetime import datetime, timezone

from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent
from app.services.network_context import NetworkContextService


def _net_event(*, event_id: str, src_ip: str, dst_ip: str, query: str, dt: datetime) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=dt,
        source_type="network_traffic",
        source="zeek",
        host=HostInfo(hostname="WEB01", ip=src_ip, os="windows"),
        event_type="dns_query",
        network=NetworkInfo(src_ip=src_ip, dst_ip=dst_ip, protocol="udp", dst_port=53),
        action="query",
        raw_data={"dns": {"query": query}},
    )


def test_network_context_builds_sessions_and_flags_covert_channel() -> None:
    service = NetworkContextService()
    dt = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)

    events = [
        _net_event(
            event_id="evt-net-1",
            src_ip="10.0.0.10",
            dst_ip="8.8.8.8",
            query="x7k9m1s2a5d6f8g9h1n2p3q4r5s6t7u8v9w0.example.com",
            dt=dt,
        ),
        _net_event(
            event_id="evt-net-2",
            src_ip="10.0.0.10",
            dst_ip="8.8.8.8",
            query="x7k9m1s2a5d6f8g9h1n2p3q4r5s6t7u8v9w0.example.com",
            dt=dt,
        ),
    ]

    sessions = service.reconstruct_sessions(events)
    assert len(sessions) == 1
    assert sessions[0]["src_ip"] == "10.0.0.10"

    covert = service.summarize_covert_channels(events)
    assert covert["count"] >= 1
    assert any(item["src_ip"] == "10.0.0.10" for item in covert["suspicious_domains"])


def test_network_context_merges_reverse_flow_and_summarizes_tcp_state() -> None:
    service = NetworkContextService()
    start = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
    events = [
        NormalizedEvent(
            timestamp=start,
            source_type="network_traffic",
            source="pcap",
            host=HostInfo(hostname="WEB01"),
            event_type="network_connection",
            network=NetworkInfo(src_ip="10.0.0.10", src_port=50000, dst_ip="10.0.0.20", dst_port=443, protocol="tcp"),
            action="packet",
            raw_data={"packet_length": 100, "tcp_flags": "SYN"},
        ),
        NormalizedEvent(
            timestamp=start,
            source_type="network_traffic",
            source="pcap",
            host=HostInfo(hostname="WEB01"),
            event_type="network_connection",
            network=NetworkInfo(src_ip="10.0.0.20", src_port=443, dst_ip="10.0.0.10", dst_port=50000, protocol="TCP"),
            action="packet",
            raw_data={
                "packet_length": 80,
                "tcp_flags": "SYN ACK",
                "tls": {
                    "sni": "c2.example.com",
                    "cert_fingerprint": "sha256:demo",
                    "version": 771,
                    "ciphers": [4865, 4866],
                    "extensions": [0, 10, 11],
                    "supported_groups": [29, 23],
                    "point_formats": [0],
                },
            },
        ),
    ]

    sessions = service.reconstruct_sessions(events)

    assert len(sessions) == 1
    assert sessions[0]["event_count"] == 2
    assert sessions[0]["bytes"] == 180
    assert sessions[0]["state"] == "syn_ack"
    assert len(sessions[0]["direction_counts"]) == 2
    assert sessions[0]["tls_sni"] == ["c2.example.com"]
    assert sessions[0]["tls_certificates"] == ["sha256:demo"]
    assert len(sessions[0]["ja3"]) == 1


def test_network_context_reassembles_split_http_payload() -> None:
    service = NetworkContextService()
    base = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    for sequence, payload in ((100, b"GET "), (104, b"/x HTTP/1.1\r\n")):
        events.append(
            NormalizedEvent(
                timestamp=base,
                source_type="network_traffic",
                source="pcap",
                host=HostInfo(hostname="WEB01"),
                event_type="network_packet",
                network=NetworkInfo(src_ip="10.0.0.10", src_port=50000, dst_ip="10.0.0.20", dst_port=80, protocol="TCP"),
                action="tcp_packet",
                raw_data={"tcp_seq": sequence, "tcp_payload_hex": payload.hex()},
            )
        )

    session = service.reconstruct_sessions(events)[0]

    assert session["reassembled_payloads"][0]["preview"] == "GET /x HTTP/1.1\r\n"
    assert session["reassembled_payloads"][0]["application_protocol"] == "HTTP_REQUEST"
    assert session["reassembled_payloads"][0]["gaps"] == 0
    assert session["reassembled_payloads"][0]["out_of_order_segments"] == 0
    assert session["reassembled_payloads"][0]["retransmissions"] == 0


def test_network_context_reports_tcp_reordering_and_retransmission() -> None:
    service = NetworkContextService()
    timestamp = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
    events = []
    for sequence, payload in ((106, b"world"), (100, b"hello "), (100, b"hello ")):
        events.append(
            NormalizedEvent(
                timestamp=timestamp,
                source_type="network_traffic",
                source="pcap",
                host=HostInfo(hostname="WEB01"),
                event_type="network_packet",
                network=NetworkInfo(src_ip="10.0.0.10", src_port=50000, dst_ip="10.0.0.20", dst_port=80, protocol="TCP"),
                action="tcp_packet",
                raw_data={"tcp_seq": sequence, "tcp_payload_hex": payload.hex()},
            )
        )

    payload = service.reconstruct_sessions(events)[0]["reassembled_payloads"][0]

    assert payload["preview"] == "hello world"
    assert payload["out_of_order_segments"] == 2
    assert payload["retransmissions"] == 1
