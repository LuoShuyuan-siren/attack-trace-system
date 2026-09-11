"""网络流量 Parser 测试数据生成器。

生成小型、可重复的测试数据，不依赖大型 PCAP 文件。
"""

import struct
import socket
from pathlib import Path


def create_minimal_pcap(filepath: Path) -> None:
    """生成一个最小合法的 PCAP 文件，包含若干 TCP/UDP/ICMP 包。"""

    # PCAP 全局头 (24 bytes)
    magic = 0xA1B2C3D4
    version_major = 2
    version_minor = 4
    thiszone = 0
    sigfigs = 0
    snaplen = 65535
    linktype = 1  # Ethernet

    global_header = struct.pack(
        "<IHHiIII",
        magic,
        version_major,
        version_minor,
        thiszone,
        sigfigs,
        snaplen,
        linktype,
    )

    packets = []

    # TCP 包: 192.168.1.1 -> 10.0.0.1, port 12345 -> 80
    tcp_pkt = build_ethernet_ipv4_tcp_packet(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.1",
        src_port=12345,
        dst_port=80,
        flags=0x18,  # PSH+ACK
        payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n",
    )
    packets.append((1000000000, tcp_pkt))  # ts=1000000000

    # UDP/DNS 包: 192.168.1.1 -> 8.8.8.8, port 53
    dns_pkt = build_ethernet_ipv4_udp_dns_packet(
        src_ip="192.168.1.1",
        dst_ip="8.8.8.8",
        src_port=54321,
        dst_port=53,
        domain="example.com",
        qtype=1,  # A
    )
    packets.append((1000000001, dns_pkt))

    # ICMP 包: 192.168.1.1 -> 10.0.0.2
    icmp_pkt = build_ethernet_ipv4_icmp_packet(
        src_ip="192.168.1.1",
        dst_ip="10.0.0.2",
        icmp_type=8,  # Echo Request
        icmp_code=0,
        payload=b"abcdefghijklmnop",
    )
    packets.append((1000000002, icmp_pkt))

    with open(filepath, "wb") as f:
        f.write(global_header)
        for ts_sec, pkt_data in packets:
            ts_usec = 0
            incl_len = len(pkt_data)
            orig_len = len(pkt_data)
            pkt_header = struct.pack(
                "<IIII",
                ts_sec,
                ts_usec,
                incl_len,
                orig_len,
            )
            f.write(pkt_header)
            f.write(pkt_data)


def build_ethernet_ipv4_tcp_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    flags: int = 0x18,
    payload: bytes = b"",
) -> bytes:
    """构造一个 Ethernet + IPv4 + TCP 包。"""
    # TCP 头 (20 bytes minimum) + payload
    tcp_header = struct.pack(
        "!HHIIBBHHH",
        src_port,
        dst_port,
        0,  # seq
        0,  # ack
        (5 << 4),  # data offset (5 * 4 = 20 bytes)
        flags,
        8192,  # window
        0,  # checksum (simplified)
        0,  # urgent pointer
    )
    tcp_data = tcp_header + payload

    # IPv4 header (20 bytes)
    total_length = 20 + len(tcp_data)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,  # version=4, IHL=5
        0,  # DSCP/ECN
        total_length,
        0,  # identification
        0,  # flags/fragment
        64,  # TTL
        6,  # protocol = TCP
        0,  # checksum (simplified)
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    # Ethernet header (14 bytes)
    eth_header = (
        b"\x00\x11\x22\x33\x44\x55"  # dst MAC
        b"\x66\x77\x88\x99\xaa\xbb"  # src MAC
        + struct.pack("!H", 0x0800)  # EtherType = IPv4
    )

    return eth_header + ip_header + tcp_data


def build_ethernet_ipv4_udp_dns_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    domain: str,
    qtype: int = 1,
) -> bytes:
    """构造一个 Ethernet + IPv4 + UDP + DNS 包。"""
    # DNS query
    dns_header = struct.pack(
        "!HHHHHH",
        0x1234,  # transaction ID
        0x0100,  # flags (standard query, recursion desired)
        1,  # qdcount
        0,  # ancount
        0,  # nscount
        0,  # arcount
    )

    # DNS question
    question = b""
    for label in domain.split("."):
        question += struct.pack("B", len(label)) + label.encode("ascii")
    question += b"\x00"  # end of name
    question += struct.pack("!HH", qtype, 1)  # qtype, qclass=IN

    dns_data = dns_header + question

    # UDP header (8 bytes)
    udp_length = 8 + len(dns_data)
    udp_header = struct.pack(
        "!HHHH",
        src_port,
        dst_port,
        udp_length,
        0,  # checksum (simplified)
    )
    udp_data = udp_header + dns_data

    # IPv4 header
    total_length = 20 + len(udp_data)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        17,  # protocol = UDP
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    # Ethernet header
    eth_header = (
        b"\x00\x11\x22\x33\x44\x55"
        b"\x66\x77\x88\x99\xaa\xbb"
        + struct.pack("!H", 0x0800)
    )

    return eth_header + ip_header + udp_data


def build_ethernet_ipv4_icmp_packet(
    src_ip: str,
    dst_ip: str,
    icmp_type: int,
    icmp_code: int,
    payload: bytes = b"",
) -> bytes:
    """构造一个 Ethernet + IPv4 + ICMP 包。"""
    # ICMP header (4 bytes) + payload
    icmp_header = struct.pack(
        "!BBH",
        icmp_type,
        icmp_code,
        0,  # checksum (simplified)
    )
    icmp_data = icmp_header + payload

    # IPv4 header
    total_length = 20 + len(icmp_data)
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        total_length,
        0,
        0,
        64,
        1,  # protocol = ICMP
        0,
        socket.inet_aton(src_ip),
        socket.inet_aton(dst_ip),
    )

    # Ethernet header
    eth_header = (
        b"\x00\x11\x22\x33\x44\x55"
        b"\x66\x77\x88\x99\xaa\xbb"
        + struct.pack("!H", 0x0800)
    )

    return eth_header + ip_header + icmp_data
