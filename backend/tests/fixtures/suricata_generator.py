"""Suricata eve.json 测试数据生成器。"""

import json
from pathlib import Path


def create_eve_json(filepath: Path) -> None:
    """生成 Suricata eve.json 测试数据 (JSONL)。"""
    records = [
        # flow 事件
        {
            "timestamp": "2026-09-08T10:00:00.000000+0000",
            "event_type": "flow",
            "src_ip": "192.168.1.1",
            "src_port": 12345,
            "dest_ip": "10.0.0.1",
            "dest_port": 80,
            "proto": "TCP",
            "flow": {
                "pkts_toserver": 10,
                "pkts_toclient": 5,
                "bytes_toserver": 1500,
                "bytes_toclient": 3000,
                "start": "2026-09-08T10:00:00",
                "end": "2026-09-08T10:01:00",
                "state": "established",
                "age": 60,
            },
        },
        # dns 事件
        {
            "timestamp": "2026-09-08T10:00:01.000000+0000",
            "event_type": "dns",
            "src_ip": "192.168.1.1",
            "src_port": 54321,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": "query",
                "id": 0x1234,
                "rrname": "example.com",
                "rrtype": "A",
                "txid": 4660,
                "rcode": 0,
            },
        },
        # http 事件
        {
            "timestamp": "2026-09-08T10:00:02.000000+0000",
            "event_type": "http",
            "src_ip": "192.168.1.1",
            "src_port": 12345,
            "dest_ip": "10.0.0.1",
            "dest_port": 80,
            "proto": "TCP",
            "http": {
                "http_method": "GET",
                "hostname": "example.com",
                "url": "/",
                "http_user_agent": "Mozilla/5.0",
                "http_status": 200,
                "http_content_type": "text/html",
                "length": 500,
            },
        },
        # alert 事件
        {
            "timestamp": "2026-09-08T10:00:03.000000+0000",
            "event_type": "alert",
            "src_ip": "10.0.0.1",
            "src_port": 80,
            "dest_ip": "192.168.1.1",
            "dest_port": 12345,
            "proto": "TCP",
            "alert": {
                "action": "alert",
                "gid": 1,
                "signature_id": 2000001,
                "rev": 1,
                "signature": "ET POLICY Suspicious HTTP Request",
                "category": "A Network Trojan was Detected",
                "severity": 1,
            },
        },
        # tls 事件
        {
            "timestamp": "2026-09-08T10:00:04.000000+0000",
            "event_type": "tls",
            "src_ip": "192.168.1.2",
            "src_port": 23456,
            "dest_ip": "10.0.0.2",
            "dest_port": 443,
            "proto": "TCP",
            "tls": {
                "subject": "CN=www.example.com",
                "issuerdn": "CN=Let's Encrypt Authority X3",
                "fingerprint": "sha256:abcdef1234567890",
                "sni": "www.example.com",
                "version": "TLS 1.2",
            },
        },
    ]

    with open(filepath, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")


def create_dns_tunnel_eve(filepath: Path) -> None:
    """生成 DNS 隧道场景的 eve.json 测试数据。"""
    records = []
    for i in range(40):
        # 生成随机子域名
        import random
        import string
        random.seed(i)
        subdomain = "".join(random.choices(string.ascii_lowercase + string.digits, k=40))
        records.append({
            "timestamp": f"2026-09-08T10:00:{i:02d}.000000+0000",
            "event_type": "dns",
            "src_ip": "192.168.1.100",
            "src_port": 10000 + i,
            "dest_ip": "8.8.8.8",
            "dest_port": 53,
            "proto": "UDP",
            "dns": {
                "type": "query",
                "rrname": f"{subdomain}.evil-domain.com",
                "rrtype": "TXT",
                "txid": i,
                "rcode": 0,
            },
        })

    with open(filepath, "w", encoding="utf-8") as f:
        for record in records:
            f.write(json.dumps(record) + "\n")
