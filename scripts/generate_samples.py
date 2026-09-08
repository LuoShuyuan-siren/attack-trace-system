"""生成成员5 模块的实际样本输出。

真实运行 3 个 Parser + 4 个 Analyzer，把代码当前实际产生的
NormalizedEvent 与 DetectionResult 序列化为 JSON，供文档/演示/评审使用。

覆盖类型（混合正常与攻击）：
- PcapParser: TCP/HTTP、UDP/DNS、ICMP
- ZeekParser: conn.log、dns.log、http.log、ssl.log
- SuricataParser: flow、dns、http、alert、tls

Analyzer 触发：
- DnsAnalyzer: 正常 + DNS 隧道（TXT + 高频 + 高熵 + 长域名 + NXDOMAIN）
- HttpAnalyzer: 正常 + Beacon + 长 URI + 大上传 + 可疑 UA
- IcmpAnalyzer: 正常 + ICMP 隧道（高频 + 大 payload + 周期性）
- ConnectionAnalyzer: 正常 + 端口扫描 + 长连接

输出：docs/sample_data.json
"""

import json
import random
import string
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

# 把 backend 加入 sys.path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from app.parsers.traffic import PcapParser, ZeekParser, SuricataParser
from app.analyzers.traffic import (
    DnsAnalyzer, HttpAnalyzer, IcmpAnalyzer, ConnectionAnalyzer,
)
from app.schemas.event import NetworkInfo, NormalizedEvent


def event_to_dict(e: NormalizedEvent) -> dict:
    """把 NormalizedEvent 序列化为可读 dict。"""
    return {
        "event_id": e.event_id,
        "timestamp": e.timestamp.isoformat(),
        "source_type": e.source_type,
        "source": e.source,
        "event_type": e.event_type,
        "host": e.host.model_dump(),
        "network": e.network.model_dump() if e.network else None,
        "action": e.action,
        "raw_data": e.raw_data,
        "severity": e.severity,
        "tags": e.tags,
        "attack": e.attack.model_dump() if e.attack else None,
    }


def detection_to_dict(d) -> dict:
    """把 DetectionResult 序列化为可读 dict。"""
    return {
        "detection_id": d.detection_id,
        "timestamp": d.timestamp.isoformat(),
        "analyzer": d.analyzer,
        "detection_type": d.detection_type,
        "title": d.title,
        "description": d.description,
        "severity": d.severity,
        "confidence": round(d.confidence, 3),
        "related_event_ids": d.related_event_ids,
        "attack_technique_id": d.attack_technique_id,
        "tags": d.tags,
        "evidence": d.evidence,
    }


# ====== 构造事件 ======

def make_dns_event(timestamp, src_ip, query, qtype="A", rcode="NOERROR") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        source_type="network_traffic",
        source="sample",
        event_type="dns_query",
        network=NetworkInfo(src_ip=src_ip, dst_ip="8.8.8.8", src_port=54321, dst_port=53, protocol="udp"),
        action="dns_query",
        raw_data={"dns": {"query": query, "query_type": qtype, "rcode": rcode}},
        tags=["dns"],
    )


def make_http_event(timestamp, src_ip, dst_ip, dst_port, method, host, uri,
                    user_agent, status=200, body_len=0) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        source_type="network_traffic",
        source="sample",
        event_type="http_request",
        network=NetworkInfo(src_ip=src_ip, dst_ip=dst_ip, src_port=12345,
                            dst_port=dst_port, protocol="tcp"),
        action="http_communication",
        raw_data={"http": {
            "method": method, "host": host, "uri": uri,
            "user_agent": user_agent, "status_code": status,
            "content_length": body_len,
        }},
        tags=["http"],
    )


def make_icmp_event(timestamp, src_ip, dst_ip, icmp_type=8, code=0, payload=b"") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        source_type="network_traffic",
        source="sample",
        event_type="icmp_packet",
        network=NetworkInfo(src_ip=src_ip, dst_ip=dst_ip, protocol="icmp"),
        action="icmp_packet",
        # ICMP analyzer 在 raw_data 顶层读取 payload_length / payload_hex / icmp_type / icmp_code
        raw_data={
            "payload_length": len(payload),
            "payload_hex": payload.hex(),
            "icmp_type": icmp_type,
            "icmp_code": code,
            "icmp": {
                "type": icmp_type, "code": code,
                "payload_hex": payload.hex(),
            },
        },
        tags=["icmp"],
    )


def make_flow_event(timestamp, src_ip, dst_ip, dst_port, proto="tcp") -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        source_type="network_traffic",
        source="sample",
        event_type="network_flow",
        network=NetworkInfo(src_ip=src_ip, dst_ip=dst_ip, src_port=40000,
                            dst_port=dst_port, protocol=proto),
        action="flow_recorded",
        raw_data={},
        tags=["flow"],
    )


# ====== 场景构造 ======

def scenario_normal_dns():
    """场景1：正常 DNS 解析（10 秒内 3 个不同域名）。"""
    base = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)
    return [
        make_dns_event(base + timedelta(seconds=0), "192.168.1.10", "example.com"),
        make_dns_event(base + timedelta(seconds=3), "192.168.1.10", "google.com"),
        make_dns_event(base + timedelta(seconds=7), "192.168.1.10", "github.com"),
    ]


def scenario_dns_tunnel():
    """场景2：DNS 隧道（40 个 TXT 查询到同一域名的随机高熵子域）。"""
    base = datetime(2026, 9, 8, 11, 0, 0, tzinfo=timezone.utc)
    random.seed(42)
    events = []
    for i in range(40):
        subdomain = "".join(random.choices(string.ascii_lowercase + string.digits, k=40))
        events.append(make_dns_event(
            base + timedelta(seconds=i),
            "192.168.1.100",
            f"{subdomain}.tunnel.example",
            qtype="TXT",
        ))
    return events


def scenario_dns_nxdomain():
    """场景3：NXDOMAIN 风暴（10 次全部 NXDOMAIN，疑似 DGA）。"""
    base = datetime(2026, 9, 8, 12, 0, 0, tzinfo=timezone.utc)
    random.seed(7)
    events = []
    for i in range(10):
        domain = "".join(random.choices(string.ascii_lowercase, k=15)) + ".xyz"
        events.append(make_dns_event(
            base + timedelta(seconds=i),
            "192.168.1.200",
            domain,
            rcode="NXDOMAIN",
        ))
    return events


def scenario_normal_http():
    """场景4：正常 HTTP 浏览（分散时间戳的 5 个 GET）。"""
    base = datetime(2026, 9, 8, 13, 0, 0, tzinfo=timezone.utc)
    return [
        make_http_event(base + timedelta(seconds=0), "192.168.1.10", "93.184.216.34", 80,
                        "GET", "example.com", "/", "Mozilla/5.0"),
        make_http_event(base + timedelta(seconds=30), "192.168.1.10", "93.184.216.34", 80,
                        "GET", "example.com", "/about", "Mozilla/5.0"),
        make_http_event(base + timedelta(seconds=60), "192.168.1.10", "140.82.114.4", 443,
                        "GET", "github.com", "/explore", "Mozilla/5.0"),
        make_http_event(base + timedelta(seconds=90), "192.168.1.10", "140.82.114.4", 443,
                        "GET", "github.com", "/topics", "Mozilla/5.0"),
        make_http_event(base + timedelta(seconds=120), "192.168.1.10", "142.250.190.78", 443,
                        "GET", "google.com", "/", "Mozilla/5.0"),
    ]


def scenario_http_beacon():
    """场景5：HTTP Beacon（每隔 60 秒 1 次 GET，共 10 次到同一 C2）。"""
    base = datetime(2026, 9, 8, 14, 0, 0, tzinfo=timezone.utc)
    return [
        make_http_event(base + timedelta(seconds=i * 60), "192.168.1.100", "203.0.113.10", 80,
                        "GET", "evil-c2.example", f"/beacon/{i}", "Mozilla/5.0")
        for i in range(10)
    ]


def scenario_http_suspicious():
    """场景6：HTTP 可疑行为（curl 大文件上传 + 长 URI + 可疑 UA）。"""
    base = datetime(2026, 9, 8, 15, 0, 0, tzinfo=timezone.utc)
    long_uri = "/" + "a" * 600  # 异常长 URI
    return [
        # 可疑 UA：sqlmap
        make_http_event(base + timedelta(seconds=0), "192.168.1.50", "10.0.0.5", 80,
                        "GET", "target.example", "/admin?id=1' OR 1=1--",
                        "sqlmap/1.5"),
        # 长 URI + curl 大文件上传
        make_http_event(base + timedelta(seconds=5), "192.168.1.50", "10.0.0.5", 80,
                        "POST", "target.example", long_uri,
                        "curl/7.68.0", body_len=15 * 1024 * 1024),
    ]


def scenario_normal_icmp():
    """场景7：正常 ping（5 个等间隔小 payload ICMP echo）。"""
    base = datetime(2026, 9, 8, 16, 0, 0, tzinfo=timezone.utc)
    return [
        make_icmp_event(base + timedelta(seconds=i), "192.168.1.10", "8.8.8.8",
                        icmp_type=8, payload=b"abcdefghijklmnop")
        for i in range(5)
    ]


def scenario_icmp_tunnel():
    """场景8：ICMP 隧道（高频 + 大 payload + 周期性 + 双向）。"""
    base = datetime(2026, 9, 8, 17, 0, 0, tzinfo=timezone.utc)
    events = []
    # 周期性 + 大 payload（200 bytes，远超 64 阈值）+ 高频
    # payload 用伪随机数据模拟加密载荷，提高熵值
    random.seed(99)
    for i in range(15):
        payload = bytes(random.randint(0, 255) for _ in range(200))
        events.append(make_icmp_event(
            base + timedelta(seconds=i),
            "192.168.1.100", "203.0.113.20",
            payload=payload,
        ))
    # 双向响应（高熵大 payload）
    for i in range(10):
        payload = bytes(random.randint(0, 255) for _ in range(200))
        events.append(make_icmp_event(
            base + timedelta(seconds=i * 2, milliseconds=500),
            "203.0.113.20", "192.168.1.100",
            icmp_type=0,  # Echo Reply
            payload=payload,
        ))
    return events


def scenario_port_scan():
    """场景9：端口扫描（同一源访问 25 个不同端口）。"""
    base = datetime(2026, 9, 8, 18, 0, 0, tzinfo=timezone.utc)
    return [
        make_flow_event(base + timedelta(milliseconds=i * 100),
                        "192.168.1.66", "10.0.0.99", dst_port=port)
        for i, port in enumerate(range(20, 45))  # 25 个不同端口
    ]


def scenario_long_connection():
    """场景10：长连接（连接跨度超过 1 小时）。"""
    start = datetime(2026, 9, 8, 9, 0, 0, tzinfo=timezone.utc)
    return [
        make_flow_event(start, "192.168.1.10", "10.0.0.5", 443),
        make_flow_event(start + timedelta(hours=1, minutes=30), "192.168.1.10", "10.0.0.5", 443),
    ]


def scenario_ssl_tls():
    """场景11：Zeek/Suricata 风格的 SSL + TLS 握手（ConnectionAnalyzer 仅统计）。"""
    base = datetime(2026, 9, 8, 19, 0, 0, tzinfo=timezone.utc)
    return [
        NormalizedEvent(
            timestamp=base,
            source_type="network_traffic",
            source="zeek",
            event_type="tls_handshake",
            network=NetworkInfo(src_ip="192.168.1.10", dst_ip="10.0.0.5",
                                src_port=50000, dst_port=443, protocol="tcp"),
            action="tls_handshake",
            raw_data={"tls": {
                "subject": "CN=www.example.com",
                "issuerdn": "CN=Let's Encrypt Authority X3",
                "sni": "www.example.com",
                "version": "TLS 1.2",
            }},
            tags=["ssl", "tls"],
        ),
    ]


def scenario_uncommon_ports():
    """场景 11b：非常用端口通信（同一源访问多个非常用端口）。"""
    base = datetime(2026, 9, 8, 19, 30, 0, tzinfo=timezone.utc)
    # 22, 23, 25, 445, 3306, 3389, 5432 等都是非常用端口白名单外
    uncommon = [22, 23, 445, 3306, 3389, 5432]
    return [
        make_flow_event(base + timedelta(seconds=i),
                        "192.168.1.77", "10.0.0.50", dst_port=p)
        for i, p in enumerate(uncommon)
    ]


def scenario_high_frequency_http():
    """场景 11c：高频 HTTP（非隐蔽信道，触发 anomaly 级告警）。"""
    base = datetime(2026, 9, 8, 20, 0, 0, tzinfo=timezone.utc)
    events = []
    # 70 个 GET，跨越约 60 秒 → 速率 ≈ 70/min，超过 60/min 阈值
    for i in range(70):
        events.append(make_http_event(
            base + timedelta(milliseconds=i * 850),
            "192.168.1.30", "10.0.0.20", 80,
            "GET", "api.example", f"/v1/data/{i}", "Mozilla/5.0"))
    return events


def scenario_high_frequency_icmp():
    """场景 11d：高频 ICMP（无 payload 异常，单纯触发高频 anomaly）。"""
    base = datetime(2026, 9, 8, 20, 30, 0, tzinfo=timezone.utc)
    events = []
    for i in range(25):
        events.append(make_icmp_event(
            base + timedelta(milliseconds=i * 2000),
            "192.168.1.40", "8.8.8.8",
            payload=b"ping",
        ))
    return events


def scenario_pcap_real():
    """场景12：用 fixtures 的真实 PCAP 生成器跑出真实事件。"""
    from tests.fixtures.pcap_generator import create_minimal_pcap
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as f:
        pcap_path = Path(f.name)
    create_minimal_pcap(pcap_path)
    events = PcapParser().parse(pcap_path)
    pcap_path.unlink()
    return events


def scenario_zeek_real():
    """场景13：用 fixtures 真实 Zeek 生成器跑出真实事件。"""
    from tests.fixtures.zeek_generator import create_all_zeek_logs
    with tempfile.TemporaryDirectory() as d:
        dpath = Path(d)
        create_all_zeek_logs(dpath)
        events = ZeekParser().parse(dpath)
    return events


def scenario_suricata_real():
    """场景14：用 fixtures 真实 Suricata 生成器跑出真实事件。"""
    from tests.fixtures.suricata_generator import create_eve_json
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
        path = Path(f.name)
    create_eve_json(path)
    events = SuricataParser().parse(path)
    path.unlink()
    return events


# ====== 主流程 ======

def main():
    # 构造所有场景
    all_events = []
    scenario_meta = []  # (scenario_name, event_indices_in_all_events)

    def add(name, events):
        start = len(all_events)
        all_events.extend(events)
        scenario_meta.append((name, list(range(start, len(all_events)))))

    add("正常 DNS 解析",            scenario_normal_dns())
    add("DNS 隧道（攻击）",         scenario_dns_tunnel())
    add("NXDOMAIN 风暴（攻击）",     scenario_dns_nxdomain())
    add("正常 HTTP 浏览",           scenario_normal_http())
    add("HTTP Beacon（攻击）",      scenario_http_beacon())
    add("HTTP 可疑行为（攻击）",     scenario_http_suspicious())
    add("正常 ICMP（ping）",        scenario_normal_icmp())
    add("ICMP 隧道（攻击）",        scenario_icmp_tunnel())
    add("端口扫描（攻击）",         scenario_port_scan())
    add("长连接（攻击）",           scenario_long_connection())
    add("SSL/TLS 握手",             scenario_ssl_tls())
    add("非常用端口通信（攻击）",    scenario_uncommon_ports())
    add("高频 HTTP（异常）",         scenario_high_frequency_http())
    add("高频 ICMP（异常）",         scenario_high_frequency_icmp())
    add("PCAP 真实解析",            scenario_pcap_real())
    add("Zeek 真实解析",            scenario_zeek_real())
    add("Suricata 真实解析",        scenario_suricata_real())

    # 跑 4 个 Analyzer
    analyzers = [
        ("dns_analyzer",       DnsAnalyzer()),
        ("http_analyzer",      HttpAnalyzer()),
        ("icmp_analyzer",      IcmpAnalyzer()),
        ("connection_analyzer", ConnectionAnalyzer()),
    ]

    print(f"总事件数: {len(all_events)}")
    print(f"分析器数: {len(analyzers)}")
    print()

    all_detections = {}
    for name, analyzer in analyzers:
        results = analyzer.analyze(all_events)
        all_detections[name] = results
        print(f"  {name}: 触发 {len(results)} 条告警")

    # 限制 NormalizedEvent 输出：每类事件保留代表性样本（最多 25 条）
    # 让样本文件大小可控，但覆盖所有 Parser/Analyzer 关心的 event_type
    sample_events = []
    seen_types: dict[str, int] = {}
    for e in all_events:
        etype = e.event_type
        if seen_types.get(etype, 0) >= 5:  # 每种 event_type 最多 5 条
            continue
        sample_events.append(event_to_dict(e))
        seen_types[etype] = seen_types.get(etype, 0) + 1

    # 确保 pcap source 有至少一条样本（PCAP parser 输出 tcp_packet/udp_dns/icmp_packet 等）
    pcap_seen = any(e["source"] == "pcap" for e in sample_events)
    if not pcap_seen:
        for e in all_events:
            if e.source == "pcap":
                sample_events.append(event_to_dict(e))
                break

    # DetectionResult 全部保留（25 条左右）
    sample_detections = []
    for name, results in all_detections.items():
        for r in results:
            sample_detections.append(detection_to_dict(r))

    # 输出文档
    output = {
        "summary": {
            "total_events": len(all_events),
            "total_detections": len(sample_detections),
            "scenarios": [{"name": n, "event_count": len(idxs)} for n, idxs in scenario_meta],
            "analyzer_counts": {n: len(rs) for n, rs in all_detections.items()},
        },
        "normalized_events": sample_events,
        "detection_results": sample_detections,
    }

    out_path = ROOT / "docs" / "sample_data.json"
    out_path.write_text(json.dumps(output, ensure_ascii=False, indent=2, default=str))
    print(f"\n输出: {out_path}")
    print(f"  NormalizedEvent（代表性样本）: {len(sample_events)} 条")
    print(f"  DetectionResult: {len(sample_detections)} 条")


if __name__ == "__main__":
    main()
