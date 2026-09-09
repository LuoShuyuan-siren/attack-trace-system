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
from app.schemas.event import (
    HostInfo,
    NetworkInfo,
    NormalizedEvent,
    SubjectInfo,
)


def event_to_dict(e: NormalizedEvent) -> dict:
    """把 NormalizedEvent 序列化为可读 dict。"""
    return {
        "event_id": e.event_id,
        "timestamp": e.timestamp.isoformat(),
        "source_type": e.source_type,
        "source": e.source,
        "event_type": e.event_type,
        "host": e.host.model_dump(),
        "subject": e.subject.model_dump() if e.subject else None,
        "object": e.object.model_dump() if e.object else None,
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
        "related_entity_ids": d.related_entity_ids,
        "attack_technique_id": d.attack_technique_id,
        "tags": d.tags,
        "evidence": d.evidence,
    }


# ====== 构造事件 ======

def make_dns_event(timestamp, src_ip, query, qtype="A", rcode="NOERROR",
                   host: HostInfo | None = None,
                   subject: SubjectInfo | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        source_type="network_traffic",
        source="sample",
        event_type="dns_query",
        host=host or HostInfo(ip=src_ip),
        subject=subject,
        network=NetworkInfo(src_ip=src_ip, dst_ip="8.8.8.8", src_port=54321, dst_port=53, protocol="udp"),
        action="dns_query",
        raw_data={"dns": {"query": query, "query_type": qtype, "rcode": rcode}},
        tags=["dns"],
    )


def make_http_event(timestamp, src_ip, dst_ip, dst_port, method, host_header, uri,
                    user_agent, status=200, body_len=0,
                    host: HostInfo | None = None,
                    subject: SubjectInfo | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        source_type="network_traffic",
        source="sample",
        event_type="http_request",
        host=host or HostInfo(ip=src_ip),
        subject=subject,
        network=NetworkInfo(src_ip=src_ip, dst_ip=dst_ip, src_port=12345,
                            dst_port=dst_port, protocol="tcp"),
        action="http_communication",
        raw_data={"http": {
            "method": method, "host": host_header, "uri": uri,
            "user_agent": user_agent, "status_code": status,
            "content_length": body_len,
        }},
        tags=["http"],
    )


def make_icmp_event(timestamp, src_ip, dst_ip, icmp_type=8, code=0, payload=b"",
                    host: HostInfo | None = None,
                    subject: SubjectInfo | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        source_type="network_traffic",
        source="sample",
        event_type="icmp_packet",
        host=host or HostInfo(ip=src_ip),
        subject=subject,
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


def make_flow_event(timestamp, src_ip, dst_ip, dst_port, proto="tcp",
                    host: HostInfo | None = None,
                    subject: SubjectInfo | None = None) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=timestamp,
        source_type="network_traffic",
        source="sample",
        event_type="network_flow",
        host=host or HostInfo(ip=src_ip),
        subject=subject,
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
    """场景2：DNS 隧道（40 个 TXT 查询到同一域名的随机高熵子域）。

    DNS 隧道（外传）：补齐 hostname + 进程上下文，便于跨源关联。
    """
    base = datetime(2026, 9, 8, 11, 0, 0, tzinfo=timezone.utc)
    random.seed(42)
    host = HostInfo(hostname="workstation-42", ip="192.168.1.100", os="Windows 10")
    subject = SubjectInfo(type="process", name="powershell.exe", pid=8812, user="bob")
    events = []
    for i in range(40):
        subdomain = "".join(random.choices(string.ascii_lowercase + string.digits, k=40))
        events.append(make_dns_event(
            base + timedelta(seconds=i),
            "192.168.1.100",
            f"{subdomain}.tunnel.example",
            qtype="TXT",
            host=host, subject=subject,
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
    host = HostInfo(hostname="workstation-01", ip="192.168.1.10", os="Windows 10")
    subject = SubjectInfo(type="process", name="chrome.exe", pid=4231, user="alice")
    return [
        make_http_event(base + timedelta(seconds=0), "192.168.1.10", "93.184.216.34", 80,
                        "GET", "example.com", "/", "Mozilla/5.0",
                        host=host, subject=subject),
        make_http_event(base + timedelta(seconds=30), "192.168.1.10", "93.184.216.34", 80,
                        "GET", "example.com", "/about", "Mozilla/5.0",
                        host=host, subject=subject),
        make_http_event(base + timedelta(seconds=60), "192.168.1.10", "140.82.114.4", 443,
                        "GET", "github.com", "/explore", "Mozilla/5.0",
                        host=host, subject=subject),
        make_http_event(base + timedelta(seconds=90), "192.168.1.10", "140.82.114.4", 443,
                        "GET", "github.com", "/topics", "Mozilla/5.0",
                        host=host, subject=subject),
        make_http_event(base + timedelta(seconds=120), "192.168.1.10", "142.250.190.78", 443,
                        "GET", "google.com", "/", "Mozilla/5.0",
                        host=host, subject=subject),
    ]


def scenario_http_beacon():
    """场景5：HTTP Beacon（每隔 60 秒 1 次 GET，共 10 次到同一 C2）。

    C2 场景：补齐 hostname + 进程上下文，便于跨源关联。
    """
    base = datetime(2026, 9, 8, 14, 0, 0, tzinfo=timezone.utc)
    host = HostInfo(hostname="workstation-42", ip="192.168.1.100", os="Windows 10")
    subject = SubjectInfo(type="process", name="rundll32.exe", pid=7104, user="bob")
    return [
        make_http_event(base + timedelta(seconds=i * 60), "192.168.1.100", "203.0.113.10", 80,
                        "GET", "evil-c2.example", f"/beacon/{i}", "Mozilla/5.0",
                        host=host, subject=subject)
        for i in range(10)
    ]


def scenario_http_suspicious():
    """场景6：HTTP 可疑行为（curl 大文件上传 + 长 URI + 可疑 UA）。

    外传场景：补齐 hostname + 进程上下文，便于跨源关联。
    """
    base = datetime(2026, 9, 8, 15, 0, 0, tzinfo=timezone.utc)
    long_uri = "/" + "a" * 600  # 异常长 URI
    host = HostInfo(hostname="workstation-07", ip="192.168.1.50", os="Windows 10")
    subject = SubjectInfo(type="process", name="curl.exe", pid=5512, user="bob")
    return [
        # 可疑 UA：sqlmap
        make_http_event(base + timedelta(seconds=0), "192.168.1.50", "10.0.0.5", 80,
                        "GET", "target.example", "/admin?id=1' OR 1=1--",
                        "sqlmap/1.5", host=host, subject=subject),
        # 长 URI + curl 大文件上传（外传）
        make_http_event(base + timedelta(seconds=5), "192.168.1.50", "10.0.0.5", 80,
                        "POST", "target.example", long_uri,
                        "curl/7.68.0", body_len=15 * 1024 * 1024,
                        host=host, subject=subject),
    ]


def scenario_normal_icmp():
    """场景7：正常 ping（5 个等间隔小 payload ICMP echo）。

    注：基线事件被 ICMP analyzer 误触为"隧道"，给同一 host/subject 上下文
    有助于跨源关联验证"误报 vs 真告警"。
    """
    base = datetime(2026, 9, 8, 16, 0, 0, tzinfo=timezone.utc)
    host = HostInfo(hostname="workstation-01", ip="192.168.1.10", os="Windows 10")
    subject = SubjectInfo(type="process", name="ping.exe", pid=7710, user="alice")
    return [
        make_icmp_event(base + timedelta(seconds=i), "192.168.1.10", "8.8.8.8",
                        icmp_type=8, payload=b"abcdefghijklmnop",
                        host=host, subject=subject)
        for i in range(5)
    ]


def scenario_icmp_tunnel():
    """场景8：ICMP 隧道（高频 + 大 payload + 周期性 + 双向）。

    ICMP 隧道（隐蔽信道）：双向两端都补齐 host/process，便于跨源关联。
    - 出站（被控端 → C2 基础设施）：host=workstation-42
    - 入站（C2 基础设施 → 被控端）：host=c2-server
    """
    base = datetime(2026, 9, 8, 17, 0, 0, tzinfo=timezone.utc)
    events = []
    # 周期性 + 大 payload（200 bytes，远超 64 阈值）+ 高频
    # payload 用伪随机数据模拟加密载荷，提高熵值
    random.seed(99)
    # 出站：被控端 → C2 基础设施
    src_host = HostInfo(hostname="workstation-42", ip="192.168.1.100", os="Windows 10")
    src_subject = SubjectInfo(type="process", name="svchost.exe", pid=992, user="bob")
    for i in range(15):
        payload = bytes(random.randint(0, 255) for _ in range(200))
        events.append(make_icmp_event(
            base + timedelta(seconds=i),
            "192.168.1.100", "203.0.113.20",
            payload=payload,
            host=src_host, subject=src_subject,
        ))
    # 入站：C2 基础设施 → 被控端
    c2_host = HostInfo(hostname="c2-server", ip="203.0.113.20", os="Linux")
    c2_subject = SubjectInfo(type="process", name="icmp_listener", pid=None, user=None)
    for i in range(10):
        payload = bytes(random.randint(0, 255) for _ in range(200))
        events.append(make_icmp_event(
            base + timedelta(seconds=i * 2, milliseconds=500),
            "203.0.113.20", "192.168.1.100",
            icmp_type=0,  # Echo Reply
            payload=payload,
            host=c2_host, subject=c2_subject,
        ))
    return events


def scenario_port_scan():
    """场景9：端口扫描（同一源访问 25 个不同端口）。

    攻击链前置：扫描后通常接 C2 握手，事件上标同一 hostname + 进程，
    便于下游做"扫描 → C2"链路聚合。
    """
    base = datetime(2026, 9, 8, 18, 0, 0, tzinfo=timezone.utc)
    host = HostInfo(hostname="workstation-15", ip="192.168.1.66", os="Windows 10")
    subject = SubjectInfo(type="process", name="nmap.exe", pid=3301, user="bob")
    return [
        make_flow_event(base + timedelta(milliseconds=i * 100),
                        "192.168.1.66", "10.0.0.99", dst_port=port,
                        host=host, subject=subject)
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
    host = HostInfo(hostname="workstation-01", ip="192.168.1.10", os="Windows 10")
    subject = SubjectInfo(type="process", name="chrome.exe", pid=4231, user="alice")
    return [
        NormalizedEvent(
            timestamp=base,
            source_type="network_traffic",
            source="zeek",
            event_type="tls_handshake",
            host=host,
            subject=subject,
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
    host = HostInfo(hostname="workstation-77", ip="192.168.1.77", os="Windows 10")
    subject = SubjectInfo(type="process", name="powershell.exe", pid=7771, user="bob")
    return [
        make_flow_event(base + timedelta(seconds=i),
                        "192.168.1.77", "10.0.0.50", dst_port=p,
                        host=host, subject=subject)
        for i, p in enumerate(uncommon)
    ]


def scenario_high_frequency_http():
    """场景 11c：高频 HTTP（非隐蔽信道，触发 anomaly 级告警）。"""
    base = datetime(2026, 9, 8, 20, 0, 0, tzinfo=timezone.utc)
    host = HostInfo(hostname="workstation-30", ip="192.168.1.30", os="Windows 10")
    subject = SubjectInfo(type="process", name="python.exe", pid=6088, user="bob")
    events = []
    # 70 个 GET，跨越约 60 秒 → 速率 ≈ 70/min，超过 60/min 阈值
    for i in range(70):
        events.append(make_http_event(
            base + timedelta(milliseconds=i * 850),
            "192.168.1.30", "10.0.0.20", 80,
            "GET", "api.example", f"/v1/data/{i}", "Mozilla/5.0",
            host=host, subject=subject))
    return events


def scenario_high_frequency_icmp():
    """场景 11d：高频 ICMP（无 payload 异常，单纯触发高频 anomaly）。"""
    base = datetime(2026, 9, 8, 20, 30, 0, tzinfo=timezone.utc)
    host = HostInfo(hostname="workstation-40", ip="192.168.1.40", os="Windows 10")
    subject = SubjectInfo(type="process", name="ping.exe", pid=9001, user="bob")
    events = []
    for i in range(25):
        events.append(make_icmp_event(
            base + timedelta(milliseconds=i * 2000),
            "192.168.1.40", "8.8.8.8",
            payload=b"ping",
            host=host, subject=subject,
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

    # ---- 兜底：所有"有 src_ip 但 host.hostname 缺失"的事件，按 src_ip
    #      补一个默认 host（仅当 src_ip 在关键 IP 集合内）。这样从 parser
    #      （Zeek / Suricata / PCAP）出来的真实事件，落到下游跨源关联
    #      链路时仍能拿到 host 上下文。----
    DEFAULT_HOSTS_BY_SRC_IP: dict[str, tuple[HostInfo, SubjectInfo | None]] = {
        "192.168.1.1":   (HostInfo(hostname="workstation-99", ip="192.168.1.1", os="Linux"),
                          SubjectInfo(type="process", name="zeek", pid=None, user=None)),
        # 192.168.1.2 来自 Zeek conn.log / ssl.log 与 Suricata eve.json tls 事件，
        # 与 192.168.1.1 同段同角色（内部 workstation，详见 SAMPLE_DATA.md "字段增补说明"）。
        # Zeek/Suricata 的网络遥测天然不含 process/user 字段，因此 subject 留空，
        # 严格遵循"缺失 process context 比伪造 process context 更可接受"原则。
        "192.168.1.2":   (HostInfo(hostname="workstation-02", ip="192.168.1.2", os="Windows 10"),
                          None),
        "192.168.1.10":  (HostInfo(hostname="workstation-01", ip="192.168.1.10", os="Windows 10"),
                          SubjectInfo(type="process", name="svchost.exe", pid=1100, user="alice")),
        "192.168.1.30":  (HostInfo(hostname="workstation-30", ip="192.168.1.30", os="Windows 10"),
                          SubjectInfo(type="process", name="python.exe", pid=6088, user="bob")),
        "192.168.1.40":  (HostInfo(hostname="workstation-40", ip="192.168.1.40", os="Windows 10"),
                          SubjectInfo(type="process", name="ping.exe", pid=9001, user="bob")),
        "192.168.1.200": (HostInfo(hostname="workstation-22", ip="192.168.1.200", os="Windows 10"),
                          SubjectInfo(type="process", name="cmd.exe", pid=4422, user="bob")),
    }
    for e in all_events:
        if e.host and e.host.hostname:
            continue
        net = e.network
        if not net or not net.src_ip:
            continue
        if net.src_ip not in DEFAULT_HOSTS_BY_SRC_IP:
            continue
        h, s = DEFAULT_HOSTS_BY_SRC_IP[net.src_ip]
        e.host = h
        if s and not e.subject:
            e.subject = s

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

    # ---- 收集所有被检测器引用的 event_id（用于"引用闭合"采样） ----
    # 在 fixture 场景下，告警的 related_event_ids 仅用于"佐证事件存在"，
    # 真正的事件全量在 detection 上下游消费。所以这里把告警引用裁短到
    # 前 5 条代表性 event_id，再按此闭包采样 normalized_events：
    # 既保证 fixture loader 看到的 related_event_ids 都能解析，
    # 也保证 sample 文件大小可控（≈ 30~60 条 NormalizedEvent）。
    REFERRED_KEEP = 5
    for name, results in all_detections.items():
        for r in results:
            r.related_event_ids = r.related_event_ids[:REFERRED_KEEP]

    referenced_event_ids: set[str] = set()
    for name, results in all_detections.items():
        for r in results:
            referenced_event_ids.update(r.related_event_ids)

    # ---- 限制 NormalizedEvent 输出：
    #   1) 所有被任何 detection 引用的 event 必须出现（引用闭合）
    #   2) 其余每种 event_type 最多保留若干条代表样本（控制文件体积）
    #   这样既保证 fixture loader 中 related_event_ids 全部能解析，
    #   又不会让文件膨胀到几百 KB。
    PER_TYPE_KEEP = 5
    sample_events: list[dict] = []
    seen_types: dict[str, int] = {}
    for e in all_events:
        etype = e.event_type
        is_referenced = e.event_id in referenced_event_ids
        if not is_referenced and seen_types.get(etype, 0) >= PER_TYPE_KEEP:
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

    # DetectionResult 全部保留
    sample_detections = []
    for name, results in all_detections.items():
        for r in results:
            sample_detections.append(detection_to_dict(r))

    # ---- 实体引用注入（related_entity_ids）：
    #   网络层目前没有 host 实体注册中心，因此我们在生成期从
    #   scenario_meta + 事件 host/subject 推出受控的 entity_id 列表。
    #   命名规则：host:<hostname>  /  process:<hostname>:<processname>
    #   这样做不会破坏 schema（仍是 list[str]），且能让 C2/外传/扫描
    #   的告警带上可被跨源关联的实体引用。
    scenario_by_event_idx: dict[int, str] = {}
    for name, idxs in scenario_meta:
        for i in idxs:
            scenario_by_event_idx[i] = name
    event_to_entities: dict[str, list[str]] = {}
    for idx, e in enumerate(all_events):
        ents: list[str] = []
        if e.host and e.host.hostname:
            ents.append(f"host:{e.host.hostname}")
            if e.subject and e.subject.name:
                ents.append(
                    f"process:{e.host.hostname}:{e.subject.name}"
                )
        if ents:
            event_to_entities[e.event_id] = ents

    for d in sample_detections:
        ents: set[str] = set()
        for eid in d.get("related_event_ids", []):
            ents.update(event_to_entities.get(eid, []))
        d["related_entity_ids"] = sorted(ents)

    # 输出文档
    # - total_events_input: 场景构造出来的全量事件数
    # - total_events:      写入 normalized_events 的样本数（=fixture loader 可读到的数量）
    # - total_detections:  写入 detection_results 的告警数
    output = {
        "summary": {
            "total_events_input": len(all_events),
            "total_events": len(sample_events),
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

    # ---- 同时输出 fixture loader 友好的"顶层数组"版本 ----
    # 两个独立数组文件，避免 loader 难以区分 NormalizedEvent / DetectionResult。
    # 同步写一个 sidecar meta 记录 summary / 来源信息。
    array_ev_path = ROOT / "docs" / "sample_data_array.normalized_events.json"
    array_det_path = ROOT / "docs" / "sample_data_array.detection_results.json"
    array_meta_path = ROOT / "docs" / "sample_data_array.meta.json"
    array_ev_path.write_text(
        json.dumps(sample_events, ensure_ascii=False, indent=2, default=str)
    )
    array_det_path.write_text(
        json.dumps(sample_detections, ensure_ascii=False, indent=2, default=str)
    )
    array_meta_path.write_text(json.dumps({
        "description": "docs/sample_data.json 的派生文件，顶层为两个独立数组（fixture loader 直接吃）。",
        "normalized_events_file": "docs/sample_data_array.normalized_events.json",
        "detection_results_file": "docs/sample_data_array.detection_results.json",
        "summary": output["summary"],
        "reference_closure": "all detection.related_event_ids 都能在前一文件的 normalized_events 中解析",
    }, ensure_ascii=False, indent=2, default=str))
    print(f"输出: {array_ev_path}")
    print(f"输出: {array_det_path}")
    print(f"输出: {array_meta_path}")


if __name__ == "__main__":
    main()
