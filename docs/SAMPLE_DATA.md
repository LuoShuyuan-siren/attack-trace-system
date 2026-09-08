# 成员5 模块样本数据说明

本目录包含成员5（网络流量分析模块）当前代码实际产出的样本数据，用于：
- 文档演示（成员6 集成参考）
- 代码评审（直观看到 Parser/Analyzer 实际输出形态）
- 测试参考（人工核验检测能力覆盖）

## 数据生成方式

**真实运行** `scripts/generate_samples.py`，实际调用：

1. **构造 18 个场景**，覆盖正常 + 攻击混合行为
2. **3 个 Parser**（PcapParser / ZeekParser / SuricataParser）真实解析 fixture 生成的样本文件
3. **4 个 Analyzer**（Dns / Http / Icmp / Connection）真实分析全部事件
4. **JSON 序列化** NormalizedEvent 与 DetectionResult

```bash
cd D:/attack-trace-system
"D:/python 3.11/python.exe" scripts/generate_samples.py
```

输出：`docs/sample_data.json`（约 80KB）。

---

## 样本规模

| 类型 | 数量 | 覆盖 |
|------|------|------|
| **NormalizedEvent**（代表性样本） | 28 | 8 种 event_type × 4 种 source |
| **DetectionResult**（全部） | 25 | 4 种 Analyzer × 3 种 severity × 2 种 detection_type × 4 种 ATT&CK |

---

## NormalizedEvent 覆盖（28 条）

### 按 event_type 分布

| event_type | 数量 | 说明 |
|------------|------|------|
| `dns_query` | 5 | 正常 + 隧道子域 + NXDOMAIN |
| `http_request` | 6 | 正常 + Beacon + 长 URI + 大上传 |
| `icmp_packet` | 5 | 正常 ping + 隧道（高熵大 payload） |
| `network_flow` | 5 | 端口扫描 + 非常用端口 |
| `network_connection` | 3 | Zeek conn.log 解析 |
| `tls_handshake` | 2 | Zeek / Suricata |
| `ssl_handshake` | 1 | Zeek ssl.log |
| `alert` | 1 | Suricata alert |

### 按 source 分布

| source | 数量 | Parser 来源 |
|--------|------|------------|
| `sample` | 20 | 手工构造场景（直接 NormalizedEvent） |
| `zeek` | 5 | `ZeekParser` 真实解析 fixture 生成的 conn/dns/http/ssl 日志 |
| `suricata` | 2 | `SuricataParser` 真实解析 fixture 生成的 eve.json |
| `pcap` | 1 | `PcapParser` 真实解析 fixture 生成的二进制 PCAP |

---

## DetectionResult 覆盖（25 条）

### 按 Analyzer 分布

| Analyzer | 数量 | 典型告警 |
|----------|------|---------|
| `dns_analyzer` | 4 | DNS 隧道（high/medium）× 3 + 高频 DNS（low） |
| `http_analyzer` | 5 | HTTP Beacon × 2 + HTTP 隐蔽信道 + 高频 HTTP × 2 |
| `icmp_analyzer` | 3 | ICMP 隧道（high/medium）× 3 |
| `connection_analyzer` | 13 | Beacon 通信 × 5 + 高频连接 × 3 + 长连接 × 3 + 端口扫描 + 非常用端口 |

### 按 severity 分布

| severity | 数量 |
|----------|------|
| `high` | 7 |
| `medium` | 11 |
| `low` | 7 |

### 按 detection_type 分布

| detection_type | 数量 | 含义 |
|----------------|------|------|
| `suspicious_behavior` | 15 | 可疑行为（攻击特征） |
| `anomaly` | 10 | 一般异常（频率等非攻击特征） |

### 按 MITRE ATT&CK 映射分布

| attack_technique_id | 数量 | 技术名称 |
|---------------------|------|---------|
| `T1046` | 1 | Network Service Scanning（端口扫描） |
| `T1071.001` | 8 | Application Layer Protocol: Web Protocols（HTTP Beacon/C2） |
| `T1071.004` | 3 | Application Layer Protocol: DNS（DNS 隧道） |
| `T1571.004` | 3 | Non-Application Layer Protocol: ICMP（ICMP 隧道） |
| `None` | 10 | 不映射广义异常（频率异常等，留给成员6） |

---

## 样本场景列表（18 个）

| # | 场景名 | 类型 | 触发告警 |
|---|--------|------|---------|
| 1 | 正常 DNS 解析 | 正常 | 高频 DNS 误报（短时分散 3 次） |
| 2 | DNS 隧道（攻击） | 攻击 | DNS 隧道 high（score=5, T1071.004） |
| 3 | NXDOMAIN 风暴（攻击） | 攻击 | DNS 隧道 medium（score=4, T1071.004） |
| 4 | 正常 HTTP 浏览 | 正常 | 无（5 个 GET 分散 120s） |
| 5 | HTTP Beacon（攻击） | 攻击 | HTTP Beacon medium（T1071.001） |
| 6 | HTTP 可疑行为（攻击） | 攻击 | HTTP 隐蔽信道 medium（T1071.001） |
| 7 | 正常 ICMP（ping） | 正常 | 误触 ICMP 隧道（短 payload 高熵特征） |
| 8 | ICMP 隧道（攻击） | 攻击 | ICMP 隧道 high（score=7, T1571.004） |
| 9 | 端口扫描（攻击） | 攻击 | 端口扫描 medium（T1046） |
| 10 | 长连接（攻击） | 攻击 | 长连接 medium |
| 11 | SSL/TLS 握手 | 正常 | 无（仅 ConnectionAnalyzer 统计） |
| 11b | 非常用端口通信（攻击） | 攻击 | 非常用端口 low |
| 11c | 高频 HTTP（异常） | 异常 | 高频 HTTP low + HTTP Beacon |
| 11d | 高频 ICMP（异常） | 异常 | ICMP 隧道 medium + Beacon + 高频连接 |
| 12 | PCAP 真实解析 | 正常 | 无（最小 PCAP 含 TCP/UDP/ICMP 各 1 个） |
| 13 | Zeek 真实解析 | 正常 | DNS 隧道 medium（fixture 内含高熵子域） |
| 14 | Suricata 真实解析 | 正常 | 无（基础 5 类事件） |

---

## 文件位置

- **完整数据**：`docs/sample_data.json`（机器可读，含全部字段）
- **生成脚本**：`scripts/generate_samples.py`（可重复执行）
- **本说明**：`docs/SAMPLE_DATA.md`

## 数据格式

`sample_data.json` 结构：

```json
{
  "summary": {
    "total_events": 28,
    "total_detections": 25,
    "scenarios": [...],
    "analyzer_counts": {"dns_analyzer": 4, "http_analyzer": 5, ...}
  },
  "normalized_events": [
    {
      "event_id": "evt-...",
      "timestamp": "2026-09-08T10:00:00+00:00",
      "source_type": "network_traffic",
      "source": "zeek",
      "event_type": "dns_query",
      "network": {"src_ip": "...", "dst_ip": "...", ...},
      "raw_data": {"dns": {"query": "...", "query_type": "A", ...}},
      "tags": ["dns"],
      ...
    }
  ],
  "detection_results": [
    {
      "detection_id": "det-...",
      "analyzer": "dns_analyzer",
      "detection_type": "suspicious_behavior",
      "title": "疑似 DNS 隧道通信 (源: 192.168.1.100)",
      "severity": "high",
      "confidence": 0.95,
      "attack_technique_id": "T1071.004",
      "evidence": {"src_ip": "...", "indicators": {...}, "score": 5},
      "tags": ["dns", "dns_tunnel", "covert_channel"],
      ...
    }
  ]
}
```

## 复现

```bash
cd D:/attack-trace-system
"D:/python 3.11/python.exe" scripts/generate_samples.py
```

输出会写到 `docs/sample_data.json`。脚本无外部依赖（仅依赖后端代码本身 + pydantic）。
