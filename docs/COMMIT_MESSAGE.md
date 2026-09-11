# Git Commit Message 草稿

## 推荐 commit message（conventional commits 风格）

```
feat(traffic): 网络流量分析模块完整交付（成员5）

实现 3 个网络流量 Parser + 4 个 Analyzer + 集中配置 + 共用工具 + 完整测试。

## 解析器层（backend/app/parsers/traffic/）

- PcapParser：PCAP/PCAPNG 经典格式 + Enhanced Packet Block，
  支持 Ethernet / Raw IP / Linux SLL 三种链路层，
  提取 IPv4/IPv6 + TCP/UDP/ICMP/DNS/HTTP 协议字段。
- ZeekParser：TSV 日志解析（conn.log / dns.log / http.log / ssl.log），
  自动日志类型检测（文件名 → #path → #fields 三级 fallback）。
- SuricataParser：eve.json 解析（flow / dns / http / alert / tls），
  Suricata severity 1/2/3 → high/medium/low 映射。

## 分析器层（backend/app/analyzers/traffic/）

- DnsAnalyzer：高频查询、异常长域名、子域高熵、唯一子域、TXT 异常、
  NXDOMAIN 比例、DNS 隧道综合判定（score ≥ 3 触发，≥ 5 升级 high）。
- HttpAnalyzer：异常长 URI、URI 高熵、可疑 UA、大上传、高 POST 频率、
  Beacon 周期性、HTTP 隐蔽信道综合判定。
- IcmpAnalyzer：高频、payload 大小与稳定性、payload 高熵、
  周期性、双向通信、ICMP 隧道综合判定。
- ConnectionAnalyzer：端口扫描、大范围连接、非常用端口、长连接、
  Beacon 周期性连接、高频连接。

## 共用工具与配置

- TrafficAnalyzerBase：统一 DetectionResult 构造（confidence clamp [0, 1]），
  事件过滤（source_type=network_traffic），DNS/HTTP 协议数据提取。
- utils.py：shannon_entropy / extract_subdomain / is_valid_domain /
  parse_iso_timestamp / safe_int / safe_str / calculate_jitter_ratio /
  rate_per_minute / **detect_periodicity**（3 个 Analyzer 共用的周期检测入口）。
- config.py：4 个 frozen dataclass（DNSThresholds / HTTPThresholds /
  ICMPThresholds / ConnectionThresholds）+ 模块级单例，魔法数字零散落。

## 审计报告问题修复（5/5）

[P1] icmp_analyzer.py: ATT&CK 映射 T1099 → T1571.004（ICMP Tunneling），
     注释 "DNS 隧道类技术" → "ICMP Tunneling"
[P2] dns_analyzer.py: 移除未使用的 import math
[P2] base.py: 移除从未调用的 _extract_icmp_info() 方法
[P2] test_traffic_parsers.py: 移除未使用的 _pytest.tmpdir 导入
[P3] pcap_parser.py: 移除 _parse_packet / _parse_tcp / _parse_udp /
     _parse_icmp / _parse_pcap_classic / _parse_pcapng 中未使用的
     filepath 参数

## Lint 清理（ruff）

清理成员5 自己文件中的 F401（unused import）/ F841（unused local）：
- connection_analyzer.py: 移除未使用的 safe_int
- dns_analyzer.py: 移除未使用的 is_valid_domain / safe_int，移除未使用的
  unique_domains 局部变量
- pcap_parser.py: 移除未使用的 HostInfo / parse_iso_timestamp
- zeek_parser.py: 移除未使用的 safe_str
- test_traffic_analyzers.py: 移除未使用的 json / pytest / create_all_zeek_logs
- test_traffic_parsers.py: 移除未使用的 pytest（json 在测试体中使用，保留）

ruff check backend/app/{parsers,analyzers}/traffic/ backend/tests/{test_traffic_*,
fixtures/} --select=E,W,F --ignore=E501 → All checks passed!

公共文件（api/、core/、schemas/、services/）的 W292（缺末尾换行）不在成员5
职责范围内，未触碰，符合"不修改公共接口"约定。

## 测试

61 个测试全部通过（pytest tests/ -v，0.85s）：
- test_event_schema.py（既有）：2 PASSED
- test_traffic_parsers.py：24 PASSED
  - PcapParser：8
  - ZeekParser：8
  - SuricataParser：8
- test_traffic_analyzers.py：35 PASSED
  - DnsAnalyzer：7
  - HttpAnalyzer：7
  - IcmpAnalyzer：7
  - ConnectionAnalyzer：8
  - EdgeCases：6（集成测试）

完整测试日志见 docs/test_output.txt。

## 交付文档

docs/ 目录下 3 份新增文档（面向成员6）：
- 成员5最终交付清单.md — 功能/修复/限制/测试覆盖
- 快速开始指南.md — Parser/Analyzer 实例化 + DetectionResult 字段说明 +
  阈值调整方法（默认 + 运行时覆盖）
- 成员6接口说明.md — 双向契约 + 接口稳定性承诺 + 集成 FAQ
- lint_output.txt — ruff 验证结果
- test_output.txt — 完整测试日志

## 关键设计决策

- PCAP 解析使用 Python 标准库 struct/socket，不引入 scapy 大型依赖
- 所有阈值集中配置在 config.py，frozen dataclass 保证不可变
- Analyzer 只消费 NormalizedEvent，不重复解析原始数据
- DNS/HTTP/ICMP 协议层细节存放在 raw_data 子字典
- ATT&CK 映射仅在明确技术时设置（DNS T1071.004、HTTP T1071.001、
  ICMP T1571.004、端口扫描 T1046），其余留给成员6
- 周期性/Beacon 检测统一通过 utils.detect_periodicity 共用函数，
  内部使用 calculate_jitter_ratio 计算 CV（std/mean）

## 公共接口合规性

未修改任何公共文件：
- backend/app/schemas/{event,detection}.py ✅ 未修改
- backend/app/core/{parser,analyzer}.py ✅ 未修改
- backend/app/api/ ✅ 未修改
- backend/app/services/ ✅ 未修改
- backend/tests/test_event_schema.py ✅ 未修改
```

---

## 备选：简短版 commit message（单行 commit subject + 多行 body）

```
feat(traffic): 网络流量分析模块（成员5完整交付）

3 个 Parser（PCAP/Zeek/Suricata）+ 4 个 Analyzer（DNS/HTTP/ICMP/Connection）
+ 集中阈值配置 + 共用工具函数 + 61 个测试全部通过。

修复审计 P1-P3 共 5 项：
- [P1] icmp_analyzer.py: ATT&CK 映射 T1099 → T1571.004（ICMP Tunneling）
- [P2] dns_analyzer.py: 移除死导入 import math
- [P2] base.py: 移除死方法 _extract_icmp_info()
- [P2] test_traffic_parsers.py: 移除未使用的 _pytest.tmpdir 导入
- [P3] pcap_parser.py: 移除未使用的 filepath 形参

提取共用：detect_periodicity() 已被 HTTP/ICMP/Connection 三个 Analyzer 共用。

Lint: ruff check on 成员5 files → All checks passed!
测试: pytest tests/ → 61/61 PASSED in 0.85s

公共接口零修改（schemas/core/api/services 全部未触碰）。

docs/ 新增：成员5最终交付清单.md / 快速开始指南.md / 成员6接口说明.md /
test_output.txt / lint_output.txt
```

---

## 备选：拆分为多个 commit（如果团队偏好细粒度 history）

```
1. feat(traffic): 实现 3 个网络流量 Parser（PCAP/Zeek/Suricata）
2. feat(traffic): 实现 4 个 Analyzer + 共用基类与工具（DNS/HTTP/ICMP/Connection）
3. feat(traffic): 集中阈值配置（frozen dataclass）+ 全局单例
4. test(traffic): 61 个测试用例（24 Parser + 35 Analyzer + 2 既有）
5. fix(traffic): 修复审计 P1-P3 共 5 项（ATT&CK 映射 + 死代码清理）
6. refactor(traffic): 提取 detect_periodicity 共用函数
7. docs(traffic): 交付文档（清单 + 快速开始 + 接口说明）
8. chore(traffic): ruff lint 清理（F401/F841）
```

---

## git 命令（如果确认提交）

```bash
cd D:/attack-trace-system

# 已暂存所有变更（git add -A 已执行）
git status

# 提交
git commit -F COMMIT_MESSAGE.txt
# 或使用编辑器交互式
git commit
```
