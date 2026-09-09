# 测试数据清单与共享方式

## 1. Git 提交原则

Git 仓库提交：

- 测试说明和过程总结。
- IP、网络模式、时间记录。
- 数据清单。
- 小型、脱敏的文本样例。

原始证据通过组内文件共享：

- PCAP 抓包。
- Windows EVTX 事件日志。
- Windows 防火墙日志。
- 含有大量原始记录或主机信息的压缩包。

## 2. 当前文件清单

| 文件 | 类型 | 内容 | 建议去向 | 主要使用成员 |
| --- | --- | --- | --- | --- |
| `kali抓包/attack-trace-tests/TC001-ping/TC001-ping.pcap` | PCAP | Kali 与 Windows 11 的 ICMP 请求和响应 | 组内共享 | 5号网络流量，7号溯源 |
| `kali抓包/attack-trace-tests/TC001-ping/README.txt` | 文本 | TC001 原始测试说明 | 可随文档提交 | 5号网络流量 |
| `kali抓包/attack-trace-tests/TC002-port-scan/TC002-port-scan.pcap` | PCAP | TCP 端口探测流量 | 组内共享 | 5号网络流量，7号溯源 |
| `kali抓包/attack-trace-tests/TC002-port-scan/nmap-result.txt` | 文本 | Nmap 扫描命令、端口状态和扫描时间 | 组内共享或提交脱敏摘要 | 5号网络流量，7号溯源 |
| `win11抓包/AttackTrace/TC002-port-scan/pfirewall.log` | 文本日志 | Windows 防火墙记录的 TCP SYN 和 DROP 动作 | 组内共享 | 2号 Windows 日志，5号网络流量 |
| `win11抓包/AttackTrace/TC002-port-scan/Security.evtx` | EVTX | Windows 安全事件 | 组内共享 | 2号 Windows 日志 |
| `win11抓包/AttackTrace/TC002-port-scan/System.evtx` | EVTX | Windows 系统事件 | 组内共享 | 2号 Windows 日志，4号主机行为 |
| `win11抓包/AttackTrace/TC002-port-scan/Application.evtx` | EVTX | Windows 应用事件 | 组内共享 | 2号 Windows 日志，4号主机行为 |
| `win11抓包/AttackTrace/TC002-port-scan.zip` | ZIP | Windows 侧 TC002 原始文件压缩包 | 组内共享，避免重复发送 | 2号、4号、5号 |
| `kali抓包/attack-trace-tests/kali-ip.txt` | 文本 | Kali 网卡和 IP 记录 | 可提交 | 全体 |
| `kali抓包/attack-trace-tests/start-time.txt` | 文本 | Kali 侧时间记录 | 可提交或并入本文档 | 全体 |
| `win11抓包/AttackTrace/win-ip.txt` | 文本 | Windows 网卡和 IP 记录 | 可提交 | 全体 |
| `win11抓包/AttackTrace/start-time.txt` | 文本 | Windows 侧时间记录 | 可提交或并入本文档 | 全体 |

## 3. 组内共享时的建议

建议发送一个名为 `TC002-port-scan-raw.zip` 的压缩包，内容包括：

```text
TC002-port-scan.pcap
nmap-result.txt
pfirewall.log
Application.evtx
Security.evtx
System.evtx
```

`TC001-ping.pcap` 单独发送即可。

发送时附上以下说明：

```text
测试编号：TC002-port-scan
攻击端：Kali 192.168.35.10
目标端：Windows 11 192.168.35.11
测试时间：2026-09-08 23:34:09 至 23:34:12，UTC+08:00
行为：对 TCP 135、139、445、3389、5985 进行探测
结果：主机在线，5 个端口均为 filtered；Windows 防火墙记录 DROP
```

## 4. 安全注意事项

- 不要上传密码、API Key、虚拟机镜像或 `.env` 文件。
- EVTX 可能包含用户名、主机名和系统环境信息，只发给确实需要分析的组员。
- PCAP 可能包含未预期的主机信息，提交前确认只包含本次隔离靶场流量。
- 如果文件过大，Git 仓库只提交本文档和测试摘要，原始文件保存在组内网盘，并在组内消息中注明文件名和哈希。

