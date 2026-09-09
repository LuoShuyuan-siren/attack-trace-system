# 9号成员测试资料

本目录是9号成员整理的靶场、测试和数据说明，适合提交到 Git 仓库。

## 文档目录

- `TC001-ping.md`：Kali 与 Windows 11 的基础 ICMP 连通性测试说明。
- `test-process-summary.md`：当前已完成测试的过程和结果总结。
- `ip-time-record.md`：虚拟机 IP、网络模式和时间记录。
- `dataset-manifest.md`：原始数据文件清单、用途和共享方式。

## 原始数据位置

原始测试数据当前保存在项目目录下：

```text
kali抓包/
win11抓包/
```

原始数据包括 PCAP、EVTX 和 Windows 防火墙日志。它们用于组内分析，不建议直接提交到 Git 仓库。提交前请检查 `.gitignore`，避免误上传大型或可能包含主机信息的原始日志。

## 当前测试

| 测试编号 | 测试内容 | 当前状态 |
| --- | --- | --- |
| `TC001-ping` | Kali 向 Windows 11 发送 ICMP Echo 请求 | 已完成 |
| `TC002-port-scan` | Kali 对 Windows 11 的指定 TCP 端口进行探测 | 已完成 |

