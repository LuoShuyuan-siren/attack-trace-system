# TC001-ping 测试说明

## 1. 测试基本信息

| 项目 | 内容 |
| --- | --- |
| 测试编号 | `TC001-ping` |
| 测试名称 | Kali 与 Windows 11 ICMP 连通性测试 |
| 测试目的 | 验证两台虚拟机在 VMware VMnet1 隔离网络中的基础连通性，并生成一份最小网络流量样本 |
| 测试发起端 | Kali，`192.168.35.10` |
| 测试目标端 | Windows 11，`192.168.35.11` |
| 网络模式 | VMware `VMnet1`，仅主机模式 |
| 子网 | `192.168.35.0/24` |
| 网关 | 未配置 |
| DNS | 未配置 |
| 时区 | 中国标准时间，UTC+08:00 |

## 2. 测试步骤

1. 确认 Kali 和 Windows 11 都接入 VMware `VMnet1`。
2. 在 Kali 上确认网卡地址为 `192.168.35.10/24`。
3. 在 Windows 11 上确认 IPv4 地址为 `192.168.35.11/24`。
4. 在 Kali 上使用 `tcpdump` 抓取两台主机之间的流量：

   ```bash
   sudo tcpdump -i eth0 -nn host 192.168.35.11 \
     -w ~/attack-trace-tests/TC001-ping/TC001-ping.pcap
   ```

5. 在 Kali 的另一个终端发送 5 个 ICMP Echo 请求：

   ```bash
   ping -c 5 192.168.35.11
   ```

6. 停止抓包并保存 `TC001-ping.pcap`。

## 3. 测试结果

- Kali 收到 Windows 11 返回的 ICMP Echo Reply。
- 截图中可见连续的 `64 bytes from 192.168.35.11` 响应。
- 两台虚拟机已在 `192.168.35.0/24` 网段内实现互通。
- 当前测试未执行漏洞利用、登录尝试或数据修改，因此它属于基础连通性基线，不是恶意攻击检测样本。

## 4. 输出文件

```text
kali抓包/attack-trace-tests/TC001-ping/README.txt
kali抓包/attack-trace-tests/TC001-ping/TC001-ping.pcap
```

其中：

- `TC001-ping.pcap` 是网络流量原始证据。
- `README.txt` 是原始测试记录。
- 本文档是适合提交到 Git 的整理版说明。

## 5. 对系统分析模块的价值

该样本可以用于验证：

- PCAP 文件是否能够被网络流量 Parser 读取。
- ICMP 请求和响应是否能被识别为网络事件。
- 事件中的源 IP、目标 IP、时间戳和协议字段是否能正确提取。
- 网络流量模块的基础数据链路是否正常。

该样本不应被标记为恶意行为，也不应单独生成高危告警。

