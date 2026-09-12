# TC001-ping 测试说明

## 1. 测试基本信息

| 项目 | 内容 |
| --- | --- |
| 测试编号 | `TC001-ping` |
| 测试名称 | Kali 与 Windows 11 ICMP 连通性测试 |
| 测试目的 | 验证两台虚拟机在 VMware VMnet1 隔离网络中的基础连通性，并生成 ICMP 网络流量样本 |
| 测试发起端 | Kali，`192.168.35.10` |
| 测试目标端 | Windows 11，`192.168.35.11` |
| 网络模式 | VMware `VMnet1`，仅主机模式 |
| 子网 | `192.168.35.0/24` |
| 网关 | 未配置 |
| DNS | 未配置 |
| 时区 | 中国标准时间，UTC+08:00 |
| 初始记录时间 | `2026-09-08T22:26:44+08:00` |

本目录整理的是 `2026-09-08` 初次基础测试中的成功 TC001 数据，不是后续 `10.10.30.10` 的丢包重跑数据。

## 2. 测试步骤

1. 确认 Kali 和 Windows 11 接入 VMware `VMnet1`。
2. 在 Kali 上确认网卡地址为 `192.168.35.10/24`。
3. 在 Windows 11 上确认 IPv4 地址为 `192.168.35.11/24`。
4. 在 Kali 上使用 `tcpdump` 抓取目标主机相关流量：

   ```bash
   sudo tcpdump -i eth0 -nn host 192.168.35.11 \
     -w ~/attack-trace-tests/TC001-ping/TC001-ping.pcap
   ```

5. 在 Kali 的另一个终端发送 5 个 ICMP Echo 请求：

   ```bash
   ping -c 5 192.168.35.11
   ```

6. 测试结束后停止抓包并保存 PCAP 文件。

## 3. 测试结果

- 初次测试的 Kali 终端截图显示：`5 packets transmitted, 5 received, 0% packet loss`。
- 同一截图显示连续收到来自 `192.168.35.11` 的 `64 bytes` ICMP Echo Reply。
- tcpdump 截图显示抓包接口为 `eth0`，并记录了该目标地址相关的数据包。
- Kali 和 Windows 11 在 `192.168.35.0/24` 网段内实现了基础互通。
- 本次仅进行了 Ping 连通性测试，未执行漏洞利用、登录尝试或数据修改，因此属于基础连通性样本，不是恶意攻击样本。

## 4. 输出文件

```text
kali-TC001-ping-rerun/README.txt
kali-TC001-ping-rerun/TC001-ping-rerun.pcap
win11-TC001-ping-rerun/win-ip.txt
```

其中：

- `TC001-ping-rerun.pcap` 是从初次基础测试压缩包中整理出的原始 PCAP。文件名沿用当前仓库目录命名，但数据内容属于初次成功测试。
- `README.txt` 是初次测试的原始记录。
- `win-ip.txt` 是初次测试中 Windows 11 的 IP 配置记录。
- 同级的 `kali\kali-TC001-ping-rerun\ping-result.txt`、`start-time.txt` 和 `end-time.txt` 属于后续重跑数据，不属于本 README 描述的初次成功测试，不应与本 PCAP 配套使用。

## 5. 对系统分析模块的价值

该样本可以用于验证：

- PCAP 文件是否能够被网络流量 Parser 读取。
- ICMP Echo Request 和 Echo Reply 是否能被识别为网络事件。
- 源 IP、目标 IP、时间戳和协议字段是否能正确提取。
- 网络流量模块的基础数据链路是否正常。

该样本不应被标记为恶意行为，也不应单独生成高危告警。
