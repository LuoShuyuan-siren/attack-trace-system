# IP 与时间记录

## 1. 网络规划

| 节点 | 角色 | IPv4 地址 | 子网掩码 | 默认网关 | 网络 |
| --- | --- | --- | --- | --- | --- |
| Kali | 攻击/测试发起端 | `192.168.35.10` | `255.255.255.0` | 未配置 | VMware `VMnet1` |
| Windows 11 | Windows 目标主机 | `192.168.35.11` | `255.255.255.0` | 未配置 | VMware `VMnet1` |
| Ubuntu Server | Linux 目标主机 | 待配置 | `255.255.255.0` | 暂不配置 | VMware `VMnet1` |

说明：

- `VMnet1` 是仅主机模式，主要用于靶场内部通信。
- 靶场内部网卡不需要通过网关访问外网。
- Kali 如果需要下载工具，可以额外使用 NAT 网卡；NAT 网卡不应替代 VMnet1 靶场网卡。

## 2. 记录文件来源

### Kali

来源文件：

```text
kali抓包/attack-trace-tests/kali-ip.txt
kali抓包/attack-trace-tests/start-time.txt
```

关键记录：

- `eth0`：`192.168.35.10/24`
- Kali 记录的开始时间：`2026-09-08T22:26:44+08:00`

### Windows 11

来源文件：

```text
win11抓包/AttackTrace/win-ip.txt
win11抓包/AttackTrace/start-time.txt
```

关键记录：

- `Ethernet0`：`192.168.35.11`
- 子网掩码：`255.255.255.0`
- 默认网关：空
- Windows 侧记录的开始时间：`2026-09-08T22:50:23.1417949+08:00`

## 3. 时间使用注意事项

Kali 的 `start-time.txt` 和 Windows 的 `start-time.txt` 不是同一时刻生成的：

- Kali 文件时间为 `22:26:44`，对应早先的 `TC001-ping` 记录。
- Windows 文件时间为 `22:50:23`，更接近后续数据整理或测试准备时间。
- `TC002-port-scan` 的准确测试时间应以 `nmap-result.txt` 和 `pfirewall.log` 中的 `23:34:09` 至 `23:34:12` 为准。

因此，分析程序进行事件关联时，应优先使用 PCAP、Nmap 输出和防火墙日志内部的事件时间，而不是把两个主机的 `start-time.txt` 直接当成同一次攻击的开始时间。

