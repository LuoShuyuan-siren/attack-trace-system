# 测试过程总结

## 1. 测试环境

本轮测试使用两台虚拟机：

- Kali：攻击/测试发起端，`192.168.35.10`
- Windows 11：目标主机，`192.168.35.11`

两台虚拟机均连接到 VMware `VMnet1` 仅主机网络，网段为 `192.168.35.0/24`。靶场网卡未配置默认网关，测试不依赖外网。

## 2. TC001-ping：基础连通性测试

### 测试行为

Kali 向 Windows 11 发送 5 个 ICMP Echo 请求，Windows 11 返回 ICMP Echo Reply。

### 关键命令

```bash
sudo tcpdump -i eth0 -nn host 192.168.35.11 \
  -w ~/attack-trace-tests/TC001-ping/TC001-ping.pcap

ping -c 5 192.168.35.11
```

### 结果

测试成功。Kali 终端显示来自 `192.168.35.11` 的连续响应，说明 VMnet1、静态 IP 和 Windows ICMP 入站规则均已基本配置正确。

### 输出

```text
kali抓包/attack-trace-tests/TC001-ping/TC001-ping.pcap
```

## 3. TC002-port-scan：指定端口探测

### 测试行为

Kali 对 Windows 11 的以下 TCP 端口进行探测：

```text
135, 139, 445, 3389, 5985
```

使用的命令为：

```bash
nmap -sT -Pn -p 135,139,445,3389,5985 192.168.35.11 \
  -oN ~/attack-trace-tests/TC002-port-scan/nmap-result.txt
```

同时在 Kali 上抓取目标主机流量，在 Windows 11 上启用并导出 Windows 防火墙日志和系统事件日志。

### 时间记录

- Kali 侧 Nmap 开始时间：`2026-09-08 23:34:09`，UTC+08:00。
- Kali 侧 Nmap 结束时间：`2026-09-08 23:34:12`，UTC+08:00。
- Windows 防火墙日志显示同一时间段内收到来自 `192.168.35.10` 的 TCP SYN，并将目标端口连接标记为 `DROP`。

### 结果

- Windows 11 主机在线。
- 5 个目标端口均显示为 `filtered`。
- 防火墙日志记录了来自 Kali 的探测流量并执行了丢弃。
- 该测试可以作为基础网络侦察和防火墙日志关联样本。

### 输出

```text
kali抓包/attack-trace-tests/TC002-port-scan/TC002-port-scan.pcap
kali抓包/attack-trace-tests/TC002-port-scan/nmap-result.txt
win11抓包/AttackTrace/TC002-port-scan/pfirewall.log
win11抓包/AttackTrace/TC002-port-scan/Application.evtx
win11抓包/AttackTrace/TC002-port-scan/Security.evtx
win11抓包/AttackTrace/TC002-port-scan/System.evtx
```

## 4. 当前结论

1. Kali 与 Windows 11 的隔离网络已建立，基础通信正常。
2. Kali 能够向 Windows 11 发送测试流量。
3. Windows 防火墙日志能够记录端口探测并显示 `DROP`。
4. 当前数据已经足够交给网络流量、Windows 日志和溯源模块成员做第一轮解析验证。
5. 当前还没有 Ubuntu 相关数据，后续需要 Ubuntu 加入 VMnet1 后补充 Linux 日志测试。

