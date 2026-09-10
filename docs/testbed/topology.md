# 三台虚拟机模拟八类逻辑节点

## 物理虚拟机

| 物理节点 | 地址 | 基本角色 |
| --- | --- | --- |
| Kali | `10.10.10.10` | 攻击/测试发起端 |
| Windows 11 / OFFICE01 | `10.10.30.10` | 内网办公区域计算机 |
| Ubuntu Server / WEB01 | `10.10.10.254` | 多个服务角色的承载主机 |

实际只有三台虚拟机。课程要求的八类节点通过服务、网络和角色隔离进行逻辑模拟；同一台虚拟机承载多个角色时，在目录、端口、日志和说明中分别标识。

## 八类逻辑节点映射

| 要求角色 | 当前映射 | 物理承载 | 证据或补做内容 |
| --- | --- | --- | --- |
| 攻击节点 | Kali | Kali | 现有 PCAP、Nmap、curl、SSH 测试记录 |
| C2 服务器 | Ubuntu C2 HTTP 服务 | Ubuntu Server | 现有 TC007 C2 日志和 PCAP；补做独立端口和日志目录 |
| 防火墙 | Ubuntu `iptables`/`nftables` 服务 | Ubuntu Server | 补做 `CHAIN001` 防火墙规则和日志 |
| Web 服务器 | Ubuntu Web 服务 | Ubuntu Server | 现有 TC003、TC004、TC006 数据 |
| email 服务器 | Ubuntu 轻量 SMTP 测试服务 | Ubuntu Server | 补做 SMTP 端口、服务日志和测试邮件记录 |
| 内网交换机 | VMware VMnet 虚拟交换网络 | VMware 网络层 | 补充网络段、网卡和连接关系说明 |
| 内网办公区域计算机 | Windows 11 / OFFICE01 | Windows 11 | 现有 Windows EVTX、Sysmon、防火墙和心跳数据 |
| 内网服务器区域核心服务器 | Ubuntu SSH/SFTP 接收服务 | Ubuntu Server | 现有 TC008 接收文件；补做独立核心接收目录和哈希 |

这里的“八节点”表示八类逻辑节点/服务角色，不表示必须有八台独立操作系统。最终报告应同时列出“逻辑角色”和“物理承载”。

## 文字拓扑

```text
                         VMware VMnet
                    (内网交换网络角色)
                 /          |           \
Kali 10.10.10.10      Windows 11       Ubuntu Server 10.10.10.254
  攻击节点          OFFICE01办公主机    Web / C2 / SMTP / Firewall /
                                      Core SSH/SFTP 接收服务
```

## Ubuntu 角色隔离建议

```text
/srv/roles/web/
/srv/roles/c2/
/srv/roles/mail/
/srv/roles/core/inbox/CHAIN001/
/var/log/attack-trace/CHAIN001/
```

建议使用不同端口：

```text
Web: 8080
C2: 8081
SMTP: 2525
SSH/Core: 22
```

## 证据要求

补做后应为每个逻辑角色至少保留角色名、物理承载、地址或端口、启动时间和一项对应日志/抓包/配置证据。多个逻辑角色共用 Ubuntu 时，不得把同一份没有角色标记的日志重复作为多个节点证据。
