# 测试数据集说明与成员使用指南

## 1. 文档说明

本文档用于说明项目当前整理的公开测试数据，以及各测试数据对应的使用成员。

测试数据主要用于验证系统的：

- 日志解析
- 主机行为分析
- 网络流量分析
- MITRE ATT&CK 技术映射
- 多源数据关联
- 攻击链溯源
- 系统整体测试

当前测试数据均为已经下载并整理好的原始数据。

**数据由组员 9 统一整理和提供，各组员根据自己的负责模块使用对应测试数据。**

需要注意，不同公开数据集之间不存在天然的攻击活动关联，因此**不将 LANL、BOTS v1、Linux Attack Data 三个数据集直接拼接为同一次攻击事件**。

攻击链关联测试主要在**同一个数据集内部**进行。

对于数据量较大的数据集，不要求一次性处理全部数据。组员可以根据测试需求选择其中一部分数据、指定时间范围或指定主机进行测试。

---

# 2. 当前测试数据目录

```text
test-datasets/
├── LANL/
│   └── raw/
│       ├── auth.txt.gz
│       ├── proc.txt.gz
│       ├── flows.txt.gz
│       ├── dns.txt.gz
│       └── redteam.txt.gz
│
├── BOTS-v1/
│   └── raw/
│       └── botsv1-attack-only.tgz
│
└── Linux/
    ├── T1068-privilege-escalation/
    │   ├── auth.txt
    │   ├── kern.txt
    │   └── linux_auditd.txt
    │
    ├── T1548.003-sudo-doas/
    │   └── linux_auditd_new_doas.txt
    │
    ├── T1552.004-ssh-private-keys/
    │   ├── auditd_execve_find_ssh.txt
    │   └── linux_auditd_find_ssh_files.txt
    │
    └── T1003.008-passwd-shadow/
        ├── auditd_proctitle_access_cred.txt
        └── linux_auditd_access_credential.txt
```

---

# 3. LANL 数据集

LANL 数据集为企业环境中的多源网络安全事件数据，包含身份认证、进程、网络流量、DNS 以及已知红队活动等数据。

当前使用以下 5 个文件：

## 3.1 `auth.txt.gz`

**使用成员：2、7**

内容主要为 Windows/域环境中的身份认证事件，包括：

- 时间
- 源用户
- 目标用户
- 源计算机
- 目标计算机
- 认证类型
- 登录类型
- 登录方向
- 成功/失败状态

主要用于：

- Windows 登录/认证日志分析
- 用户与主机之间的行为关联
- 横向移动相关分析
- 多源攻击链关联

---

## 3.2 `proc.txt.gz`

**使用成员：4、7**

内容主要为进程启动与结束事件，包括：

- 时间
- 用户
- 计算机
- 进程名称
- 进程启动时间
- 进程结束时间

主要用于：

- 主机进程行为分析
- 进程活动检测
- 进程相关攻击行为分析
- 与认证、网络事件进行关联

由于该文件数据量较大，测试时可以根据需要截取部分数据进行处理。

---

## 3.3 `flows.txt.gz`

**使用成员：5、7**

内容为网络流量记录，包括：

- 时间
- 持续时间
- 源计算机
- 源端口
- 目标计算机
- 目标端口
- 协议
- 数据包数量
- 字节数

主要用于：

- 网络连接分析
- 网络会话分析
- 异常网络行为检测
- 主机之间通信关系分析
- 与认证、进程等事件进行关联

数据量较大时，可以选择部分时间范围或部分主机进行测试。

---

## 3.4 `dns.txt.gz`

**使用成员：5、7**

内容主要为 DNS 解析事件，包括：

- 时间
- 发起解析的计算机
- 解析得到的计算机

主要用于：

- DNS 行为分析
- 主机之间关系分析
- DNS 异常行为相关测试
- 与其他网络及主机事件进行关联

该文件可以与 `flows.txt.gz` 等 LANL 数据配合使用。

---

## 3.5 `redteam.txt.gz`

**使用成员：7**

该文件记录 LANL 数据集中的已知红队活动事件。

主要用于：

- 确定已知攻击活动的时间范围
- 确定涉及的主机和用户
- 为攻击链关联提供参考
- 与 `auth.txt.gz`、`proc.txt.gz`、`flows.txt.gz`、`dns.txt.gz` 进行交叉关联

该文件主要作为**已知攻击活动参考数据**使用，而不是普通业务日志进行单独分析。

---

## 3.6 LANL 攻击链测试

LANL 的多个数据文件属于同一个数据集，因此可以在 LANL 内部进行多源事件关联。

例如：

```text
redteam
   ↓
确定攻击时间 / 主机 / 用户
   ↓
auth
   ↓
proc
   ↓
flows
   ↓
dns
   ↓
多源事件关联
   ↓
攻击链
   ↓
AttackGraph
```

具体使用时，可以根据 `redteam.txt.gz` 确定相关攻击活动，再从其他 LANL 数据中提取对应时间范围和主机的事件。

**这里的攻击链关联仅针对 LANL 数据集内部的数据，不与 BOTS v1 或 Linux Attack Data 直接拼接。**

---

# 4. Splunk BOTS v1 数据集

当前使用：

```text
BOTS-v1/raw/botsv1-attack-only.tgz
```

**使用成员：2、4、5、6、7**

该版本为 BOTS v1 的攻击数据版本，主要保留与攻击活动相关的数据。

数据中包含多种 Windows、网络以及安全设备日志，例如：

- Windows Event Log
- Windows Sysmon
- Windows Registry
- IIS
- Fortigate
- Suricata
- DNS
- HTTP
- ICMP
- IP
- LDAP
- MAPI
- SMB
- TCP
- 其他网络相关数据

不同成员根据自己的分析模块选择对应数据源即可。

---

## 4.1 成员 2

主要使用：

- `WinEventLog`
- `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`
- Windows 相关系统日志

用于：

- Windows 主机日志解析
- 用户、登录、进程等 Windows 事件分析

---

## 4.2 成员 4

主要使用：

- Sysmon
- Windows Registry
- 与进程、文件、主机行为相关的数据

用于：

- 进程行为分析
- 文件/注册表行为分析
- 主机异常行为检测

---

## 4.3 成员 5

主要使用：

- `stream:dns`
- `stream:http`
- `stream:icmp`
- `stream:ip`
- `stream:smb`
- `stream:tcp`
- `suricata`
- 其他网络相关数据

用于：

- 网络流量分析
- 网络协议分析
- DNS/HTTP/ICMP 等行为分析
- 网络攻击检测

---

## 4.4 成员 6

主要使用 BOTS 中已经能够识别出的攻击行为数据，用于：

- 将检测结果映射到 MITRE ATT&CK
- 验证 ATT&CK 技术识别规则
- 验证不同攻击行为对应的 Tactic / Technique

---

## 4.5 成员 7

根据需要综合使用 BOTS v1 中的：

- Windows Event Log
- Sysmon
- 网络流量
- Suricata
- DNS
- HTTP
- SMB
- 其他相关数据

用于：

- 多源事件关联
- 攻击链重建
- 攻击路径分析
- AttackGraph 构建

---

## 4.6 BOTS v1 攻击链测试

BOTS v1 中的不同日志来源属于同一个攻击数据集，因此可以在 **BOTS v1 内部**进行多源关联。

例如：

```text
Windows Event
      +
Sysmon
      +
网络流量
      +
DNS / HTTP
      +
Suricata
      ↓
多源事件关联
      ↓
攻击行为链
      ↓
AttackGraph
```

具体关联时，应根据 BOTS v1 中实际存在的时间、主机、进程、网络连接等信息进行关联。

**BOTS v1 的攻击链测试独立于 LANL 和 Linux Attack Data，不将三个数据集混合为同一次攻击。**

---

# 5. Linux Attack Data

Linux 测试数据来自 Splunk Attack Data，当前整理了 4 类攻击行为数据。

这些数据主要用于 Linux 日志解析、主机行为检测以及 MITRE ATT&CK 技术映射测试。

当前数据分别对应不同的攻击技术，不将不同目录中的数据默认视为同一次攻击。

---

# 5.1 T1068 - Linux Auditd

目录：

```text
Linux/T1068-privilege-escalation/
```

文件：

```text
auth.txt
kern.txt
linux_auditd.txt
```

**使用成员：3、4、6、7**

该数据主要对应 Linux 环境中的权限提升相关行为。

可用于：

- Linux 系统日志解析
- auditd 日志解析
- 进程/命令行为分析
- 权限提升行为检测
- MITRE ATT&CK T1068 映射
- 攻击行为关联

---

# 5.2 T1548.003 - Sudo / Doas

目录：

```text
Linux/T1548.003-sudo-doas/
```

文件：

```text
linux_auditd_new_doas.txt
```

**使用成员：3、4、6、7**

主要用于：

- Linux auditd 日志解析
- sudo/doas 相关行为分析
- 权限提升行为检测
- MITRE ATT&CK T1548.003 映射
- 攻击事件分析

---

# 5.3 T1552.004 - SSH Private Keys

目录：

```text
Linux/T1552.004-ssh-private-keys/
```

文件：

```text
auditd_execve_find_ssh.txt
linux_auditd_find_ssh_files.txt
```

**使用成员：3、4、6、7**

主要用于：

- Linux 命令执行行为分析
- auditd `EXECVE` 等事件解析
- SSH 私钥相关行为检测
- MITRE ATT&CK T1552.004 映射
- 攻击行为分析

---

# 5.4 T1003.008 - `/etc/passwd` / `/etc/shadow`

目录：

```text
Linux/T1003.008-passwd-shadow/
```

文件：

```text
auditd_proctitle_access_cred.txt
linux_auditd_access_credential.txt
```

**使用成员：3、4、6、7**

主要用于：

- Linux auditd 日志解析
- 凭据访问行为分析
- `/etc/passwd`、`/etc/shadow` 相关行为检测
- MITRE ATT&CK T1003.008 映射
- 攻击行为分析

---

# 5.5 Linux 数据的使用方式

Linux Attack Data 中的各目录分别对应不同攻击技术。

因此：

```text
T1068
T1548.003
T1552.004
T1003.008
```

主要作为**独立的攻击行为测试样本**使用。

例如：

```text
Linux Auditd
    ↓
事件解析
    ↓
行为识别
    ↓
DetectionResult
    ↓
MITRE ATT&CK
    ↓
T1068
```

或者：

```text
Linux Auditd
    ↓
行为识别
    ↓
DetectionResult
    ↓
T1552.004
```

不能仅根据这些独立数据集的文件，就认定：

```text
T1552.004
    ↓
T1003.008
    ↓
T1548.003
    ↓
T1068
```

一定属于同一次连续攻击。

如果系统需要测试连续攻击链，应使用具有同一攻击场景和多源事件的数据，例如 LANL 或 BOTS v1。

---

# 6. 各测试数据与使用成员对应关系

| 数据集 | 文件 | 使用成员 | 主要用途 |
|---|---|---|---|
| LANL | `auth.txt.gz` | 2、7 | Windows 认证、登录、关联 |
| LANL | `proc.txt.gz` | 4、7 | 进程行为、关联 |
| LANL | `flows.txt.gz` | 5、7 | 网络流量、网络关联 |
| LANL | `dns.txt.gz` | 5、7 | DNS 分析、网络关联 |
| LANL | `redteam.txt.gz` | 7 | 已知攻击活动、攻击链关联 |
| BOTS v1 | `botsv1-attack-only.tgz` | 2、4、5、6、7 | Windows、主机行为、网络、ATT&CK、关联 |
| Linux T1068 | `auth.txt` | 3、4、6、7 | Linux 日志、提权、ATT&CK |
| Linux T1068 | `kern.txt` | 3、4、6、7 | Linux 系统日志、主机行为 |
| Linux T1068 | `linux_auditd.txt` | 3、4、6、7 | auditd、主机行为、提权 |
| Linux T1548.003 | `linux_auditd_new_doas.txt` | 3、4、6、7 | sudo/doas、提权 |
| Linux T1552.004 | `auditd_execve_find_ssh.txt` | 3、4、6、7 | 命令执行、SSH 私钥 |
| Linux T1552.004 | `linux_auditd_find_ssh_files.txt` | 3、4、6、7 | SSH 私钥相关行为 |
| Linux T1003.008 | `auditd_proctitle_access_cred.txt` | 3、4、6、7 | 凭据访问 |
| Linux T1003.008 | `linux_auditd_access_credential.txt` | 3、4、6、7 | passwd/shadow 访问 |

---

# 7. 数据使用方式

测试时不要求所有数据都完整处理。

对于数据量较大的数据集，可以根据实际测试需求：

- 截取指定时间范围
- 选择指定主机
- 选择指定用户
- 选择指定类型的日志
- 选择部分记录进行测试

例如 LANL 数据可以先根据 `redteam.txt.gz` 确定攻击时间和涉及主机，再从 `auth.txt.gz`、`proc.txt.gz`、`flows.txt.gz`、`dns.txt.gz` 中截取对应范围的数据进行测试。

BOTS v1 可以根据具体模块选择需要的日志类型，也可以选择其中一部分数据进行测试，不要求一次处理整个压缩包。

Linux 数据文件体积较小，可以直接用于完整测试；也可以根据具体测试模块选择其中的日志文件。

---

# 8. 测试数据与系统模块对应关系

整体测试流程可以按照：

```text
原始测试数据
    ↓
Parser
    ↓
NormalizedEvent
    ↓
Analyzer
    ↓
DetectionResult
    ↓
MITRE ATT&CK 映射
    ↓
多源事件关联
    ↓
AttackGraph / 攻击链
```

不同数据集对应的测试重点如下：

```text
LANL
 ├── Windows 认证
 ├── 进程行为
 ├── 网络流量
 ├── DNS
 └── 红队活动参考
          ↓
     LANL 内部多源关联
          ↓
       攻击链


BOTS v1
 ├── Windows Event Log
 ├── Sysmon
 ├── Registry
 ├── DNS / HTTP / ICMP
 ├── Suricata
 └── 其他网络数据
          ↓
     BOTS v1 内部多源关联
          ↓
       攻击链


Linux Attack Data
 ├── Auditd
 ├── 权限提升
 ├── sudo/doas
 ├── SSH 私钥访问
 └── passwd/shadow 访问
          ↓
     单项攻击行为检测
          ↓
     MITRE ATT&CK 映射
```

**LANL、BOTS v1、Linux Attack Data 分别独立进行测试，不将不同数据集直接拼接为同一次攻击链。**

---

# 9. 数据提供说明

本目录中的测试数据由组员 9 统一整理和提供。

各组员负责根据自己的模块使用对应测试数据，并将测试结果用于系统开发和测试。

对于数据量较大的数据，各组员可以自行选择合适的数据范围进行测试。

**本目录负责提供测试数据，不要求各组员完整处理所有数据，也不要求不同公开数据集之间建立不存在的攻击关联。**