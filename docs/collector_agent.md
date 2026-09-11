# 采集 Agent 使用说明

采集 Agent 支持两种工作模式：

- 准实时模式：定时采集进程快照、文件变化和可用的网络连接，并通过 HTTP 批量上报。
- 缓存回放模式：先写入 JSONL，再在后端恢复后批量补传。

## 启动后端

在项目根目录执行：

```powershell
Set-Location backend
$env:PYTHONPATH = "."
D:/Miniconda3/python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

采集接口为 `POST /api/v1/agent/events`。

## Windows 采集

另开终端，在项目根目录执行：

```powershell
$env:PYTHONPATH = "backend"
D:/Miniconda3/python.exe scripts/run_collector.py --agent-id win-lab-01 --once --watch-path C:\\Users\\Public
```

持续采集：

```powershell
$env:PYTHONPATH = "backend"
D:/Miniconda3/python.exe scripts/run_collector.py --agent-id win-lab-01 --interval 5 --watch-path C:\\Users\\Public
```

Windows 进程采集使用系统自带 `tasklist`，不需要额外安装采集驱动。

## Linux 采集

```bash
PYTHONPATH=backend python scripts/run_collector.py \
  --agent-id linux-lab-01 \
  --interval 5 \
  --watch-path /tmp \\
  --linux-system-log /var/log/auth.log
```

Linux 进程采集读取 `/proc`。网络连接采集为可选增强能力，安装 `psutil` 后自动启用：

```bash
python -m pip install psutil
```

## 断网补传

Agent 会把每轮事件追加到 `collector-events.jsonl`。后端恢复后执行：

```powershell
$env:PYTHONPATH = "backend"
D:/Miniconda3/python.exe scripts/run_collector.py --agent-id win-lab-01 --replay-cache --cache collector-events.jsonl
```

后端会按照 `event_id` 去重，重复补传不会重复生成事件。

## 溯源产物接口

- `GET /api/v1/forensics/process-tree`：进程树节点和父子关系。
- `GET /api/v1/forensics/attribution`：APT/TTP 相似度、攻击者指纹和 C2 端点。
- `GET /api/v1/forensics/report`：结构化 JSON 报告。
- `GET /api/v1/forensics/report/markdown`：可直接保存的 Markdown 报告。

## 当前采集范围

- 进程快照：PID、父 PID（Linux）、进程名、命令行、主机信息。
- 文件变化：指定目录内文件的首次观测、修改、删除。
- 网络连接：安装 `psutil` 时采集已建立的 TCP/UDP 远端连接。

## 深度实时采集

安装 `backend/requirements.txt` 后可按需启用：

- Windows：`--windows-realtime --windows-native --windows-state windows-event-cursors.json` 优先使用 pywin32 `EvtSubscribe` 原生订阅 Sysmon/Security 的 ETW-backed 事件通道，并持久化 EventRecordID 游标；未安装 pywin32 时自动回退轮询，覆盖进程访问、远程线程、镜像加载和进程篡改。
- Linux auditd：继续使用 `--linux-system-log /var/log/audit/audit.log` 的增量读取。
- Linux eBPF：先在 Linux 主机安装内核匹配的 BCC/python3-bcc，再运行 `sudo python3 scripts/ebpf_syscall_sensor.py --output /var/run/attack-trace/events.jsonl`；Agent 使用 `--ebpf-jsonl /var/run/attack-trace/events.jsonl` 增量读取，保留 syscall、PID 和参数。
- 网卡抓包：`--packet-interface Ethernet` 启用 Scapy 实时抓包；Linux 通常需要 root/CAP_NET_RAW，Windows 需要 Npcap。实时 TCP 事件会保存序号、标志位和受限 payload，因此可以直接进入双向会话、TCP 重组、乱序和重传分析；网络上下文会输出方向计数、字节数和 TCP 状态摘要。
- TLS 元数据：Zeek/Suricata 的 TLS 事件会统一提取 SNI、证书指纹和 JA3；这些字段会汇总到网络会话摘要中，明文 PCAP 只有在握手字段可见时才能计算。
- TCP 流重组：PCAP TCP 事件会保存受限的序号和 payload，网络会话按方向重组跨包内容，输出缺口、乱序段、重传段、预览和基础 HTTP/TLS 协议判断。
- 时钟校准：Agent 默认读取 Windows `w32tm` 或 Linux `chronyc/timedatectl` 状态；使用 `--no-clock-calibration` 可关闭，或通过 `ATTACK_TRACE_CLOCK_OFFSET_MS` 提供受控实验偏差。

外部 C2 情报接口为 `GET /api/v1/intelligence/lookup?indicator=example.com`，提供 WHOIS、RDAP 和可选 Passive DNS。Passive DNS 通过环境部署配置的 URL 模板接入：`{indicator}` 会被 URL 编码；未配置或网络不可用时返回 `null`，不会影响采集。

外部情报默认使用 300 秒进程内 TTL 缓存，可通过 `PASSIVE_INTELLIGENCE_CACHE_TTL` 调整；WHOIS/RDAP/Passive DNS 均为失败可降级查询，单个服务不可用不会阻塞攻击报告。

后端运行时证据默认保存在内存中；设置 `ATTACK_TRACE_DB_PATH=./runtime/attack-trace.db` 后，事件、检测结果和 ATT&CK 映射会写入 SQLite，并在服务重启时恢复。

采集链路诊断接口为 `GET /api/v1/agent/health`，返回后端接收/接受/重复事件计数、来源分布、最近摄取时间和持久化状态；本地 Agent 可调用 `CollectorAgent.health()` 查看采集量、发送失败数和缓存文件状态。

会话重建优先使用 Windows `TargetLogonId/SubjectLogonId` 或 Linux `session_id` 关联同一登录会话；缺少会话 ID 时才按主机和用户顺序回退。

归因和报告接口支持按需 enrichment：`GET /api/v1/forensics/attribution?enrich=true`、`GET /api/v1/forensics/report?enrich_c2=true`。默认关闭外部查询，避免普通报告受网络延迟影响。

APT 画像默认使用内置版本；设置 `ATTACK_TRACE_APT_PROFILES=./config/apt-profiles.json` 可加载外部画像。文件支持 `{ "version": "...", "profiles": { "Group": { "techniques": [], "tags": [] } } }` 格式，归因结果会返回画像来源和版本。

传感器默认监听 `execve`、`openat`、`connect`、`ptrace`、`process_vm_writev`、`memfd_create`、`mmap` 和 `mprotect`；支持自动识别或通过 `--arch x86_64/aarch64` 指定 syscall 架构，并尽量为 `execve/openat` 提取用户态路径，写入 `raw_data.arguments.path`；`connect` 会提取远端 IP/端口并标准化为网络事件；同时补充进程的 `ppid`、`exe` 和 `command_line` 上下文；`--include-all` 可保留未知 syscall 编号。它需要 root 或等价的 BPF 权限，建议通过 systemd 管理并限制输出文件权限。

这是课程靶场所需的轻量采集链路，不等同于内核级 EDR。生产环境应使用签名的 Sysmon/eBPF 传感器，并限制情报服务的网络出口与访问频率。
