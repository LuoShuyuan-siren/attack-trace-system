#!/usr/bin/env python
"""
测试脚本：解析 fixtures 目录下的 .evtx 文件，并输出标准化 JSON
为成员4和成员7分别生成专用样例文件
"""

import json
import sys
from pathlib import Path
from typing import List
from collections import Counter

# 添加项目根目录到 sys.path
PROJECT_ROOT = Path(__file__).parent.parent.parent
BACKEND_DIR = Path(__file__).parent.parent
sys.path.extend([str(PROJECT_ROOT), str(BACKEND_DIR)])

from backend.app.schemas.event import NormalizedEvent
from backend.app.parsers.windows_log_parser import WindowsLogParser

# 使用相对路径
TEST_DIR = Path(__file__).parent / "fixtures"
OUTPUT_DIR = TEST_DIR / "output"


def generate_member4_mock_data() -> List[NormalizedEvent]:
    """生成成员4需要的主机行为模拟数据（包含多种事件类型）"""
    events = []

    # 1. 正常进程创建
    events.append(NormalizedEvent(
        event_id="evt-m4-proc-001",
        timestamp="2026-09-08T10:00:00Z",
        source_type="host_log",
        source="windows_security",
        host={"hostname": "PC01", "os": "windows"},
        event_type="process_create",
        subject={"type": "process", "name": "explorer.exe", "pid": 1234, "user": "admin"},
        object={"type": "process", "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 5678},
        action="create_process",
        raw_data={"command_line": "cmd.exe /c dir"},
        severity="info",
        tags=["normal", "process"]
    ))

    # 2. 恶意进程创建（PowerShell 编码命令）
    events.append(NormalizedEvent(
        event_id="evt-m4-proc-002",
        timestamp="2026-09-08T10:01:00Z",
        source_type="host_log",
        source="windows_sysmon",
        host={"hostname": "PC01", "os": "windows"},
        event_type="process_create",
        subject={"type": "process", "name": "powershell.exe", "pid": 2001, "user": "admin"},
        object={"type": "process", "name": "cmd.exe", "path": "C:\\Windows\\System32\\cmd.exe", "pid": 1999},
        action="create_process",
        raw_data={"command_line": "powershell.exe -enc SQBFAFgA"},
        severity="high",
        tags=["attack", "powershell", "execution"]
    ))

    # 3. 文件创建（恶意）
    events.append(NormalizedEvent(
        event_id="evt-m4-file-001",
        timestamp="2026-09-08T10:02:00Z",
        source_type="host_log",
        source="windows_sysmon",
        host={"hostname": "PC01", "os": "windows"},
        event_type="file_create",
        subject={"type": "process", "name": "cmd.exe", "pid": 5678, "user": "admin"},
        object={"type": "file", "path": "C:\\Users\\admin\\malware.exe"},
        action="create_file",
        severity="high",
        tags=["attack", "file"]
    ))

    # 4. 文件修改（恶意）
    events.append(NormalizedEvent(
        event_id="evt-m4-file-002",
        timestamp="2026-09-08T10:03:00Z",
        source_type="host_log",
        source="windows_sysmon",
        host={"hostname": "PC01", "os": "windows"},
        event_type="file_modify",
        subject={"type": "process", "name": "notepad.exe", "pid": 3001, "user": "admin"},
        object={"type": "file", "path": "C:\\Windows\\System32\\drivers\\etc\\hosts"},
        action="modify_file",
        severity="critical",
        tags=["attack", "file"]
    ))

    # 5. DNS 查询（C2）
    events.append(NormalizedEvent(
        event_id="evt-m4-dns-001",
        timestamp="2026-09-08T10:04:00Z",
        source_type="host_log",
        source="windows_sysmon",
        host={"hostname": "PC01", "os": "windows"},
        event_type="dns_query",
        subject={
            "type": "process",
            "name": "powershell.exe",
            "pid": 2001,
            "user": "admin"
        },
        object={
            "type": "domain",
            "name": "evil-c2.example.com"
        },
        network={
            "protocol": "dns"
        },
        action="dns_query",
        raw_data={
            "query": "evil-c2.example.com"
        },
        severity="high",
        tags=["attack", "c2", "dns"]
    ))

    # 6. 网络连接（恶意）
    events.append(NormalizedEvent(
        event_id="evt-m4-net-001",
        timestamp="2026-09-08T10:05:00Z",
        source_type="host_log",
        source="windows_sysmon",
        host={"hostname": "PC01", "os": "windows"},
        event_type="network_connection",
        subject={"type": "process", "name": "malware.exe", "pid": 4001, "user": "admin"},
        network={"dst_ip": "192.168.1.100", "dst_port": 4444, "protocol": "tcp"},
        action="connect",
        severity="high",
        tags=["attack", "network"]
    ))

    # 7-22：更多混合事件（保证足够数量）
    for i in range(7, 23):
        is_attack = i > 15
        event_type_idx = i % 5
        if event_type_idx == 0:
            et = "process_create"
            obj = {"type": "process", "name": f"process_{i}.exe", "path": f"C:\\Temp\\process_{i}.exe", "pid": 1000 + i}
            action = "create_process"
            raw = {"command_line": f"process_{i}.exe -c test"}
        elif event_type_idx == 1:
            et = "file_create"
            obj = {"type": "file", "path": f"C:\\Temp\\file_{i}.txt"}
            action = "create_file"
            raw = {}
        elif event_type_idx == 2:
            et = "file_modify"
            obj = {"type": "file", "path": f"C:\\Windows\\System32\\config\\file_{i}.dat"}
            action = "modify_file"
            raw = {}
        elif event_type_idx == 3:
            et = "dns_query"
            obj = {
                "type": "domain",
                "name": f"domain-{i}.example.com"
            }
            action = "dns_query"
            raw = {
                "query": f"domain-{i}.example.com"
            }
        else:
            et = "network_connection"
            obj = None
            action = "connect"
            raw = {}

        events.append(NormalizedEvent(
            event_id=f"evt-m4-{i:03d}",
            timestamp=f"2026-09-08T10:{i:02d}:00Z",
            source_type="host_log",
            source="windows_sysmon" if i % 2 == 0 else "windows_security",
            host={"hostname": "PC01", "os": "windows"},
            event_type=et,
            subject={
                "type": "process",
                "name": f"process_{i}.exe",
                "pid": 2000 + i,
                "user": "admin"
            },
            object=obj,
            network={
                "protocol": "dns"
            } if et == "dns_query" else {
                "dst_ip": f"192.168.1.{100 + i}",
                "dst_port": 4000 + i,
                "protocol": "tcp"
            } if et == "network_connection" else None,
            action=action,
            raw_data=raw,
            severity="high" if is_attack else "info",
            tags=["attack" if is_attack else "normal", "member4", et]
        ))

    return events


def generate_member7_mock_data() -> List[NormalizedEvent]:
    """生成成员7需要的攻击链样例：登录→进程执行（时间连续、用户一致）"""
    events = []
    # 登录 10:00:00
    events.append(NormalizedEvent(
        event_id="evt-chain-login-001",
        timestamp="2026-09-08T10:00:00Z",
        source_type="host_log",
        source="windows_security",
        host={"hostname": "PC01", "os": "windows"},
        event_type="user_login",
        subject={"type": "user", "name": "admin"},
        network={"src_ip": "192.168.1.10"},
        action="login",
        severity="info",
        tags=["normal", "chain"]
    ))
    # 进程创建 10:00:05，同一用户
    events.append(NormalizedEvent(
        event_id="evt-chain-proc-001",
        timestamp="2026-09-08T10:00:05Z",
        source_type="host_log",
        source="windows_security",
        host={"hostname": "PC01", "os": "windows"},
        event_type="process_create",
        subject={
            "type": "process",
            "name": "C:\\Windows\\System32\\cmd.exe",
            "pid": 1234,
            "user": "admin"
        },
        object={
            "type": "process",
            "name": "C:\\Windows\\explorer.exe",
            "path": "C:\\Windows\\explorer.exe",
            "pid": 800
        },
        action="create_process",
        raw_data={"command_line": "cmd.exe /c whoami"},
        severity="medium",
        tags=["normal", "chain"]
    ))
    return events


def parse_security_evtx() -> List[NormalizedEvent]:
    """只解析 Security.evtx，忽略 Application 和 System"""
    all_evtx = list(TEST_DIR.glob("*.evtx"))
    # 只处理 Security 相关文件
    evtx_files = [f for f in all_evtx if "Security" in f.name or "Sysmon" in f.name]
    
    if not evtx_files:
        print("⚠️ 未找到 Security.evtx 或 Sysmon.evtx")
        return []

    print(f"✅ 检测到 {len(evtx_files)} 个日志文件（Security/Sysmon），开始解析...")
    all_events = []
    parser = WindowsLogParser()

    for evtx_file in evtx_files:
        try:
            print(f"正在解析: {evtx_file.name} ...")
            events = parser.parse(evtx_file)
            print(f"  -> {evtx_file.name} 解析出了 {len(events)} 条事件")
            all_events.extend(events)
        except Exception as e:
            print(f"  -> {evtx_file.name} 解析失败: {e}")

    return all_events


def main():
    print("=" * 60)
    print("Windows 日志解析测试 - 为成员4和成员7生成联调数据")
    print("=" * 60)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # ----- 1. 尝试解析真实 Security.evtx -----
    real_events = parse_security_evtx()

    # ----- 2. 生成成员4的样例（真实数据 + 模拟数据混合）-----
    member4_events = []
    
    # 2.1 从真实数据中筛选成员4需要的事件类型
    if real_events:
        # 先提取所有 process_create（真实数据）
        for e in real_events:
            if e.event_type in ["process_create", "file_create", "file_modify", "dns_query", "network_connection"]:
                member4_events.append(e)
        print(f"✅ 从真实数据中提取了 {len(member4_events)} 条行为事件")
    
    # 2.2 补充模拟数据（确保包含多种事件类型）
    mock_events = generate_member4_mock_data()
    
    # 统计真实数据中已有的事件类型
    existing_types = set(e.event_type for e in member4_events)
    print(f"📊 真实数据已有事件类型: {existing_types if existing_types else '无'}")
    
    # 补充模拟数据中真实数据缺少的事件类型
    for e in mock_events:
        if e.event_type not in existing_types:
            # 这种类型真实数据中没有，直接添加
            member4_events.append(e)
            print(f"  补充模拟事件: {e.event_type}")
        elif len(member4_events) < 22:
            # 即使已有这种类型，如果总数不足22条，也补充一些
            if e.event_type in ["file_create", "file_modify", "dns_query", "network_connection"]:
                member4_events.append(e)
    
    # 确保至少有 18 条，最多 22 条
    while len(member4_events) < 18:
        for e in mock_events:
            if len(member4_events) >= 18:
                break
            member4_events.append(e)
    
    member4_events = member4_events[:22]
    
    # 统计最终事件类型分布
    final_types = Counter(e.event_type for e in member4_events if hasattr(e, 'event_type'))
    print(f"📊 成员4样例最终事件类型分布: {dict(final_types)}")
    
    # 导出成员4的样例
    member4_file = OUTPUT_DIR / "member4_host_behavior_samples.json"
    with open(member4_file, "w", encoding="utf-8") as f:
        json.dump(
            [e.model_dump(mode="json") for e in member4_events],
            f,
            indent=2,
            ensure_ascii=False
        )
    print(f"✅ 成员4样例已导出至: {member4_file} (共 {len(member4_events)} 条)")

    # ----- 3. 生成成员7的样例（独立的攻击链）-----
    member7_events = generate_member7_mock_data()
    member7_file = OUTPUT_DIR / "member7_attack_chain_samples.json"
    with open(member7_file, "w", encoding="utf-8") as f:
        json.dump(
            [e.model_dump(mode="json") for e in member7_events],
            f,
            indent=2,
            ensure_ascii=False
        )
    print(f"✅ 成员7样例已导出至: {member7_file} (共 {len(member7_events)} 条)")

    # ----- 4. 同时导出完整数据（供成员6使用）-----
    if real_events:
        full_file = OUTPUT_DIR / "normalized_events.json"
        with open(full_file, "w", encoding="utf-8") as f:
            json.dump(
                [e.model_dump(mode="json") for e in real_events],
                f,
                indent=2,
                ensure_ascii=False
            )
        print(f"✅ 完整数据已导出至: {full_file} (共 {len(real_events)} 条)")

    # ----- 5. 统计信息 -----
    print("\n" + "=" * 60)
    print("📊 统计信息")
    print("=" * 60)
    
    if real_events:
        type_counts = Counter(e.event_type for e in real_events if hasattr(e, 'event_type'))
        print(f"真实事件分布: {dict(type_counts)}")
    
    print(f"\n成员4样例条数: {len(member4_events)}")
    print(f"成员7样例条数: {len(member7_events)}")
    
    print("\n" + "=" * 60)
    print("✅ 联调数据准备完成！")
    print(f"📁 成员4 (主机行为): {member4_file}")
    print(f"📁 成员7 (攻击链): {member7_file}")
    if real_events:
        print(f"📁 成员6 (完整数据): {full_file}")
    print("=" * 60)


if __name__ == "__main__":
    main()