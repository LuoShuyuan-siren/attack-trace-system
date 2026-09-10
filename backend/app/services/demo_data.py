"""可运行演示用数据。

真实解析器和分析器接入后，只需要替换 API 路由中的数据来源，不改变前端接口契约。
"""

from typing import Any


DEMO_EVENTS: list[dict[str, Any]] = [
    {
        "event_id": "evt-001",
        "timestamp": "2026-09-08T10:20:00Z",
        "source_type": "host_log",
        "source": "windows_sysmon",
        "host": {"hostname": "WIN-PC01", "ip": "192.168.1.20", "os": "windows"},
        "event_type": "process_create",
        "severity": "high",
        "action": "create_process",
        "tags": ["powershell", "process"],
        "raw_data": {"process_name": "powershell.exe", "command_line": "powershell.exe -enc ..."},
    },
    {
        "event_id": "evt-002",
        "timestamp": "2026-09-08T10:22:10Z",
        "source_type": "host_behavior",
        "source": "ebpf",
        "host": {"hostname": "WEB01", "ip": "10.0.0.15", "os": "linux"},
        "event_type": "network_connection",
        "severity": "critical",
        "action": "connect",
        "tags": ["c2", "network"],
        "raw_data": {"destination_ip": "203.0.113.9", "port": 443},
    },
    {
        "event_id": "evt-003",
        "timestamp": "2026-09-08T10:35:00Z",
        "source_type": "network_traffic",
        "source": "zeek",
        "host": {"hostname": "CORE-SRV", "ip": "10.0.0.50", "os": "linux"},
        "event_type": "dns_query",
        "severity": "medium",
        "action": "resolve",
        "tags": ["dns", "tunnel"],
        "raw_data": {"query": "cdn.evil.example.com"},
    },
]

DEMO_GRAPH: dict[str, Any] = {
    "graph_id": "graph-demo-001",
    "description": "演示攻击链：Web 入口 -> 横向移动 -> 权限提升 -> C2 通信",
    "start_time": "2026-09-08T10:20:00Z",
    "end_time": "2026-09-08T10:45:00Z",
    "nodes": [
        {"node_id": "host:WEB01", "node_type": "host", "name": "WEB01", "severity": "high", "attributes": {}, "tags": ["web", "initial_access"]},
        {"node_id": "host:PC01", "node_type": "host", "name": "PC01", "severity": "medium", "attributes": {}, "tags": ["workstation"]},
        {"node_id": "host:CORE-SRV", "node_type": "host", "name": "CORE-SRV", "severity": "critical", "attributes": {}, "tags": ["server", "exfiltration"]},
        {"node_id": "ip:203.0.113.9", "node_type": "ip", "name": "203.0.113.9", "severity": "high", "attributes": {}, "tags": ["c2"]},
    ],
    "edges": [
        {"edge_id": "edge-001", "source": "host:WEB01", "target": "host:PC01", "relation": "lateral_movement", "timestamp": "2026-09-08T10:35:00Z", "confidence": 0.88, "related_event_ids": ["evt-001"], "related_detection_ids": ["det-001"], "attack_technique_id": "T1021", "attributes": {}},
        {"edge_id": "edge-002", "source": "host:PC01", "target": "host:CORE-SRV", "relation": "privilege_escalation", "timestamp": "2026-09-08T10:40:00Z", "confidence": 0.81, "related_event_ids": ["evt-002"], "related_detection_ids": ["det-002"], "attack_technique_id": "T1068", "attributes": {}},
        {"edge_id": "edge-003", "source": "host:CORE-SRV", "target": "ip:203.0.113.9", "relation": "c2_communication", "timestamp": "2026-09-08T10:45:00Z", "confidence": 0.92, "related_event_ids": ["evt-003"], "related_detection_ids": ["det-003"], "attack_technique_id": "T1071", "attributes": {}},
    ],
}

DEMO_CHAIN = {
    "stages": [
        {"stage": "initial_access", "host": "WEB01", "technique_id": "T1190"},
        {"stage": "execution", "host": "WEB01", "technique_id": "T1059"},
        {"stage": "lateral_movement", "host": "PC01", "technique_id": "T1021"},
        {"stage": "privilege_escalation", "host": "PC01", "technique_id": "T1068"},
        {"stage": "command_and_control", "host": "CORE-SRV", "technique_id": "T1071"},
        {"stage": "exfiltration", "host": "CORE-SRV", "technique_id": "T1041"},
    ]
}

DEMO_TASKS = [
    {"task_id": "task-001", "name": "主机日志关联", "status": "success", "progress": 100, "created_at": "2026-09-08T09:30:00Z", "updated_at": "2026-09-08T09:45:00Z"},
    {"task_id": "task-002", "name": "网络异常检测", "status": "running", "progress": 72, "created_at": "2026-09-08T10:00:00Z", "updated_at": "2026-09-08T10:12:00Z"},
    {"task_id": "task-003", "name": "攻击链重建", "status": "pending", "progress": 30, "created_at": "2026-09-08T10:15:00Z", "updated_at": "2026-09-08T10:15:00Z"},
]