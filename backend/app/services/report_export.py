from __future__ import annotations

from typing import Any


def render_report_markdown(report: dict[str, Any]) -> str:
    def json_value(value: Any) -> str:
        import json

        return json.dumps(value, ensure_ascii=False, indent=2, default=str)

    lines = [
        "# 攻击溯源分析报告",
        "",
        f"- 报告类型：{report.get('report_type', 'attack_trace')}",
        f"- 生成时间：{report.get('generated_at', 'unknown')}",
        f"- 事件数量：{report.get('event_count', 0)}",
        f"- 检测数量：{report.get('detection_count', 0)}",
        "",
        "## 攻击时间线",
        "",
    ]
    timeline = report.get("timeline", [])
    if timeline:
        for item in timeline:
            lines.append(
                f"- `{item.get('timestamp', 'unknown')}` "
                f"{item.get('stage', 'unknown')} / "
                f"{item.get('technique_id', 'unknown')} / "
                f"{item.get('host', 'unknown')}"
            )
    else:
        lines.append("- 暂无可由语义关系重建的攻击阶段，以下列出异常检测证据：")
        detections = sorted(
            report.get("detections", []),
            key=lambda item: str(item.get("timestamp", "")),
        )
        for detection in detections:
            lines.append(
                f"- `{detection.get('timestamp', 'unknown')}` "
                f"[{detection.get('severity', 'unknown')}] "
                f"{detection.get('title', 'unknown')} / "
                f"{detection.get('attack_technique_id') or '未映射技术'} / "
                f"事件={', '.join(detection.get('related_event_ids', [])) or '无'}"
            )
        if not detections:
            lines.append("- 暂无异常检测证据")

    lines.extend(["", "## 攻击路径", ""])
    for index, path in enumerate(report.get("paths", []), start=1):
        lines.append(f"### 路径 {index}（评分={path.get('score', 'unknown')}）")
        lines.append(f"- 节点：{' -> '.join(path.get('nodes', [])) or '无'}")
        lines.append(f"- 关系：{' -> '.join(path.get('relations', [])) or '无'}")
    if not report.get("paths"):
        lines.append("- 暂无满足语义攻击链条件的路径，以下列出图谱中的证据关系：")
        graph_edges = report.get("graph", {}).get("edges", [])
        for edge in graph_edges:
            lines.append(
                f"- `{edge.get('source', 'unknown')}` "
                f"{edge.get('relation', 'unknown')} "
                f"`{edge.get('target', 'unknown')}`；"
                f"时间={edge.get('timestamp', 'unknown')}；"
                f"置信度={edge.get('confidence', 'unknown')}；"
                f"事件={', '.join(edge.get('related_event_ids', [])) or '无'}；"
                f"检测={', '.join(edge.get('related_detection_ids', [])) or '无'}"
            )
        if not graph_edges:
            lines.append("- 暂无图谱关系")

    graph = report.get("graph", {})
    lines.extend(["", "## 攻击图谱", ""])
    lines.append(f"- 图谱 ID：`{graph.get('graph_id', 'unknown')}`")
    lines.append(f"- 节点数量：{len(graph.get('nodes', []))}")
    lines.append(f"- 边数量：{len(graph.get('edges', []))}")
    lines.append("```json")
    lines.append(json_value(graph))
    lines.append("```")

    lines.extend(["", "## 进程树", ""])
    process_tree = report.get("process_tree", {})
    for node in process_tree.get("nodes", []):
        lines.append(
            f"- `{node.get('node_id', 'unknown')}` "
            f"主机={node.get('host', 'unknown')} "
            f"PID={node.get('pid', 'unknown')} "
            f"进程={node.get('name', 'unknown')} "
            f"用户={node.get('user') or 'unknown'}"
        )
    if not process_tree.get("nodes"):
        lines.append("- 暂无进程树证据")
    lines.append(f"- 父子关系数量：{len(process_tree.get('edges', []))}")

    lines.extend(["", "## APT/TTP 相似度", ""])
    for item in report.get("apt_matches", []):
        lines.append(
            f"- {item.get('profile', 'unknown')}: "
            f"{item.get('similarity', 0):.4f}; "
            f"技术={', '.join(item.get('matched_techniques', [])) or '无'}; "
            f"标签={', '.join(item.get('matched_tags', [])) or '无'}; "
            f"证据支持={'是' if item.get('evidence_based') else '否'}"
        )

    fingerprint = report.get("attacker_fingerprint", {})
    lines.extend([
        "",
        "## 攻击者指纹",
        "",
        f"- 指纹哈希：`{fingerprint.get('fingerprint_hash', 'unknown')}`",
        f"- 进程：{', '.join(fingerprint.get('process_names', [])) or '无'}",
        f"- 命令行：{', '.join(fingerprint.get('command_lines', [])) or '无'}",
        f"- User-Agent：{', '.join(fingerprint.get('user_agents', [])) or '无'}",
        f"- ATT&CK 技术：{', '.join(fingerprint.get('attack_techniques', [])) or '无'}",
        f"- 关联事件：{', '.join(fingerprint.get('evidence_event_ids', [])) or '无'}",
        "",
        "## C2 基础设施",
        "",
    ])
    for endpoint in report.get("c2_infrastructure", {}).get("endpoints", []):
        lines.append(
            f"- {endpoint.get('type', 'unknown')} `{endpoint.get('value', 'unknown')}` "
            f"端口={', '.join(str(port) for port in endpoint.get('ports', [])) or '未知'} "
            f"事件={', '.join(endpoint.get('event_ids', [])) or '无'}"
        )

    for relationship in report.get("c2_infrastructure", {}).get("relationships", []):
        lines.append(
            f"- 关系：`{relationship.get('source', 'unknown')}` "
            f"{relationship.get('relation', 'unknown')} "
            f"`{relationship.get('target', 'unknown')}` "
            f"事件={', '.join(relationship.get('event_ids', [])) or '无'}"
        )

    lines.extend(["", "## 检测结果", ""])
    for detection in report.get("detections", []):
        lines.append(
            f"- `{detection.get('detection_id', 'unknown')}` "
            f"`{detection.get('timestamp', 'unknown')}` "
            f"[{detection.get('severity', 'unknown')}] "
            f"{detection.get('title', 'unknown')}；"
            f"类型={detection.get('detection_type', 'unknown')}；"
            f"分析器={detection.get('analyzer', 'unknown')}；"
            f"置信度={detection.get('confidence', 'unknown')}；"
            f"技术={detection.get('attack_technique_id') or '无'}"
        )
        if detection.get("description"):
            lines.append(f"  - 描述：{detection['description']}")
        lines.append(f"  - 关联事件：{', '.join(detection.get('related_event_ids', [])) or '无'}")
        lines.append(f"  - 证据：`{json_value(detection.get('evidence', {}))}`")

    lines.extend(["", "## 原始事件明细", ""])
    for event in report.get("events", []):
        lines.extend([
            f"### `{event.get('event_id', 'unknown')}`",
            f"- 时间：{event.get('timestamp', 'unknown')}",
            f"- 来源：{event.get('source_type', 'unknown')} / {event.get('source', 'unknown')}",
            f"- 主机：{json_value(event.get('host', {}))}",
            f"- 类型与动作：{event.get('event_type', 'unknown')} / {event.get('action', 'unknown')}",
            f"- 主体：{json_value(event.get('subject', {}))}",
            f"- 对象：{json_value(event.get('object', {}))}",
            f"- 网络：{json_value(event.get('network', {}))}",
            f"- 严重性：{event.get('severity', 'unknown')}",
            f"- ATT&CK：{json_value(event.get('attack', {}))}",
            f"- 标签：{', '.join(event.get('tags', [])) or '无'}",
            f"- 原始数据：`{json_value(event.get('raw_data', {}))}`",
        ])

    lines.extend(["", "## 分析限制", ""])
    lines.extend(f"- {item}" for item in report.get("limitations", []))
    return "\n".join(lines) + "\n"
