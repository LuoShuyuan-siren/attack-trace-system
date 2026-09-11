from __future__ import annotations

from typing import Any


def render_report_markdown(report: dict[str, Any]) -> str:
    lines = [
        "# 攻击溯源分析报告",
        "",
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
        lines.append("- 暂无攻击阶段证据")

    lines.extend(["", "## APT/TTP 相似度", ""])
    for item in report.get("apt_matches", []):
        lines.append(
            f"- {item['profile']}: {item['similarity']:.4f}; "
            f"技术={', '.join(item['matched_techniques']) or '无'}"
        )

    fingerprint = report.get("attacker_fingerprint", {})
    lines.extend([
        "",
        "## 攻击者指纹",
        "",
        f"- 指纹哈希：`{fingerprint.get('fingerprint_hash', 'unknown')}`",
        f"- 进程：{', '.join(fingerprint.get('process_names', [])) or '无'}",
        f"- User-Agent：{', '.join(fingerprint.get('user_agents', [])) or '无'}",
        "",
        "## C2 基础设施",
        "",
    ])
    for endpoint in report.get("c2_infrastructure", {}).get("endpoints", []):
        lines.append(
            f"- {endpoint['type']} `{endpoint['value']}` "
            f"端口={', '.join(str(port) for port in endpoint['ports']) or '未知'}"
        )

    lines.extend(["", "## 局限性", ""])
    lines.extend(f"- {item}" for item in report.get("limitations", []))
    return "\n".join(lines) + "\n"
