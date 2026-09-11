from pathlib import Path

from app.collectors.system_log_tail import LinuxSystemLogTail
from app.services.report_export import render_report_markdown


def test_markdown_report_contains_key_sections() -> None:
    markdown = render_report_markdown({
        "generated_at": "2026-09-11T10:00:00Z",
        "event_count": 2,
        "detection_count": 1,
        "timeline": [{"timestamp": "2026-09-11T10:00:00Z", "stage": "command_and_control", "technique_id": "T1071.001", "host": "web01"}],
        "paths": [{"score": 0.9, "nodes": ["host:web01", "ip:10.0.0.5"], "relations": ["c2_communication"]}],
        "graph": {"graph_id": "graph-current", "nodes": [{"node_id": "host:web01"}], "edges": []},
        "process_tree": {"nodes": [{"node_id": "process:web01:42", "pid": 42, "name": "powershell.exe", "host": "web01"}], "edges": []},
        "apt_matches": [{"profile": "APT29", "similarity": 0.5, "matched_techniques": ["T1071.001"]}],
        "attacker_fingerprint": {"fingerprint_hash": "abc", "process_names": ["powershell.exe"], "command_lines": ["whoami"], "user_agents": []},
        "c2_infrastructure": {"endpoints": [{"type": "ip", "value": "10.0.0.5", "ports": [443]}]},
        "detections": [{"detection_id": "det-1", "timestamp": "2026-09-11T10:00:00Z", "severity": "high", "title": "Suspicious command", "evidence": {"command": "whoami"}}],
        "events": [{"event_id": "evt-1", "timestamp": "2026-09-11T10:00:00Z", "source_type": "host_log", "source": "sysmon", "event_type": "process_start", "action": "start", "severity": "high", "raw_data": {"command_line": "whoami"}}],
        "limitations": ["test limitation"],
    })

    assert "# 攻击溯源分析报告" in markdown
    assert "APT29" in markdown
    assert "10.0.0.5" in markdown
    assert "## 攻击路径" in markdown
    assert "## 攻击图谱" in markdown
    assert "## 检测结果" in markdown
    assert "whoami" in markdown
    assert "evt-1" in markdown


def test_markdown_report_falls_back_to_anomaly_evidence() -> None:
    markdown = render_report_markdown({
        "event_count": 1,
        "detection_count": 1,
        "timeline": [],
        "paths": [],
        "graph": {
            "edges": [{
                "source": "host:web01",
                "relation": "anomaly",
                "target": "process:web01:42",
                "related_event_ids": ["evt-1"],
                "related_detection_ids": ["det-1"],
            }],
        },
        "detections": [{
            "timestamp": "2026-09-11T10:00:00Z",
            "severity": "high",
            "title": "Sequence anomaly",
            "related_event_ids": ["evt-1"],
        }],
    })

    assert "暂无可由语义关系重建的攻击阶段" in markdown
    assert "Sequence anomaly" in markdown
    assert "host:web01" in markdown


def test_linux_system_log_tail_reads_only_appended_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "auth.log"
    log_path.write_text(
        "Sep 11 10:00:00 web01 sshd[20]: Accepted publickey for analyst from 10.0.0.2 port 5522 ssh2\n",
        encoding="utf-8",
    )
    tail = LinuxSystemLogTail(log_path, hostname="web01")

    first = tail.collect_once()
    second = tail.collect_once()
    log_path.write_text(
        log_path.read_text(encoding="utf-8")
        + "Sep 11 10:00:01 web01 sshd[20]: Failed password for analyst from 10.0.0.2 port 5522 ssh2\n",
        encoding="utf-8",
    )
    third = tail.collect_once()

    assert len(first) == 1
    assert second == []
    assert len(third) == 1
