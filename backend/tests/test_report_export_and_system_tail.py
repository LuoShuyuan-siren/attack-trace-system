from pathlib import Path

from app.collectors.system_log_tail import LinuxSystemLogTail
from app.services.report_export import render_report_markdown


def test_markdown_report_contains_key_sections() -> None:
    markdown = render_report_markdown({
        "generated_at": "2026-09-11T10:00:00Z",
        "event_count": 2,
        "detection_count": 1,
        "timeline": [{"timestamp": "2026-09-11T10:00:00Z", "stage": "command_and_control", "technique_id": "T1071.001", "host": "web01"}],
        "apt_matches": [{"profile": "APT29", "similarity": 0.5, "matched_techniques": ["T1071.001"]}],
        "attacker_fingerprint": {"fingerprint_hash": "abc", "process_names": ["powershell.exe"], "user_agents": []},
        "c2_infrastructure": {"endpoints": [{"type": "ip", "value": "10.0.0.5", "ports": [443]}]},
        "limitations": ["test limitation"],
    })

    assert "# 攻击溯源分析报告" in markdown
    assert "APT29" in markdown
    assert "10.0.0.5" in markdown


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
