from pathlib import Path

from app.parsers.linux import LinuxLogParser


def test_linux_auth_and_audit(tmp_path: Path) -> None:
    log = tmp_path / "linux.log"
    log.write_text("Sep  8 10:00:01 web sshd[10]: Accepted publickey for deploy from 10.0.0.2 port 5522 ssh2\n" "type=SYSCALL msg=audit(1788861602.000:1): arch=c000003e pid=42 ppid=10 ppcomm=\"sshd\" uid=0 syscall=59 comm=\"bash\" exe=\"/bin/bash\" arguments=\"id\" result=success\n" "type=PATH msg=audit(1788861603.000:2): pid=42 uid=0 comm=\"bash\" exe=\"/bin/bash\" name=\"/tmp/dropper\" nametype=CREATE\n", encoding="utf-8")
    events = LinuxLogParser("web", "10.0.0.5", year=2026).parse(log)
    assert len(events) == 3
    assert events[0].source == "linux_auth"
    assert events[1].event_type == "system_call"
    assert events[1].subject.pid == 42
    assert events[1].raw_data["syscall_name"] == "execve"
    assert events[1].raw_data["arch"] == "c000003e"
    assert events[1].raw_data["parent_process_name"] == "sshd"
    assert events[2].subject.pid == 42
    assert events[2].object.path == "/tmp/dropper"


def test_linux_syslog_process(tmp_path: Path) -> None:
    log = tmp_path / "syslog"
    log.write_text("Sep  9 14:09:30 kali sudo[7995]: kali : TTY=pts/0 ; COMMAND=/usr/bin/cp /tmp/a /tmp/b\n", encoding="utf-8")
    events = LinuxLogParser("kali", "192.168.35.10", year=2026).parse(log)
    assert len(events) == 1
    assert events[0].source == "linux_syslog"
    assert events[0].subject.pid == 7995
