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


def test_linux_ssh_session_iso_and_journal_formats(tmp_path: Path) -> None:
    log = tmp_path / "auth.log"
    log.write_text(
        "2026-09-10T05:12:27.000000+00:00 ubuntu-server sshd-session[1888]: "
        "pam_unix(sshd:auth): authentication failure; rhost=10.10.10.10 user=attacktest\n"
        "2026-09-10T05:12:29.000000+00:00 ubuntu-server sshd-session[1888]: "
        "Failed password for attacktest from 10.10.10.10 port 52232 ssh2\n"
        "Sep 10 05:13:07 ubuntu-server sshd-session[1891]: "
        "Accepted password for attacktest from 10.10.10.10 port 52180 ssh2\n",
        encoding="utf-8",
    )

    events = LinuxLogParser("ubuntu-server", "10.10.10.254", year=2026).parse(log)

    assert len(events) == 3
    assert [event.action for event in events] == ["login_failure", "login_failure", "login_success"]
    assert events[0].timestamp.isoformat() == "2026-09-10T05:12:27+00:00"
    assert events[0].subject.user == "attacktest"
    assert events[0].network.src_ip == "10.10.10.10"
    assert events[0].network.src_port is None
    assert events[1].network.src_port == 52232
    assert events[2].network.src_port == 52180


def test_linux_ssh_ignores_non_authentication_messages(tmp_path: Path) -> None:
    log = tmp_path / "ssh-journal.log"
    log.write_text(
        "Sep 10 05:05:55 ubuntu-server sshd[1191]: Server listening on 0.0.0.0 port 22.\n"
        "Sep 10 05:12:39 ubuntu-server sshd-session[1888]: "
        "Connection closed by authenticating user attacktest 10.10.10.10 port 52232 [preauth]\n",
        encoding="utf-8",
    )

    assert LinuxLogParser("ubuntu-server", "10.10.10.254", year=2026).parse(log) == []


def test_linux_dated_audit_and_hex_proctitle(tmp_path: Path) -> None:
    log = tmp_path / "audit.log"
    log.write_text(
        "type=SYSCALL msg=audit(04/16/2025 08:20:03.591:45423) : "
        "arch=x86_64 syscall=openat success=yes exit=4 ppid=2476 pid=5110 "
        "uid=ubuntu euid=root comm=doas exe=/usr/bin/doas\n"
        "type=PROCTITLE msg=audit(1723042099.699:13369): "
        "proctitle=7375646F00636174002F6574632F736861646F77\n",
        encoding="utf-8",
    )

    events = LinuxLogParser("ubuntu", year=2026).parse(log)

    assert len(events) == 2
    assert events[0].event_type == "system_call"
    assert events[0].timestamp.isoformat() == "2025-04-16T08:20:03.591000+00:00"
    assert events[0].raw_data["syscall_name"] == "openat"
    assert events[1].event_type == "process_create"
    assert events[1].subject.name == "sudo"
    assert events[1].raw_data["command_line"] == "sudo cat /etc/shadow"


def test_linux_plain_proctitle_and_standalone_execve_arguments(tmp_path: Path) -> None:
    log = tmp_path / "commands.log"
    log.write_text(
        "type=PROCTITLE msg=audit(02/20/2025 13:07:46.504:118908) : "
        "proctitle=cat /etc/shadow /etc/gshadow\n"
        "type=EXECVE msg=audit(02/20/2025 13:07:05.711:110417) : "
        "argc=3 a0=grep a1=-E a2=id_rsa.*$\n",
        encoding="utf-8",
    )

    events = LinuxLogParser("ubuntu", year=2026).parse(log)

    assert events[0].raw_data["command_line"] == "cat /etc/shadow /etc/gshadow"
    assert events[1].raw_data["command_line"] == "grep -E id_rsa.*$"
    assert events[1].subject.name == "grep"


def test_linux_embedded_kernel_audit_and_su_login(tmp_path: Path) -> None:
    log = tmp_path / "linux.log"
    log.write_text(
        "May  6 17:24:02 snapubuntu su: pam_unix(su:session): "
        "session opened for user snapattack(uid=0) by (uid=1000)\n"
        "May  7 06:42:22 snapubuntu kernel: [48703.161027] audit: "
        "type=1300 audit(1778136141.681:369131): arch=c000003e syscall=59 "
        "success=no exit=-2 ppid=32200 pid=32562 uid=0 comm=apt-check exe=/usr/bin/python3.10\n",
        encoding="utf-8",
    )

    events = LinuxLogParser("snapubuntu", year=2026).parse(log)

    assert len(events) == 2
    assert events[0].event_type == "user_login"
    assert events[0].subject.user == "snapattack"
    assert events[0].raw_data["auth_method"] == "su"
    assert events[1].event_type == "system_call"
    assert events[1].raw_data["syscall_name"] == "execve"
    assert events[1].raw_data["result"] == "no"
