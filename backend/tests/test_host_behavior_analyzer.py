from __future__ import annotations

import unittest
from datetime import datetime, timedelta, timezone

from app.analyzers.host_behavior import HostBehaviorAnalyzer
from app.schemas.event import (
    HostInfo,
    NetworkInfo,
    NormalizedEvent,
    ObjectInfo,
    SubjectInfo,
)


BASE_TIME = datetime(2026, 9, 8, 10, 0, tzinfo=timezone.utc)


def make_event(
    *,
    event_id: str,
    event_type: str,
    action: str,
    timestamp: datetime = BASE_TIME,
    source_type: str = "host_behavior",
    source: str = "test_sensor",
    hostname: str = "LAB-PC01",
    process_name: str | None = "worker.exe",
    pid: int | None = 1200,
    path: str | None = None,
    raw_data: dict | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type=source_type,
        source=source,
        host=HostInfo(hostname=hostname, os="windows"),
        event_type=event_type,
        subject=SubjectInfo(
            type="process",
            name=process_name,
            pid=pid,
            user="student",
        ),
        object=ObjectInfo(type="file", path=path) if path else None,
        action=action,
        raw_data=raw_data or {},
    )


def rule_ids(results) -> set[str]:
    return {str(result.evidence["rule_id"]) for result in results}


class HostBehaviorAnalyzerTests(unittest.TestCase):
    def test_document_process_spawning_powershell_is_detected(self) -> None:
        event = make_event(
            event_id="evt-process-1",
            event_type="process_create",
            action="create_process",
            process_name=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            pid=3152,
            raw_data={
                "parent_pid": 2200,
                "parent_process_name": r"C:\Program Files\Microsoft Office\WINWORD.EXE",
                "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
            },
        )

        results = HostBehaviorAnalyzer().analyze([event])

        self.assertIn("HB-PROC-001", rule_ids(results))
        self.assertIn("HB-PROC-003", rule_ids(results))
        parent_child = next(
            result
            for result in results
            if result.evidence["rule_id"] == "HB-PROC-001"
        )
        self.assertEqual(parent_child.related_event_ids, ["evt-process-1"])
        self.assertEqual(
            parent_child.related_entity_ids,
            [
                "process:LAB-PC01:2200",
                "process:LAB-PC01:3152",
            ],
        )
        self.assertEqual(parent_child.evidence["pid"], 3152)
        self.assertEqual(parent_child.evidence["ppid"], 2200)

    def test_process_create_supports_parent_subject_child_object_shape(self) -> None:
        event = NormalizedEvent(
            event_id="evt-object-child",
            timestamp=BASE_TIME,
            source_type="host_log",
            source="windows_security",
            host=HostInfo(hostname="OFFICE01", os="windows"),
            event_type="process_create",
            subject=SubjectInfo(
                type="process",
                name="WINWORD.EXE",
                pid=2200,
                user="-",
            ),
            object=ObjectInfo(
                type="process",
                name="powershell.exe",
                path=(
                    r"C:\Windows\System32\WindowsPowerShell\v1.0"
                    r"\powershell.exe"
                ),
                pid=3152,
            ),
            action="create_process",
            raw_data={
                "command_line": "powershell.exe -EncodedCommand SQBFAFgA",
            },
        )

        results = HostBehaviorAnalyzer().analyze([event])
        parent_child = next(
            result
            for result in results
            if result.evidence["rule_id"] == "HB-PROC-001"
        )

        self.assertEqual(
            parent_child.related_entity_ids,
            [
                "process:OFFICE01:2200",
                "process:OFFICE01:3152",
            ],
        )
        self.assertEqual(parent_child.evidence["process_name"], "powershell.exe")
        self.assertEqual(parent_child.evidence["parent_process"], "winword.exe")
        command_line_match = next(
            result
            for result in results
            if result.evidence["rule_id"] == "HB-PROC-003"
        )
        self.assertEqual(
            command_line_match.related_entity_ids,
            ["host:OFFICE01", "process:OFFICE01:3152"],
        )

    def test_common_parent_child_process_is_not_flagged(self) -> None:
        event = make_event(
            event_id="evt-process-safe",
            event_type="process_create",
            action="create_process",
            process_name="notepad.exe",
            raw_data={
                "ParentProcessId": "0x400",
                "ParentImage": r"C:\Windows\explorer.exe",
                "CommandLine": "notepad.exe notes.txt",
            },
        )

        self.assertEqual(HostBehaviorAnalyzer().analyze([event]), [])

    def test_member2_extracted_attributes_are_supported(self) -> None:
        event = make_event(
            event_id="evt-member2-nested-fields",
            event_type="process_create",
            action="process",
            source="windows_sysmon",
            hostname="WINDOWS-PC01",
            process_name="powershell.exe",
            pid=3152,
            raw_data={
                "extracted_attributes": {
                    "parent_pid": "2200",
                    "parent_process_name": "WINWORD.EXE",
                    "command_line": (
                        "powershell.exe -EncodedCommand SQBFAFgA"
                    ),
                }
            },
        )

        results = HostBehaviorAnalyzer().analyze([event])

        self.assertIn("HB-PROC-001", rule_ids(results))
        self.assertIn("HB-PROC-003", rule_ids(results))
        match = next(
            item
            for item in results
            if item.evidence["rule_id"] == "HB-PROC-001"
        )
        self.assertEqual(
            match.related_entity_ids,
            [
                "process:WINDOWS-PC01:2200",
                "process:WINDOWS-PC01:3152",
            ],
        )

    def test_password_database_command_without_pid_is_detected(self) -> None:
        event = make_event(
            event_id="evt-shadow-command",
            event_type="process_create",
            action="execute_command",
            source="linux_auditd",
            hostname="LINUX-SRV01",
            process_name="cat",
            pid=None,
            raw_data={"command_line": "cat /etc/passwd /etc/shadow"},
        )

        result = next(
            item
            for item in HostBehaviorAnalyzer().analyze([event])
            if item.evidence["rule_id"] == "HB-PROC-005"
        )

        self.assertEqual(
            result.related_entity_ids,
            ["host:LINUX-SRV01", "file:LINUX-SRV01:/etc/shadow"],
        )
        self.assertIn("credential_access", result.tags)

    def test_private_key_search_without_pid_is_detected(self) -> None:
        event = make_event(
            event_id="evt-private-key-search",
            event_type="process_create",
            action="execute_command",
            source="linux_auditd",
            hostname="LINUX-SRV01",
            process_name="grep",
            pid=None,
            raw_data={"command_line": "grep -E 'id_rsa.*$' input.txt"},
        )

        result = next(
            item
            for item in HostBehaviorAnalyzer().analyze([event])
            if item.evidence["rule_id"] == "HB-PROC-006"
        )

        self.assertEqual(
            result.related_entity_ids,
            ["host:LINUX-SRV01", "file:LINUX-SRV01:~/.ssh/id_rsa"],
        )
        self.assertTrue(result.evidence["inferred_target"])

    def test_parent_name_is_resolved_from_earlier_process_event(self) -> None:
        parent_event = make_event(
            event_id="evt-parent",
            event_type="process_create",
            action="create_process",
            timestamp=BASE_TIME,
            process_name="WINWORD.EXE",
            pid=2200,
            raw_data={
                "parent_pid": 1000,
                "parent_process_name": "explorer.exe",
                "command_line": "WINWORD.EXE report.docx",
            },
        )
        child_event = make_event(
            event_id="evt-child",
            event_type="process_create",
            action="create_process",
            timestamp=BASE_TIME + timedelta(seconds=2),
            process_name="powershell.exe",
            pid=3152,
            raw_data={
                "parent_pid": 2200,
                "command_line": "powershell.exe Get-Date",
            },
        )

        results = HostBehaviorAnalyzer().analyze(
            [child_event, parent_event]
        )

        match = next(
            result
            for result in results
            if result.evidence["rule_id"] == "HB-PROC-001"
        )
        self.assertEqual(match.evidence["parent_process"], "winword.exe")

    def test_linux_sensitive_file_read_is_detected(self) -> None:
        event = make_event(
            event_id="evt-file-1",
            event_type="file_read",
            action="read_file",
            source="linux_auditd",
            hostname="LINUX-SRV01",
            process_name="/usr/bin/cat",
            pid=772,
            path="/etc/shadow",
        )

        results = HostBehaviorAnalyzer().analyze([event])

        self.assertIn("HB-FILE-001", rule_ids(results))
        self.assertEqual(
            results[0].related_entity_ids,
            [
                "process:LINUX-SRV01:772",
                "file:LINUX-SRV01:/etc/shadow",
            ],
        )
        self.assertEqual(results[0].evidence["file_path"], "/etc/shadow")
        self.assertEqual(results[0].evidence["operation"], "read_file")

    def test_startup_file_modification_is_detected(self) -> None:
        event = make_event(
            event_id="evt-file-2",
            event_type="file_modify",
            action="write_file",
            path=(
                r"C:\Users\student\AppData\Roaming\Microsoft\Windows"
                r"\Start Menu\Programs\Startup\update.cmd"
            ),
        )

        self.assertIn(
            "HB-FILE-002",
            rule_ids(HostBehaviorAnalyzer().analyze([event])),
        )

    def test_file_event_without_process_uses_host_as_source(self) -> None:
        event = NormalizedEvent(
            event_id="evt-file-no-process",
            timestamp=BASE_TIME,
            source_type="host_log",
            source="linux_auditd",
            host=HostInfo(hostname="LINUX-WEB01", os="linux"),
            event_type="file_delete",
            subject=None,
            object=ObjectInfo(
                type="file",
                name="/var/log/auth.log",
                path="/var/log/auth.log",
            ),
            action="delete",
            raw_data={"name": "/var/log/auth.log", "nametype": "DELETE"},
        )

        results = HostBehaviorAnalyzer().analyze([event])

        self.assertEqual(
            results[0].related_entity_ids,
            [
                "host:LINUX-WEB01",
                "file:LINUX-WEB01:/var/log/auth.log",
            ],
        )

    def test_high_risk_syscall_is_detected(self) -> None:
        event = make_event(
            event_id="evt-syscall-1",
            event_type="system_call",
            action="ptrace",
            source="linux_auditd",
            hostname="LINUX-SRV01",
            process_name="/tmp/debugger",
            pid=900,
            raw_data={"syscall": "ptrace", "arguments": {"request": 16}},
        )

        results = HostBehaviorAnalyzer().analyze([event])

        self.assertIn("HB-SYSCALL-001", rule_ids(results))
        self.assertEqual(results[0].evidence["syscall"], "ptrace")
        self.assertEqual(
            results[0].related_entity_ids,
            ["host:LINUX-SRV01", "process:LINUX-SRV01:900"],
        )

    def test_symbolic_syscall_name_is_preferred_over_numeric_value(self) -> None:
        event = make_event(
            event_id="evt-symbolic-syscall",
            event_type="system_call",
            action="system_call",
            source="linux_auditd",
            hostname="LINUX-SRV01",
            process_name="debugger",
            pid=901,
            raw_data={
                "syscall": "101",
                "syscall_name": "ptrace",
                "arguments": "PTRACE_ATTACH",
                "result": "success",
            },
        )

        results = HostBehaviorAnalyzer().analyze([event])

        self.assertIn("HB-SYSCALL-001", rule_ids(results))
        self.assertEqual(results[0].evidence["syscall"], "ptrace")

    def test_successful_exec_to_root_is_detected(self) -> None:
        event = make_event(
            event_id="evt-doas-root",
            event_type="system_call",
            action="system_call",
            source="linux_auditd",
            hostname="LINUX-SRV01",
            process_name="doas",
            pid=5110,
            raw_data={
                "syscall_name": "execve",
                "uid": "ubuntu",
                "euid": "root",
                "auid": "ubuntu",
                "success": "yes",
                "exe": "/usr/bin/doas",
            },
        )

        result = next(
            item
            for item in HostBehaviorAnalyzer().analyze([event])
            if item.evidence["rule_id"] == "HB-SYSCALL-003"
        )

        self.assertEqual(
            result.related_entity_ids,
            ["process:LINUX-SRV01:5110", "user:LINUX-SRV01:root"],
        )
        self.assertIn("privilege_escalation", result.tags)

    def test_exec_without_identity_change_is_not_flagged(self) -> None:
        event = make_event(
            event_id="evt-normal-exec",
            event_type="system_call",
            action="system_call",
            source="linux_auditd",
            hostname="LINUX-SRV01",
            process_name="bash",
            pid=5510,
            raw_data={
                "syscall_name": "execve",
                "uid": "1000",
                "euid": "1000",
                "success": "yes",
            },
        )

        self.assertEqual(HostBehaviorAnalyzer().analyze([event]), [])

    def test_cross_process_syscall_preserves_source_target_direction(self) -> None:
        event = make_event(
            event_id="evt-syscall-memory",
            event_type="system_call",
            action="process_vm_writev",
            source="ebpf",
            hostname="LINUX-SRV01",
            process_name="/tmp/injector",
            pid=1900,
            raw_data={
                "syscall": "process_vm_writev",
                "arguments": {"target_pid": 801, "bytes": 512},
                "result": 512,
            },
        )

        results = HostBehaviorAnalyzer().analyze([event])

        self.assertEqual(
            results[0].related_entity_ids,
            [
                "process:LINUX-SRV01:1900",
                "process:LINUX-SRV01:801",
            ],
        )
        self.assertEqual(results[0].evidence["target_pid"], 801)

    def test_memfd_then_execve_sequence_is_detected(self) -> None:
        events = [
            make_event(
                event_id="evt-memfd",
                event_type="system_call",
                action="memfd_create",
                source="ebpf",
                hostname="LINUX-SRV01",
                process_name="/tmp/loader",
                pid=445,
                raw_data={"syscall": "memfd_create"},
            ),
            make_event(
                event_id="evt-execve",
                event_type="system_call",
                action="execve",
                timestamp=BASE_TIME + timedelta(seconds=5),
                source="ebpf",
                hostname="LINUX-SRV01",
                process_name="/tmp/loader",
                pid=445,
                raw_data={"syscall": "execve"},
            ),
        ]

        results = HostBehaviorAnalyzer().analyze(list(reversed(events)))
        sequence = next(
            result
            for result in results
            if result.evidence["rule_id"] == "HB-SYSCALL-002"
        )

        self.assertEqual(
            sequence.related_event_ids,
            ["evt-memfd", "evt-execve"],
        )
        self.assertEqual(
            sequence.related_entity_ids,
            ["host:LINUX-SRV01", "process:LINUX-SRV01:445"],
        )

    def test_bulk_file_change_threshold_is_configurable(self) -> None:
        events = [
            make_event(
                event_id=f"evt-bulk-{index}",
                event_type="file_modify",
                action="write_file",
                timestamp=BASE_TIME + timedelta(seconds=index),
                path=f"/home/student/document-{index}.txt",
                hostname="LINUX-PC01",
                process_name="/tmp/encryptor",
                pid=911,
            )
            for index in range(3)
        ]
        analyzer = HostBehaviorAnalyzer(
            bulk_file_threshold=3,
            bulk_file_window_seconds=10,
        )

        results = analyzer.analyze(events)

        bulk = next(
            result
            for result in results
            if result.evidence["rule_id"] == "HB-FILE-005"
        )
        self.assertEqual(bulk.evidence["event_count"], 3)
        self.assertEqual(len(bulk.related_event_ids), 3)

    def test_explicit_memory_injection_event_is_detected(self) -> None:
        event = make_event(
            event_id="evt-memory-1",
            event_type="remote_thread_create",
            action="create_remote_thread",
            process_name="injector.exe",
            pid=1010,
        )
        event.object = ObjectInfo(type="process", name="lsass.exe", pid=700)

        results = HostBehaviorAnalyzer().analyze([event])

        self.assertIn("HB-MEM-001", rule_ids(results))
        self.assertEqual(results[0].detection_type, "malicious_behavior")
        self.assertEqual(
            results[0].related_entity_ids,
            [
                "process:LAB-PC01:1010",
                "process:LAB-PC01:700",
            ],
        )

    def test_network_event_and_missing_optional_fields_do_not_crash(self) -> None:
        network_event = NormalizedEvent(
            event_id="evt-network-1",
            timestamp=BASE_TIME,
            source_type="network_traffic",
            source="zeek",
            host=HostInfo(),
            event_type="network_connection",
            network=NetworkInfo(dst_ip="198.51.100.10", dst_port=443),
            action="connect",
        )
        incomplete_host_event = NormalizedEvent(
            event_id="evt-incomplete",
            timestamp=BASE_TIME,
            source_type="host_behavior",
            source="test_sensor",
            host=HostInfo(),
            event_type="process_create",
            action="create_process",
        )

        self.assertEqual(
            HostBehaviorAnalyzer().analyze(
                [network_event, incomplete_host_event]
            ),
            [],
        )


if __name__ == "__main__":
    unittest.main()
