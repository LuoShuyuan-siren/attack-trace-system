from pathlib import Path

from app.analyzers.host_behavior import HostBehaviorAnalyzer
from app.collectors.linux_realtime import LinuxRealtimeCollector
from app.collectors.windows_realtime import WindowsRealtimeCollector
from app.schemas.event import HostInfo, NormalizedEvent, ObjectInfo, SubjectInfo


def test_linux_ebpf_jsonl_is_incremental(tmp_path: Path) -> None:
    output = tmp_path / "events.jsonl"
    output.write_text(
        '{"timestamp":"2026-09-11T10:00:00Z","pid":42,"syscall":"process_vm_writev",'
        '"target_pid":99,"comm":"debugger","action":"memory_write"}\n',
        encoding="utf-8",
    )
    collector = LinuxRealtimeCollector(hostname="linux-01", ebpf_jsonl=output)

    events = collector.collect_once()

    assert len(events) == 1
    assert events[0].source == "ebpf"
    assert events[0].raw_data["syscall_name"] == "process_vm_writev"
    assert events[0].object.pid == 99
    assert len(HostBehaviorAnalyzer().analyze(events)) == 1
    assert collector.collect_once() == []


def test_linux_ebpf_path_is_preserved_in_syscall_arguments(tmp_path: Path) -> None:
    output = tmp_path / "events.jsonl"
    output.write_text(
        '{"timestamp":"2026-09-11T10:00:00Z","pid":42,"syscall":"openat",'
        '"path":"/etc/shadow","arguments":{"arg0":-100}}\n',
        encoding="utf-8",
    )

    event = LinuxRealtimeCollector(hostname="linux-01", ebpf_jsonl=output).collect_once()[0]

    assert event.raw_data["arguments"]["path"] == "/etc/shadow"


def test_linux_ebpf_connect_is_normalized_to_network_info(tmp_path: Path) -> None:
    output = tmp_path / "events.jsonl"
    output.write_text(
        '{"timestamp":"2026-09-11T10:00:00Z","pid":42,"syscall":"connect",'
        '"remote_ip":"203.0.113.7","remote_port":443}\n',
        encoding="utf-8",
    )

    event = LinuxRealtimeCollector(hostname="linux-01", ebpf_jsonl=output).collect_once()[0]

    assert event.network is not None
    assert event.network.dst_ip == "203.0.113.7"
    assert event.network.dst_port == 443
    assert event.network.protocol == "TCP"


def test_windows_realtime_is_safe_off_windows() -> None:
    assert WindowsRealtimeCollector().collect_once() == []


def test_windows_event_record_cursor_survives_restart(tmp_path: Path, monkeypatch) -> None:
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>1</EventID><EventRecordID>42</EventRecordID>"
        "<Computer>WIN01</Computer><TimeCreated SystemTime=\"2026-09-11T10:00:00Z\"/>"
        "</System><EventData /></Event>"
    )
    commands: list[list[str]] = []

    class FakeCompleted:
        returncode = 0
        stdout = xml

    class FakeParser:
        @staticmethod
        def _parse_event(*_args):
            return None

    monkeypatch.setattr("app.collectors.windows_realtime._is_windows", lambda: True)
    monkeypatch.setattr(
        "app.collectors.windows_realtime.subprocess.run",
        lambda command, **_: commands.append(command) or FakeCompleted(),
    )

    state = tmp_path / "windows-cursors.json"
    first = WindowsRealtimeCollector(channels=("Test",), state_path=state)
    first._parser = FakeParser()
    assert first.collect_once() == []
    assert state.read_text(encoding="utf-8").find("42") >= 0

    second = WindowsRealtimeCollector(channels=("Test",), state_path=state)
    second._parser = FakeParser()
    assert second.collect_once() == []
    assert any("EventRecordID > 42" in item for item in commands[-1])


def test_reflective_load_is_detected() -> None:
    event = NormalizedEvent(
        timestamp="2026-09-11T10:00:00Z",
        source_type="host_behavior",
        source="ebpf",
        host=HostInfo(hostname="linux-01", os="linux"),
        event_type="reflective_load",
        subject=SubjectInfo(type="process", name="loader", pid=42),
        object=ObjectInfo(type="image", name="payload.dll"),
        action="load_reflective_module",
        raw_data={"technique": "reflective_dll_loading"},
    )

    results = HostBehaviorAnalyzer().analyze([event])

    assert results[0].evidence["rule_id"] == "HB-MEM-001"
    assert results[0].evidence["technique"] == "reflective_dll_loading"
