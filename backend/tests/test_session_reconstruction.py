from datetime import datetime, timedelta, timezone

from app.schemas.event import HostInfo, NetworkInfo, NormalizedEvent, SubjectInfo
from app.services.session_reconstruction import SessionReconstructionService


def _event(
    *,
    event_id: str,
    host: str,
    user: str,
    src_ip: str,
    event_type: str,
    action: str,
    timestamp: datetime,
    subject_name: str | None = None,
    process_name: str | None = None,
) -> NormalizedEvent:
    return NormalizedEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_type="host_log",
        source="security",
        host=HostInfo(hostname=host, ip="10.0.0.11", os="windows"),
        event_type=event_type,
        subject=SubjectInfo(type="user", name=subject_name or user, user=user),
        network=NetworkInfo(src_ip=src_ip, dst_ip="10.0.0.22", protocol="tcp"),
        action=action,
        raw_data={"process_name": process_name or subject_name or user},
    )


def test_reconstruct_login_sessions_and_detect_suspicious_processes() -> None:
    service = SessionReconstructionService()
    base = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)

    events = [
        _event(
            event_id="evt-1",
            host="WEB01",
            user="alice",
            src_ip="192.168.10.20",
            event_type="logon",
            action="login",
            timestamp=base,
            subject_name="SYSTEM",
            process_name="winlogon.exe",
        ),
        _event(
            event_id="evt-2",
            host="WEB01",
            user="alice",
            src_ip="192.168.10.20",
            event_type="process_create",
            action="spawn",
            timestamp=base + timedelta(minutes=1),
            subject_name="powershell.exe",
            process_name="powershell.exe",
        ),
        _event(
            event_id="evt-3",
            host="WEB01",
            user="alice",
            src_ip="192.168.10.20",
            event_type="logoff",
            action="logout",
            timestamp=base + timedelta(minutes=12),
            subject_name="SYSTEM",
            process_name="winlogon.exe",
        ),
    ]

    sessions = service.reconstruct_sessions(events)
    assert len(sessions) == 1
    assert sessions[0]["user"] == "alice"
    assert sessions[0]["login_at"] == base
    assert sessions[0]["logout_at"] == base + timedelta(minutes=12)
    assert sessions[0]["duration_seconds"] == 720

    summary = service.build_summary(events)
    assert any(item["name"] == "powershell.exe" for item in summary["suspicious_processes"])
    assert summary["session_count"] == 1


def test_logon_id_keeps_concurrent_user_sessions_separate() -> None:
    service = SessionReconstructionService()
    base = datetime(2026, 9, 8, 10, 0, 0, tzinfo=timezone.utc)

    def event(event_id: str, event_type: str, minute: int, logon_id: str, process: str | None = None) -> NormalizedEvent:
        return NormalizedEvent(
            event_id=event_id,
            timestamp=base + timedelta(minutes=minute),
            source_type="host_log",
            source="windows_security",
            host=HostInfo(hostname="WEB01", os="windows"),
            event_type=event_type,
            subject=SubjectInfo(type="process" if process else "user", name=process or "alice", user="alice"),
            action="login" if event_type == "user_login" else event_type,
            raw_data={"logon_id": logon_id, "process_name": process} if process else {"logon_id": logon_id},
        )

    sessions = service.reconstruct_sessions([
        event("login-a", "user_login", 0, "A"),
        event("login-b", "user_login", 1, "B"),
        event("proc-b", "process_create", 2, "B", "powershell.exe"),
        event("logout-b", "user_logout", 3, "B"),
        event("logout-a", "user_logout", 4, "A"),
    ])

    by_id = {item["logon_id"]: item for item in sessions}
    assert by_id["B"]["processes"] == ["powershell.exe"]
    assert by_id["B"]["logout_event_id"] == "logout-b"
    assert by_id["A"]["logout_event_id"] == "logout-a"
