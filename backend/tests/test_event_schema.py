from pydantic import ValidationError

from app.schemas.event import (
    HostInfo,
    NormalizedEvent,
    SubjectInfo,
)


def test_valid_event() -> None:
    event = NormalizedEvent(
        timestamp="2026-09-08T10:20:00Z",
        source_type="host_log",
        source="windows_sysmon",
        host=HostInfo(
            hostname="WIN-PC01",
            ip="192.168.1.20",
            os="windows",
        ),
        event_type="process_create",
        subject=SubjectInfo(
            type="process",
            name="powershell.exe",
            pid=3152,
            user="administrator",
        ),
        action="create_process",
        severity="medium",
        tags=["powershell", "process"],
    )

    print("Valid event created successfully.")
    print(event.model_dump_json(indent=2))


def test_invalid_event() -> None:
    try:
        NormalizedEvent(
            timestamp="2026-09-08T10:20:00Z",

            # 故意填写错误值
            source_type="unknown_source",

            source="test",
            event_type="process_create",
            action="create_process",

            # 故意填写错误值
            severity="danger",
        )

    except ValidationError as exc:
        print("\nInvalid event rejected successfully.")
        print(exc)


def main() -> None:
    test_valid_event()
    test_invalid_event()


if __name__ == "__main__":
    main()