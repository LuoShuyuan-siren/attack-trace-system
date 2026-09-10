from app.parsers.windows_log_parser import WindowsLogParser


parser = WindowsLogParser()
TIMESTAMP = "2026-09-10T10:00:00Z"
HOSTNAME = "WIN11"


def test_sysmon_3_network_connection():
    event = parser._parse_event(
        3,
        {
            "Image": r"C:\Windows\System32\cmd.exe",
            "ProcessId": "1234",
            "User": r"WIN11\admin",
            "SourceIp": "192.168.1.10",
            "SourcePort": "50000",
            "DestinationIp": "192.168.1.20",
            "DestinationPort": "443",
            "Protocol": "tcp",
        },
        TIMESTAMP,
        HOSTNAME,
    )

    assert event is not None
    assert event.event_type == "network_connection"
    assert event.network.src_ip == "192.168.1.10"
    assert event.network.dst_ip == "192.168.1.20"
    assert event.network.dst_port == 443


def test_sysmon_13_registry_modify():
    event = parser._parse_event(
        13,
        {
            "Image": r"C:\Windows\System32\reg.exe",
            "ProcessId": "2000",
            "User": r"WIN11\admin",
            "TargetObject": r"HKCU\Software\Test",
            "Details": "DWORD (0x00000001)",
        },
        TIMESTAMP,
        HOSTNAME,
    )

    assert event is not None
    assert event.event_type == "registry_modify"
    assert event.object.type == "registry"
    assert event.object.path == r"HKCU\Software\Test"


def test_sysmon_22_dns_query():
    event = parser._parse_event(
        22,
        {
            "Image": r"C:\Windows\System32\powershell.exe",
            "ProcessId": "3000",
            "User": r"WIN11\admin",
            "QueryName": "example.com",
            "QueryStatus": "0",
            "QueryResults": "1.2.3.4",
        },
        TIMESTAMP,
        HOSTNAME,
    )

    assert event is not None
    assert event.event_type == "dns_query"
    assert event.object.name == "example.com"
    assert event.network.protocol == "dns"
    assert event.raw_data["query"] == "example.com"


def test_security_4624_source_ip():
    event = parser._parse_event(
        4624,
        {
            "TargetUserName": "admin",
            "IpAddress": "192.168.1.100",
            "IpPort": "49152",
        },
        TIMESTAMP,
        HOSTNAME,
    )

    assert event is not None
    assert event.event_type == "user_login"
    assert event.network.src_ip == "192.168.1.100"
    assert event.network.src_port == 49152
    assert event.network.dst_ip is None