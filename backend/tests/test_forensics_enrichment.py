from app.schemas.detection import DetectionResult
from app.schemas.event import HostInfo, NormalizedEvent, SubjectInfo
from app.services.forensics_enrichment import (
    align_event_times,
    build_process_tree,
    load_apt_profiles,
    match_apt_profiles,
)


def test_align_event_times_preserves_original_timestamp() -> None:
    event = NormalizedEvent(
        timestamp="2026-09-11T10:00:01Z",
        source_type="host_behavior",
        source="collector_agent",
        host=HostInfo(hostname="host-a"),
        event_type="process_snapshot",
        subject=SubjectInfo(type="process", name="powershell.exe", pid=22),
        action="observe_process",
        raw_data={"clock_offset_ms": 1000},
    )

    aligned = align_event_times([event])[0]

    assert aligned.timestamp.isoformat() == "2026-09-11T10:00:00+00:00"
    assert aligned.raw_data["original_timestamp"] == "2026-09-11T10:00:01+00:00"
    assert aligned.raw_data["clock_source"] == "event_metadata"
    assert aligned.raw_data["clock_confidence"] == 0.0
    assert aligned.raw_data["alignment_applied"] is True


def test_process_tree_and_apt_match_use_event_evidence() -> None:
    parent = NormalizedEvent(
        timestamp="2026-09-11T10:00:00Z",
        source_type="host_behavior",
        source="collector_agent",
        host=HostInfo(hostname="host-a"),
        event_type="process_snapshot",
        subject=SubjectInfo(type="process", name="powershell.exe", pid=22),
        action="observe_process",
        raw_data={"ppid": 1},
        tags=["powershell"],
    )
    child = parent.model_copy(update={
        "event_id": "child",
        "subject": SubjectInfo(type="process", name="rundll32.exe", pid=23),
        "raw_data": {"ppid": 22},
        "tags": ["c2"],
    })
    detection = DetectionResult(
        timestamp=child.timestamp,
        analyzer="test",
        detection_type="malicious_behavior",
        title="C2",
        attack_technique_id="T1071.001",
        tags=["c2"],
    )

    tree = build_process_tree([parent, child])
    matches = match_apt_profiles([parent, child], [detection])

    assert any(edge["source"].endswith(":22") and edge["target"].endswith(":23") for edge in tree["edges"])
    assert matches[0]["similarity"] > 0
    assert matches[0]["matched_techniques"] == ["T1071.001"]


def test_external_apt_profiles_are_versioned_and_source_tracked(tmp_path, monkeypatch) -> None:
    profile_file = tmp_path / "apt-profiles.json"
    profile_file.write_text(
        '{"version":"2026.09","profiles":{"DemoGroup":{"techniques":["T1059.001"],"tags":["powershell"]}}}',
        encoding="utf-8",
    )
    monkeypatch.setenv("ATTACK_TRACE_APT_PROFILES", str(profile_file))

    profiles, source, version = load_apt_profiles()
    matches = match_apt_profiles(
        [
            NormalizedEvent(
                timestamp="2026-09-11T10:00:00Z",
                source_type="host_behavior",
                source="test",
                host=HostInfo(hostname="HOST01"),
                event_type="process_create",
                action="execute",
                tags=["powershell"],
            )
        ],
        [],
    )

    assert list(profiles) == ["DemoGroup"]
    assert source == "external"
    assert version == "2026.09"
    assert matches[0]["profile"] == "DemoGroup"
    assert matches[0]["profile_source"] == "external"
    assert matches[0]["profile_version"] == "2026.09"
