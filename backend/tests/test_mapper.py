from datetime import datetime, timezone

from app.analyzers.attack_mapping import AttackMapper
from app.schemas.detection import DetectionResult

from tests.fixtures import detection


def test_explicit_technique_is_used():
    result = AttackMapper().map_one(
        detection(attack_technique_id="T1071.004", confidence=0.9)
    )

    assert result.technique_id == "T1071.004"
    assert result.technique_name == "DNS"
    assert result.mapping_source == "explicit"
    assert result.primary_tactic_id == "TA0011"
    assert result.primary_tactic_name == "Command and Control"


def test_dns_tunnel_analyzer_maps_to_c2():
    result = AttackMapper().map_one(
        detection(analyzer="dns_tunnel_analyzer", tags=["dns", "tunnel"])
    )

    assert result.technique_id == "T1071.004"
    assert result.primary_tactic_id == "TA0011"
    assert "c2_communication" in result.ttp_tags
    assert result.mapping_source == "rule"


def test_powershell_text_maps_to_execution():
    result = AttackMapper().map_one(
        detection(
            analyzer="process_analyzer",
            title="Suspicious powershell.exe invocation",
            description="Encoded PowerShell command was observed",
        )
    )

    assert result.technique_id == "T1059.001"
    assert result.primary_tactic_id == "TA0002"
    assert result.stages == ("execution",)


def test_unknown_detection_has_explicit_unknown_mapping():
    result = AttackMapper().map_one(
        detection(analyzer="noise_analyzer", confidence=0.3)
    )

    assert result.technique_id == "unknown"
    assert result.technique_name == "Unknown"
    assert result.mapping_source == "none"
    assert result.tactics == ()


def test_confidence_is_bounded_between_zero_and_one():
    result = AttackMapper().map_one(
        detection(analyzer="dns_tunnel_analyzer", confidence=1.4)
    )

    assert result.confidence == 1.0


def test_real_detection_result_is_supported():
    detection_result = DetectionResult(
        detection_id="det-real",
        timestamp=datetime(2026, 9, 8, 10, 20, tzinfo=timezone.utc),
        analyzer="dns_tunnel_analyzer",
        detection_type="malicious_behavior",
        title="Potential DNS Tunnel",
        confidence=0.91,
        related_entity_ids=["host:WIN-PC01"],
        tags=["dns", "tunnel"],
    )

    result = AttackMapper().map_one(detection_result)

    assert result.detection_id == "det-real"
    assert result.technique_id == "T1071.004"
    assert result.hosts == ("WIN-PC01",)
