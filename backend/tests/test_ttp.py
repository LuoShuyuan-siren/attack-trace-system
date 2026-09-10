from app.analyzers.attack_mapping import AttackMapper, build_ttp_profile

from tests.member6_fixtures import detection


def test_ttp_profile_aggregates_mapped_detections():
    mapper = AttackMapper()
    mappings = mapper.map_many(
        [
            detection(
                detection_id="det-1",
                analyzer="dns_tunnel_analyzer",
                confidence=0.8,
            ),
            detection(
                detection_id="det-2",
                attack_technique_id="T1190",
                confidence=0.9,
            ),
        ]
    )

    profile = build_ttp_profile(mappings)

    assert profile.technique_ids == ("T1071.004", "T1190")
    assert profile.tactic_ids == ("TA0001", "TA0011")
    assert "c2_communication" in profile.tags
    assert profile.confidence == 0.85
    assert profile.stage_count == 2
