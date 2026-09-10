from app.analyzers.attack_mapping import AttackMapper, map_and_build_stages

from tests.fixtures.attack_mapping import detection


def test_stages_are_sorted_by_timestamp():
    mapper = AttackMapper()
    detections = [
        detection(
            detection_id="det-late",
            timestamp="2026-09-08T10:20:00Z",
            attack_technique_id="T1071.004",
        ),
        detection(
            detection_id="det-early",
            timestamp="2026-09-08T10:00:00Z",
            attack_technique_id="T1190",
            related_entity_ids=["host:WEB01"],
        ),
    ]

    stages = map_and_build_stages(detections, mapper)

    assert [stage.detection_id for stage in stages] == ["det-early", "det-late"]
    assert stages[0].stage == "initial_access"
    assert stages[0].host == "WEB01"
    assert stages[1].stage == "command_and_control"


def test_duplicate_consecutive_stages_are_removed():
    mapper = AttackMapper()
    detections = [
        detection(
            detection_id="det-1",
            timestamp="2026-09-08T10:00:00Z",
            attack_technique_id="T1190",
            related_entity_ids=["host:WEB01"],
        ),
        detection(
            detection_id="det-2",
            timestamp="2026-09-08T10:01:00Z",
            attack_technique_id="T1190",
            related_entity_ids=["host:WEB01"],
        ),
    ]

    stages = map_and_build_stages(detections, mapper)

    assert len(stages) == 1
    assert stages[0].detection_id == "det-1"
