from app.analyzers.attack_mapping import AttackMapper, AttackMappingResult
from app.schemas.detection import DetectionResult


_mapper = AttackMapper()


def map_detections(
    detections: list[DetectionResult],
) -> list[AttackMappingResult]:
    """将检测结果映射到 MITRE ATT&CK 技术和战术。"""

    return _mapper.map_many(detections)