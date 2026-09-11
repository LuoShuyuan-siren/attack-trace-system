"""ATT&CK mapping and attack-detection helpers for Member 6."""

from .mapper import AttackMapper
from .models import (
    AttackMappingResult,
    AttackStage,
    DetectionResultLike,
    RuleMatch,
    TacticRef,
    TechniqueRef,
    TTPProfile,
)
from .registry import (
    STAGES_BY_TACTIC,
    TACTICS,
    TECHNIQUES,
    stage_for_tactic,
    tactic_name,
    tactics_for_technique,
    technique_name,
)
from .rules import MappingRule, build_default_rules, match_detection
from .tactic_sequence import build_attack_stages, map_and_build_stages
from .ttp import build_ttp_profile

__all__ = [
    "AttackMapper",
    "AttackMappingResult",
    "AttackStage",
    "DetectionResultLike",
    "MappingRule",
    "RuleMatch",
    "STAGES_BY_TACTIC",
    "TACTICS",
    "TECHNIQUES",
    "TacticRef",
    "TechniqueRef",
    "TTPProfile",
    "build_attack_stages",
    "build_default_rules",
    "build_ttp_profile",
    "map_and_build_stages",
    "match_detection",
    "stage_for_tactic",
    "tactic_name",
    "tactics_for_technique",
    "technique_name",
]
