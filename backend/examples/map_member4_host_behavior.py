"""Map Member 4 HostBehaviorAnalyzer output to ATT&CK technique IDs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.schemas.detection import DetectionResult


EXAMPLES_DIR = Path(__file__).resolve().parent
INPUT_FILE = EXAMPLES_DIR / "member4_host_behavior_detections.json"
OUTPUT_FILE = EXAMPLES_DIR / "member4_host_behavior_mapped.json"
SUMMARY_FILE = EXAMPLES_DIR / "member4_host_behavior_mapping_summary.json"


RULE_MAPPING: dict[str, dict[str, Any]] = {
    "HB-PROC-001": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactics": [("TA0002", "Execution", "execution")],
    },
    "HB-PROC-002": {
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "tactics": [("TA0001", "Initial Access", "initial_access")],
    },
    "HB-PROC-003": {
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactics": [("TA0002", "Execution", "execution")],
    },
    "HB-PROC-004": {
        "technique_id": "T1059.004",
        "technique_name": "Unix Shell",
        "tactics": [("TA0002", "Execution", "execution")],
    },
    "HB-FILE-001": {
        "technique_id": "T1003",
        "technique_name": "OS Credential Dumping",
        "tactics": [("TA0006", "Credential Access", "credential_access")],
    },
    "HB-FILE-002": {
        "technique_id": "T1547",
        "technique_name": "Boot or Logon Autostart Execution",
        "tactics": [("TA0003", "Persistence", "persistence")],
    },
    "HB-FILE-003": {
        "technique_id": "T1070",
        "technique_name": "Indicator Removal",
        "tactics": [("TA0005", "Defense Evasion", "defense_evasion")],
    },
    "HB-FILE-004": {
        "technique_id": "T1105",
        "technique_name": "Ingress Tool Transfer",
        "tactics": [("TA0011", "Command and Control", "command_and_control")],
    },
    "HB-SYSCALL-001": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactics": [
            ("TA0004", "Privilege Escalation", "privilege_escalation"),
            ("TA0005", "Defense Evasion", "defense_evasion"),
        ],
    },
    "HB-SYSCALL-002": {
        "technique_id": "T1620",
        "technique_name": "Reflective Code Loading",
        "tactics": [("TA0005", "Defense Evasion", "defense_evasion")],
    },
    "HB-MEM-001": {
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactics": [
            ("TA0004", "Privilege Escalation", "privilege_escalation"),
            ("TA0005", "Defense Evasion", "defense_evasion"),
        ],
    },
}


def main() -> None:
    raw_items = json.loads(INPUT_FILE.read_text(encoding="utf-8"))
    mapped_items: list[dict[str, Any]] = []
    summary: dict[str, dict[str, Any]] = {}

    for item in raw_items:
        mapped = map_detection(item)
        mapped_items.append(mapped.model_dump(mode="json"))
        rule_id = mapped.evidence.get("rule_id")
        if rule_id:
            rule = RULE_MAPPING[rule_id]
            summary[mapped.detection_id] = {
                "rule_id": rule_id,
                "title": mapped.title,
                "technique_id": mapped.attack_technique_id,
                "technique_name": rule["technique_name"],
                "tactics": [
                    {
                        "tactic_id": tactic_id,
                        "tactic_name": tactic_name,
                        "stage": stage,
                    }
                    for tactic_id, tactic_name, stage in rule["tactics"]
                ],
            }

    OUTPUT_FILE.write_text(
        json.dumps(mapped_items, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    SUMMARY_FILE.write_text(
        json.dumps(summary, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"mapped={len(mapped_items)} rules={len(RULE_MAPPING)}")


def map_detection(item: dict[str, Any]) -> DetectionResult:
    rule_id = item.get("evidence", {}).get("rule_id")
    rule = RULE_MAPPING.get(rule_id)
    if rule is None:
        raise ValueError(f"Unsupported rule id: {rule_id}")

    original_tags = list(item.get("tags", []))
    mapping_tags = []
    mapping_tags.append(f"attack_technique:{rule['technique_id']}")
    for tactic_id, _, stage in rule["tactics"]:
        mapping_tags.append(f"attack_tactic:{tactic_id}")
        mapping_tags.append(f"attack_stage:{stage}")

    return DetectionResult(
        detection_id=item["detection_id"],
        timestamp=item["timestamp"],
        analyzer=item["analyzer"],
        detection_type=item["detection_type"],
        title=item["title"],
        description=item["description"],
        severity=item["severity"],
        confidence=item["confidence"],
        related_event_ids=item["related_event_ids"],
        related_entity_ids=item["related_entity_ids"],
        evidence=item["evidence"],
        attack_technique_id=rule["technique_id"],
        tags=_deduplicate(original_tags + mapping_tags),
    )


def _deduplicate(values: list[str]) -> list[str]:
    return list(dict.fromkeys(values))


if __name__ == "__main__":
    main()
