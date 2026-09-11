"""Focused MITRE ATT&CK taxonomy used by the mapping rules."""

from __future__ import annotations


STAGES_BY_TACTIC: dict[str, str] = {
    "TA0001": "initial_access",
    "TA0002": "execution",
    "TA0003": "persistence",
    "TA0004": "privilege_escalation",
    "TA0005": "defense_evasion",
    "TA0006": "credential_access",
    "TA0007": "discovery",
    "TA0008": "lateral_movement",
    "TA0009": "collection",
    "TA0010": "exfiltration",
    "TA0011": "command_and_control",
    "TA0040": "impact",
}

TACTICS: dict[str, tuple[str, str]] = {
    "TA0001": ("Initial Access", "initial_access"),
    "TA0002": ("Execution", "execution"),
    "TA0003": ("Persistence", "persistence"),
    "TA0004": ("Privilege Escalation", "privilege_escalation"),
    "TA0005": ("Defense Evasion", "defense_evasion"),
    "TA0006": ("Credential Access", "credential_access"),
    "TA0007": ("Discovery", "discovery"),
    "TA0008": ("Lateral Movement", "lateral_movement"),
    "TA0009": ("Collection", "collection"),
    "TA0010": ("Exfiltration", "exfiltration"),
    "TA0011": ("Command and Control", "command_and_control"),
    "TA0040": ("Impact", "impact"),
}

# Technique ID -> (name, tactic IDs)
TECHNIQUES: dict[str, tuple[str, tuple[str, ...]]] = {
    "T1003": ("OS Credential Dumping", ("TA0006",)),
    "T1003.008": ("/etc/passwd and /etc/shadow", ("TA0006",)),
    "T1005": ("Data from Local System", ("TA0009",)),
    "T1018": ("Remote System Discovery", ("TA0007",)),
    "T1021": ("Remote Services", ("TA0008",)),
    "T1027": ("Obfuscated Files or Information", ("TA0005",)),
    "T1036": ("Masquerading", ("TA0005",)),
    "T1041": ("Exfiltration Over C2 Channel", ("TA0010",)),
    "T1046": ("Network Service Discovery", ("TA0007",)),
    "T1048": ("Exfiltration Over Alternative Protocol", ("TA0010",)),
    "T1053": ("Scheduled Task/Job", ("TA0002", "TA0003", "TA0004")),
    "T1055": ("Process Injection", ("TA0004", "TA0005")),
    "T1059": ("Command and Scripting Interpreter", ("TA0002",)),
    "T1059.001": ("PowerShell", ("TA0002",)),
    "T1059.003": ("Windows Command Shell", ("TA0002",)),
    "T1059.004": ("Unix Shell", ("TA0002",)),
    "T1068": ("Exploitation for Privilege Escalation", ("TA0004",)),
    "T1070": ("Indicator Removal", ("TA0005",)),
    "T1071": ("Application Layer Protocol", ("TA0011",)),
    "T1071.001": ("Web Protocols", ("TA0011",)),
    "T1071.004": ("DNS", ("TA0011",)),
    "T1078": ("Valid Accounts", ("TA0001", "TA0003", "TA0008")),
    "T1082": ("System Information Discovery", ("TA0007",)),
    "T1087": ("Account Discovery", ("TA0007",)),
    "T1090": ("Proxy", ("TA0011",)),
    "T1095": ("Non-Application Layer Protocol", ("TA0011",)),
    "T1105": ("Ingress Tool Transfer", ("TA0011",)),
    "T1110": ("Brute Force", ("TA0006",)),
    "T1110.001": ("Password Guessing", ("TA0006",)),
    "T1110.002": ("Password Cracking", ("TA0006",)),
    "T1119": ("Automated Collection", ("TA0009",)),
    "T1133": ("External Remote Services", ("TA0001",)),
    "T1135": ("Network Share Discovery", ("TA0007",)),
    "T1136.001": ("Create Account: Local Account", ("TA0003",)),
    "T1190": ("Exploit Public-Facing Application", ("TA0001",)),
    "T1204": ("User Execution", ("TA0002",)),
    "T1218": ("System Binary Proxy Execution", ("TA0005",)),
    "T1219": ("Remote Access Software", ("TA0011",)),
    "T1485": ("Data Destruction", ("TA0040",)),
    "T1486": ("Data Encrypted for Impact", ("TA0040",)),
    "T1490": ("Inhibit System Recovery", ("TA0040",)),
    "T1543": ("Create or Modify System Process", ("TA0003",)),
    "T1505.003": ("Server Software Component: Web Shell", ("TA0002", "TA0003")),
    "T1547": ("Boot or Logon Autostart Execution", ("TA0003", "TA0004")),
    "T1548": ("Abuse Elevation Control Mechanism", ("TA0004", "TA0005")),
    "T1548.003": ("Sudo and Sudo Caching", ("TA0004", "TA0005")),
    "T1552": ("Unsecured Credentials", ("TA0006",)),
    "T1552.004": ("Private Keys", ("TA0006",)),
    "T1550": ("Use Alternate Authentication Material", ("TA0008", "TA0005")),
    "T1555": ("Credentials from Password Stores", ("TA0006",)),
    "T1560": ("Archive Collected Data", ("TA0009",)),
    "T1566": ("Phishing", ("TA0001",)),
    "T1567": ("Exfiltration Over Web Service", ("TA0010",)),
    "T1570": ("Lateral Tool Transfer", ("TA0008",)),
    "T1572": ("Protocol Tunneling", ("TA0011",)),
    "T1571": ("Non-Standard Port", ("TA0011",)),
    "T1571.004": ("ICMP", ("TA0011",)),
    "T1620": ("Reflective Code Loading", ("TA0005",)),
}


def tactic_name(tactic_id: str) -> str:
    value = TACTICS.get(tactic_id)
    return value[0] if value else "Unknown"


def stage_for_tactic(tactic_id: str) -> str:
    return STAGES_BY_TACTIC.get(tactic_id, "unknown")


def technique_name(technique_id: str) -> str:
    value = TECHNIQUES.get(technique_id)
    return value[0] if value else "Unknown"


def tactics_for_technique(technique_id: str) -> tuple[str, ...]:
    value = TECHNIQUES.get(technique_id)
    return value[1] if value else ()
