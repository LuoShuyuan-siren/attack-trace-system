"""Rule definitions and matching for detection-to-technique mapping."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable

from .models import DetectionResultLike, RuleMatch


@dataclass(frozen=True)
class MappingRule:
    rule_id: str
    name: str
    technique_id: str
    priority: int = 0
    tactic_ids: tuple[str, ...] = ()
    analyzers: frozenset[str] = frozenset()
    detection_types: frozenset[str] = frozenset()
    tags: frozenset[str] = frozenset()
    text_patterns: tuple[str, ...] = ()
    evidence_keys: frozenset[str] = frozenset()
    ttp_tags: tuple[str, ...] = ()
    confidence_adjustment: float = 0.0

    def matches(self, detection: DetectionResultLike) -> bool:
        if self.analyzers and detection.analyzer not in self.analyzers:
            return False
        if self.detection_types and detection.detection_type not in self.detection_types:
            return False
        if self.tags and not self.tags.intersection(detection.tags):
            return False
        if self.text_patterns:
            haystack = detection_text(detection)
            if not any(pattern.lower() in haystack for pattern in self.text_patterns):
                return False
        if self.evidence_keys and not self.evidence_keys.intersection(detection.evidence):
            return False
        return True


def detection_text(detection: DetectionResultLike) -> str:
    parts = [
        detection.title or "",
        detection.description or "",
        detection.detection_type or "",
        detection.analyzer or "",
        " ".join(detection.tags),
        " ".join(str(key) for key in detection.evidence),
        " ".join(
            str(value)
            for value in detection.evidence.values()
            if isinstance(value, (str, int, float))
        ),
    ]
    return " ".join(parts).lower()


def build_default_rules() -> tuple[MappingRule, ...]:
    rules = [
        MappingRule(
            rule_id="explicit-dns-c2",
            name="DNS application layer C2",
            technique_id="T1071.004",
            priority=90,
            tactic_ids=("TA0011",),
            analyzers=frozenset({"dns_tunnel_analyzer"}),
            ttp_tags=("dns_tunnel", "c2_communication"),
        ),
        MappingRule(
            rule_id="tag-dns-tunnel",
            name="DNS tunnel tag",
            technique_id="T1071.004",
            priority=82,
            tactic_ids=("TA0011",),
            tags=frozenset({"dns_tunnel", "dns-tunnel", "dns"}),
            ttp_tags=("dns_tunnel", "c2_communication"),
        ),
        MappingRule(
            rule_id="explicit-http-c2",
            name="HTTP application layer C2",
            technique_id="T1071.001",
            priority=90,
            tactic_ids=("TA0011",),
            analyzers=frozenset({"http_tunnel_analyzer", "http_analyzer"}),
            ttp_tags=("http_tunnel", "c2_communication"),
        ),
        MappingRule(
            rule_id="explicit-icmp-c2",
            name="ICMP tunnel C2",
            technique_id="T1095",
            priority=90,
            tactic_ids=("TA0011",),
            analyzers=frozenset({"icmp_tunnel_analyzer", "icmp_analyzer"}),
            ttp_tags=("icmp_tunnel", "c2_communication"),
        ),
        MappingRule(
            rule_id="protocol-tunneling",
            name="Generic protocol tunneling",
            technique_id="T1572",
            priority=72,
            tactic_ids=("TA0011",),
            tags=frozenset({"tunnel", "covert_channel", "protocol_tunneling"}),
            ttp_tags=("covert_channel", "c2_communication"),
        ),
        MappingRule(
            rule_id="process-injection",
            name="Process injection",
            technique_id="T1055",
            priority=88,
            tactic_ids=("TA0004", "TA0005"),
            analyzers=frozenset({"process_injection_analyzer", "memory_analyzer"}),
            ttp_tags=("process_injection", "defense_evasion"),
        ),
        MappingRule(
            rule_id="reflective-code-loading",
            name="Reflective or in-memory code loading",
            technique_id="T1620",
            priority=96,
            tactic_ids=("TA0005",),
            text_patterns=(
                "reflective load",
                "reflective code loading",
                "in-memory module",
                "anonymous in-memory file executed",
            ),
            ttp_tags=("reflective_loading", "defense_evasion"),
        ),
        MappingRule(
            rule_id="cross-process-memory",
            name="Cross-process memory manipulation",
            technique_id="T1055",
            priority=90,
            tactic_ids=("TA0004", "TA0005"),
            text_patterns=(
                "cross-process memory",
                "remote thread",
                "process tampering",
                "process access",
            ),
            ttp_tags=("process_injection", "defense_evasion"),
        ),
        MappingRule(
            rule_id="text-process-injection",
            name="Process injection evidence",
            technique_id="T1055",
            priority=74,
            tactic_ids=("TA0004", "TA0005"),
            text_patterns=(
                "process injection",
                "reflective load",
                "code injection",
                "remote thread",
            ),
            ttp_tags=("process_injection", "defense_evasion"),
        ),
        MappingRule(
            rule_id="credential-dumping",
            name="Credential dumping",
            technique_id="T1003",
            priority=88,
            tactic_ids=("TA0006",),
            analyzers=frozenset(
                {"credential_access_analyzer", "credential_dump_analyzer"}
            ),
            ttp_tags=("credential_access", "credential_dumping"),
        ),
        MappingRule(
            rule_id="text-credential-dumping",
            name="Credential dumping evidence",
            technique_id="T1003",
            priority=74,
            tactic_ids=("TA0006",),
            text_patterns=("mimikatz", "lsass", "credential dump", "sam database"),
            ttp_tags=("credential_access", "credential_dumping"),
        ),
        MappingRule(
            rule_id="brute-force",
            name="Brute force",
            technique_id="T1110",
            priority=86,
            tactic_ids=("TA0006",),
            analyzers=frozenset({"brute_force_analyzer", "auth_analyzer"}),
            text_patterns=("brute force", "password spray", "multiple failed login"),
            ttp_tags=("credential_access", "brute_force"),
        ),
        MappingRule(
            rule_id="lateral-movement",
            name="Lateral movement",
            technique_id="T1021",
            priority=86,
            tactic_ids=("TA0008",),
            analyzers=frozenset({"lateral_movement_analyzer"}),
            ttp_tags=("lateral_movement",),
        ),
        MappingRule(
            rule_id="text-lateral-movement",
            name="Remote service lateral movement",
            technique_id="T1021",
            priority=72,
            tactic_ids=("TA0008",),
            text_patterns=("psexec", "remote services", "wmi", "rdp", "lateral"),
            ttp_tags=("lateral_movement",),
        ),
        MappingRule(
            rule_id="privilege-escalation",
            name="Privilege escalation exploitation",
            technique_id="T1068",
            priority=86,
            tactic_ids=("TA0004",),
            analyzers=frozenset({"privilege_escalation_analyzer"}),
            ttp_tags=("privilege_escalation",),
        ),
        MappingRule(
            rule_id="valid-accounts",
            name="Valid accounts abuse",
            technique_id="T1078",
            priority=74,
            tactic_ids=("TA0001", "TA0003", "TA0008"),
            tags=frozenset({"valid_account", "account_abuse"}),
            text_patterns=("valid account", "stolen credential"),
            ttp_tags=("valid_accounts",),
        ),
        MappingRule(
            rule_id="powershell",
            name="PowerShell execution",
            technique_id="T1059.001",
            priority=84,
            tactic_ids=("TA0002",),
            text_patterns=("powershell", "power shell"),
            ttp_tags=("scripting", "powershell"),
        ),
        MappingRule(
            rule_id="windows-shell",
            name="Windows command shell",
            technique_id="T1059.003",
            priority=80,
            tactic_ids=("TA0002",),
            text_patterns=("cmd.exe", "command shell", "batch script"),
            ttp_tags=("scripting", "windows_shell"),
        ),
        MappingRule(
            rule_id="unix-shell",
            name="Unix shell",
            technique_id="T1059.004",
            priority=80,
            tactic_ids=("TA0002",),
            text_patterns=("bash", "sh -c", "unix shell", "/bin/sh"),
            ttp_tags=("scripting", "unix_shell"),
        ),
        MappingRule(
            rule_id="scheduled-task",
            name="Scheduled task or job",
            technique_id="T1053",
            priority=78,
            tactic_ids=("TA0002", "TA0003", "TA0004"),
            text_patterns=("scheduled task", "cron", "at job"),
            ttp_tags=("persistence", "scheduled_task"),
        ),
        MappingRule(
            rule_id="persistence",
            name="Persistence mechanism",
            technique_id="T1547",
            priority=78,
            tactic_ids=("TA0003", "TA0004"),
            tags=frozenset({"persistence"}),
            text_patterns=("autostart", "run key", "registry persistence"),
            ttp_tags=("persistence",),
        ),
        MappingRule(
            rule_id="system-process",
            name="System process modification",
            technique_id="T1543",
            priority=76,
            tactic_ids=("TA0003",),
            text_patterns=("service create", "service modify", "systemd"),
            ttp_tags=("persistence",),
        ),
        MappingRule(
            rule_id="indicator-removal",
            name="Indicator removal",
            technique_id="T1070",
            priority=80,
            tactic_ids=("TA0005",),
            text_patterns=(
                "clear log",
                "event log cleared",
                "log cleared",
                "remove indicator",
                "delete log",
            ),
            ttp_tags=("defense_evasion", "log_cleanup"),
        ),
        MappingRule(
            rule_id="obfuscation",
            name="Obfuscated files or information",
            technique_id="T1027",
            priority=76,
            tactic_ids=("TA0005",),
            text_patterns=("obfusc", "base64", "encrypted payload"),
            ttp_tags=("defense_evasion", "obfuscation"),
        ),
        MappingRule(
            rule_id="masquerading",
            name="Masquerading",
            technique_id="T1036",
            priority=74,
            tactic_ids=("TA0005",),
            text_patterns=("masquerad", "impersonat", "spoof"),
            ttp_tags=("defense_evasion", "masquerading"),
        ),
        MappingRule(
            rule_id="system-binary-proxy",
            name="System binary proxy execution",
            technique_id="T1218",
            priority=76,
            tactic_ids=("TA0005",),
            text_patterns=("rundll32", "regsvr32", "mshta", "certutil"),
            ttp_tags=("defense_evasion", "lolbin"),
        ),
        MappingRule(
            rule_id="external-remote-services",
            name="External remote service exploit",
            technique_id="T1133",
            priority=82,
            tactic_ids=("TA0001",),
            text_patterns=("external remote", "vpn exploit", "public service"),
            ttp_tags=("initial_access", "remote_access"),
        ),
        MappingRule(
            rule_id="exploit-public-app",
            name="Public-facing application exploit",
            technique_id="T1190",
            priority=84,
            tactic_ids=("TA0001",),
            analyzers=frozenset({"exploit_analyzer", "web_exploit_analyzer"}),
            text_patterns=("exploit", "web shell", "sql injection", "rce"),
            ttp_tags=("initial_access", "exploitation"),
        ),
        MappingRule(
            rule_id="phishing",
            name="Phishing",
            technique_id="T1566",
            priority=84,
            tactic_ids=("TA0001",),
            analyzers=frozenset({"email_analyzer", "phishing_analyzer"}),
            text_patterns=("phish", "malicious attachment", "spear"),
            ttp_tags=("initial_access", "phishing"),
        ),
        MappingRule(
            rule_id="discovery",
            name="System and account discovery",
            technique_id="T1082",
            priority=70,
            tactic_ids=("TA0007",),
            text_patterns=("system information discovery", "host enumeration", "whoami"),
            ttp_tags=("discovery",),
        ),
        MappingRule(
            rule_id="network-discovery",
            name="Network service discovery",
            technique_id="T1046",
            priority=70,
            tactic_ids=("TA0007",),
            text_patterns=("port scan", "network scan", "service discovery"),
            ttp_tags=("discovery", "scanning"),
        ),
        MappingRule(
            rule_id="remote-system-discovery",
            name="Remote system discovery",
            technique_id="T1018",
            priority=70,
            tactic_ids=("TA0007",),
            text_patterns=("remote system discovery", "net view", "active directory enum"),
            ttp_tags=("discovery",),
        ),
        MappingRule(
            rule_id="collection",
            name="Local data collection",
            technique_id="T1005",
            priority=70,
            tactic_ids=("TA0009",),
            text_patterns=(
                "data from local system",
                "sensitive file read",
                "database file read",
                "sensitive file",
            ),
            ttp_tags=("collection",),
        ),
        MappingRule(
            rule_id="archive-collection",
            name="Archive collected data",
            technique_id="T1560",
            priority=72,
            tactic_ids=("TA0009",),
            text_patterns=("archive", "compress", "zip", "rar"),
            ttp_tags=("collection", "staging"),
        ),
        MappingRule(
            rule_id="exfiltration-c2",
            name="Exfiltration over C2",
            technique_id="T1041",
            priority=80,
            tactic_ids=("TA0010",),
            text_patterns=("exfiltr", "data upload", "data transfer"),
            ttp_tags=("exfiltration",),
        ),
        MappingRule(
            rule_id="exfiltration-alt",
            name="Exfiltration over alternative protocol",
            technique_id="T1048",
            priority=78,
            tactic_ids=("TA0010",),
            text_patterns=("alternative protocol", "dns exfiltration", "ftp upload"),
            ttp_tags=("exfiltration",),
        ),
        MappingRule(
            rule_id="impact-ransomware",
            name="Data encrypted for impact",
            technique_id="T1486",
            priority=86,
            tactic_ids=("TA0040",),
            text_patterns=("ransom", "encrypt", "locker"),
            ttp_tags=("impact", "ransomware"),
        ),
        MappingRule(
            rule_id="impact-destruction",
            name="Data destruction",
            technique_id="T1485",
            priority=80,
            tactic_ids=("TA0040",),
            text_patterns=("wipe", "data destruction", "delete volume"),
            ttp_tags=("impact",),
        ),
    ]
    return tuple(rules)


def match_detection(
    detection: DetectionResultLike,
    rules: Iterable[MappingRule],
) -> list[RuleMatch]:
    matches: list[RuleMatch] = []
    for rule in rules:
        if not rule.matches(detection):
            continue
        matches.append(
            RuleMatch(
                rule_id=rule.rule_id,
                technique_id=rule.technique_id,
                tactic_ids=rule.tactic_ids,
                ttp_tags=rule.ttp_tags,
                confidence_adjustment=rule.confidence_adjustment,
            )
        )
    return sorted(matches, key=lambda match: -_priority_for_rule(match.rule_id, rules))


def _priority_for_rule(rule_id: str, rules: Iterable[MappingRule]) -> int:
    for rule in rules:
        if rule.rule_id == rule_id:
            return rule.priority
    return 0
