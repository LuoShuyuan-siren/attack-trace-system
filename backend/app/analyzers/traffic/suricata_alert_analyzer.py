from collections import defaultdict

from app.core.analyzer import BaseAnalyzer
from app.schemas.detection import DetectionResult
from app.schemas.event import NormalizedEvent


class SuricataAlertAnalyzer(BaseAnalyzer):
    """将 Suricata IDS alert 聚合为 DetectionResult。"""

    @property
    def name(self) -> str:
        return "suricata_alert_analyzer"

    def analyze(
        self,
        events: list[NormalizedEvent],
    ) -> list[DetectionResult]:

        groups: dict[
            tuple[str, str, str],
            list[NormalizedEvent]
        ] = defaultdict(list)

        for event in events:
            if event.event_type != "alert":
                continue

            signature = str(
                event.raw_data.get("signature", "")
            ).lower()

            family = self._classify(signature)
            if family is None:
                continue

            src_ip = (
                event.network.src_ip
                if event.network
                else None
            )
            dst_ip = (
                event.network.dst_ip
                if event.network
                else None
            )

            if not src_ip or not dst_ip:
                continue

            groups[(src_ip, dst_ip, family)].append(event)

        results: list[DetectionResult] = []

        for (src_ip, dst_ip, family), group in groups.items():

            technique_id, title, tag, confidence = self._family_info(
                family
            )

            timestamps = [e.timestamp for e in group]

            signatures = sorted({
                str(e.raw_data.get("signature", ""))
                for e in group
            })

            results.append(
                DetectionResult(
                    timestamp=min(timestamps),
                    analyzer=self.name,
                    detection_type="suspicious_behavior",
                    title=title,
                    description=(
                        f"Suricata 检测到 {src_ip} 对 {dst_ip} "
                        f"发起 {len(group)} 次相关攻击尝试。"
                    ),
                    severity=(
                        "medium"
                        if family == "scan"
                        else "high"
                    ),
                    confidence=confidence,
                    related_event_ids=[
                        e.event_id for e in group[:100]
                    ],
                    related_entity_ids=[
                        f"ip:{src_ip}",
                        f"ip:{dst_ip}",
                    ],
                    evidence={
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "alert_count": len(group),
                        "first_seen": min(timestamps).isoformat(),
                        "last_seen": max(timestamps).isoformat(),
                        "signatures": signatures,
                    },
                    attack_technique_id=technique_id,
                    tags=[
                        "suricata",
                        "ids_alert",
                        tag,
                        family,
                    ],
                )
            )

        return results

    @staticmethod
    def _classify(signature: str) -> str | None:

        if "acunetix" in signature:
            return "scan"

        if "cve-2014-6271" in signature:
            return "shellshock"

        if "sql injection" in signature:
            return "sql_injection"

        if "xxe" in signature:
            return "xxe"

        if "cmd.exe in uri" in signature:
            return "command_execution_attempt"

        return None

    @staticmethod
    def _family_info(
        family: str,
    ) -> tuple[str, str, str, float]:

        mapping = {
            "scan": (
                "T1046",
                "Web 漏洞扫描行为",
                "discovery",
                0.85,
            ),
            "shellshock": (
                "T1190",
                "Shellshock 漏洞利用尝试",
                "initial_access",
                0.95,
            ),
            "sql_injection": (
                "T1190",
                "SQL 注入攻击尝试",
                "initial_access",
                0.95,
            ),
            "xxe": (
                "T1190",
                "XXE 漏洞利用尝试",
                "initial_access",
                0.95,
            ),
            "command_execution_attempt": (
                "T1190",
                "Web 命令执行攻击尝试",
                "initial_access",
                0.90,
            ),
        }

        return mapping[family]