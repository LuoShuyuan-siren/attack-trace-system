import re

from app.analyzers.tracing.agents.base_agent import AgentValidationError, LLMClient, validate_subset
from app.analyzers.tracing.agents.models import (
    AttributionReview, ChainReview, EvidenceReview, TraceContext, TraceReport,
)
from app.analyzers.tracing.agents.prompts import REPORT

TOKEN_PATTERN = re.compile(
    r"\bT\d{4}(?:\.\d{3})?\b|(?:\d{1,3}\.){3}\d{1,3}"
    r"|(?:host|user|process|file|ip|domain):[^\s,;]+"
)


class ReportAgent:
    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm

    def fallback(
        self, context: TraceContext, evidence: EvidenceReview,
        chain: ChainReview, attribution: AttributionReview,
    ) -> TraceReport:
        path = context.candidate_paths[0] if context.candidate_paths else {}
        nodes = path.get("nodes", [])
        hosts = [node for node in nodes if node.startswith("host:")]
        relations = path.get("relations", [])
        origin = nodes[0] if nodes else "unknown"
        timeline = [
            f"{item.get('timestamp')}: {item.get('stage')} {item.get('source')} -> {item.get('target')}"
            for item in context.attack_stages
        ]
        uncertainties = list(chain.missing_stages)
        weak = [item.stage for item in evidence.stages if item.status != "supported"]
        uncertainties.extend(stage for stage in weak if stage not in uncertainties)
        return TraceReport(
            attack_origin=origin, timeline=timeline, victim_hosts=hosts,
            lateral_movement_path=[
                f"{path['nodes'][i]} -> {path['nodes'][i + 1]}"
                for i, relation in enumerate(relations) if relation == "lateral_movement"
            ] if nodes else [],
            privilege_escalation="supported" if "privilege_escalation" in relations else "not evidenced",
            c2_communication="supported" if "c2_communication" in relations else "not evidenced",
            data_exfiltration="supported" if "data_exfiltration" in relations else "not evidenced",
            techniques=attribution.techniques,
            key_evidence_ids=list(dict.fromkeys(chain.evidence_ids)),
            overall_confidence=chain.confidence, uncertainties=uncertainties,
            summary="Structured trace report generated only from supplied graph evidence.",
        )

    def analyze(
        self, context: TraceContext, evidence: EvidenceReview,
        chain: ChainReview, attribution: AttributionReview,
    ) -> TraceReport:
        if not self.llm:
            return self.fallback(context, evidence, chain, attribution)
        payload = context.model_dump(mode="json")
        payload["reviews"] = {
            "evidence": evidence.model_dump(mode="json"),
            "chain": chain.model_dump(mode="json"),
            "attribution": attribution.model_dump(mode="json"),
        }
        result = TraceReport.model_validate(self.llm.generate_structured(
            system_prompt=REPORT, input_data=payload, response_model=TraceReport,
        ))
        allowed_techniques = set(context.attack_technique_ids)
        allowed_evidence_ids = set(context.related_event_ids) | set(context.related_detection_ids)
        result.techniques = [
            item for item in result.techniques if item in allowed_techniques
        ]
        result.key_evidence_ids = [
            item for item in result.key_evidence_ids if item in allowed_evidence_ids
        ]
        validate_subset(result.techniques, allowed_techniques, "techniques")
        validate_subset(result.key_evidence_ids, allowed_evidence_ids, "key_evidence_ids")
        allowed_nodes = {
            node["node_id"] for node in context.graph_summary.get("nodes", [])
        }
        allowed_tokens = allowed_techniques | allowed_nodes | {
            item.removeprefix("ip:") for item in context.indicators if item.startswith("ip:")
        }
        text = " ".join(
            [result.attack_origin, *result.timeline, *result.victim_hosts,
             *result.lateral_movement_path, result.privilege_escalation,
             result.c2_communication, result.data_exfiltration, result.summary]
        )
        unknown = set(TOKEN_PATTERN.findall(text)).difference(allowed_tokens)
        if unknown:
            return self.fallback(context, evidence, chain, attribution)
        return result
