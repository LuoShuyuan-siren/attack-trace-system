from statistics import fmean

from app.analyzers.tracing.agents.base_agent import LLMClient, validate_subset
from app.analyzers.tracing.agents.models import EvidenceReview, StageEvidenceReview, TraceContext
from app.analyzers.tracing.agents.prompts import EVIDENCE_REVIEW

KEY_STAGES = [
    "initial_access", "privilege_escalation", "lateral_movement",
    "command_and_control", "data_exfiltration",
]


class EvidenceAgent:
    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm

    def fallback(self, context: TraceContext) -> EvidenceReview:
        reviews = []
        for stage in KEY_STAGES:
            matches = [item for item in context.attack_stages if item.get("stage") == stage]
            event_ids = list(dict.fromkeys(x for item in matches for x in item.get("related_event_ids", [])))
            detection_ids = list(dict.fromkeys(x for item in matches for x in item.get("related_detection_ids", [])))
            edge_ids = [
                edge["edge_id"] for edge in context.graph_summary.get("edges", [])
                if self._edge_stage(edge.get("relation")) == stage
            ]
            confidence = fmean(item.get("confidence", 0.0) for item in matches) if matches else 0.0
            complete = bool(matches and (event_ids or detection_ids))
            status = "supported" if complete and confidence >= 0.7 else "weak" if matches else "unsupported"
            reviews.append(StageEvidenceReview(
                stage=stage, status=status, supported=status == "supported",
                confidence=round(confidence, 4), event_ids=event_ids,
                detection_ids=detection_ids, edge_ids=edge_ids,
                missing_evidence=[] if complete else ["event_or_detection_evidence"],
                explanation="Evidence references present." if complete else "No sufficient referenced evidence.",
            ))
        overall = fmean(review.confidence for review in reviews) if reviews else 0.0
        return EvidenceReview(stages=reviews, overall_confidence=round(overall, 4))

    def analyze(self, context: TraceContext) -> EvidenceReview:
        if not self.llm:
            return self.fallback(context)
        result = EvidenceReview.model_validate(self.llm.generate_structured(
            system_prompt=EVIDENCE_REVIEW,
            input_data=context.model_dump(mode="json"),
            response_model=EvidenceReview,
        ))
        for review in result.stages:
            validate_subset(review.event_ids, set(context.related_event_ids), "event_ids")
            validate_subset(review.detection_ids, set(context.related_detection_ids), "detection_ids")
            validate_subset(review.edge_ids, set(context.edge_ids), "edge_ids")
        return result

    @staticmethod
    def _edge_stage(relation: str | None) -> str | None:
        return {"c2_communication": "command_and_control", "data_exfiltration": "data_exfiltration"}.get(relation, relation)
