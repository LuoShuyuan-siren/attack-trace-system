from app.analyzers.tracing.agents.base_agent import LLMClient, validate_subset
from app.analyzers.tracing.agents.models import ChainReview, TraceContext
from app.analyzers.tracing.agents.prompts import CHAIN_REVIEW


class ChainReviewAgent:
    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm

    def fallback(self, context: TraceContext) -> ChainReview:
        stages = list(dict.fromkeys(item.get("stage") for item in context.attack_stages if item.get("stage")))
        weak = [
            item.get("stage") for item in context.attack_stages
            if item.get("confidence", 0.0) < 0.7 and item.get("stage")
        ]
        suspicious = [
            edge["edge_id"] for edge in context.graph_summary.get("edges", [])
            if edge.get("confidence", 0.0) < 0.7
        ]
        missing = [stage for stage in ("initial_access", "lateral_movement", "command_and_control") if stage not in stages]
        score = context.candidate_paths[0].get("score", 0.0) if context.candidate_paths else 0.0
        status = (
            "supported"
            if score >= 0.7 and not missing and not suspicious
            else "weak" if stages else "unsupported"
        )
        evidence = list(dict.fromkeys(context.related_event_ids + context.related_detection_ids))
        return ChainReview(
            status=status, confidence=round(score, 4),
            supported_stages=[stage for stage in stages if stage not in weak],
            weak_stages=list(dict.fromkeys(weak)), missing_stages=missing,
            suspicious_edges=suspicious, evidence_ids=evidence,
            summary="Rule-based review of the highest-ranked grounded path.",
        )

    def analyze(self, context: TraceContext) -> ChainReview:
        if not self.llm:
            return self.fallback(context)
        result = ChainReview.model_validate(self.llm.generate_structured(
            system_prompt=CHAIN_REVIEW, input_data=context.model_dump(mode="json"),
            response_model=ChainReview,
        ))
        validate_subset(result.suspicious_edges, set(context.edge_ids), "suspicious_edges")
        validate_subset(
            result.evidence_ids,
            set(context.related_event_ids) | set(context.related_detection_ids),
            "evidence_ids",
        )
        return result
