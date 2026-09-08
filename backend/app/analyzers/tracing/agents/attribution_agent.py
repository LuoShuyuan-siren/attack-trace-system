from app.analyzers.tracing.agents.base_agent import LLMClient, validate_subset
from app.analyzers.tracing.agents.models import AttributionReview, TraceContext
from app.analyzers.tracing.agents.prompts import ATTRIBUTION


class AttributionAgent:
    def __init__(self, llm: LLMClient | None = None) -> None:
        self.llm = llm

    def fallback(self, context: TraceContext) -> AttributionReview:
        techniques = context.attack_technique_ids
        pattern = list(dict.fromkeys(
            item.get("stage") for item in context.attack_stages if item.get("stage")
        ))
        evidence = list(dict.fromkeys(context.related_detection_ids + context.related_event_ids))
        return AttributionReview(
            techniques=techniques, ttp_pattern=pattern,
            possible_profile="Evidence-grounded multi-stage intrusion; actor identity undetermined.",
            similarity_reasoning=[
                "No actor or APT knowledge base was supplied.",
                "Profile is limited to observed ATT&CK techniques and behavior stages.",
            ],
            confidence=round(min(0.6, len(techniques) * 0.1), 4),
            evidence_ids=evidence,
        )

    def analyze(self, context: TraceContext) -> AttributionReview:
        if not self.llm:
            return self.fallback(context)
        result = AttributionReview.model_validate(self.llm.generate_structured(
            system_prompt=ATTRIBUTION, input_data=context.model_dump(mode="json"),
            response_model=AttributionReview,
        ))
        validate_subset(result.techniques, set(context.attack_technique_ids), "techniques")
        validate_subset(
            result.evidence_ids,
            set(context.related_event_ids) | set(context.related_detection_ids),
            "evidence_ids",
        )
        return result
