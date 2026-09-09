from app.analyzers.tracing import AttackTraceService
from app.analyzers.tracing.agents import TraceAgentOrchestrator
from app.analyzers.tracing.agents.models import (
    AttributionReview, ChainReview, EvidenceReview, StageEvidenceReview, TraceReport,
)
from app.schemas.detection import DetectionResult


def detection(det_id, minute, source, target, relation, confidence=0.9, technique=None):
    return DetectionResult(
        detection_id=det_id, timestamp=f"2026-09-08T10:{minute:02d}:00Z",
        analyzer="test", detection_type="malicious_behavior", title=relation,
        confidence=confidence, related_event_ids=[f"evt-{det_id}"],
        related_entity_ids=[source, target], attack_technique_id=technique,
        tags=[relation],
    )


def chain(confidence=0.9):
    return [
        detection("initial", 0, "ip:203.0.113.8", "host:WEB01", "initial_access", confidence, "T1190"),
        detection("lateral", 5, "host:WEB01", "host:DB01", "lateral_movement", confidence, "T1021.002"),
        detection("c2", 10, "host:DB01", "ip:8.8.8.8", "c2_communication", confidence, "T1071.001"),
    ]


class FakeLLM:
    def __init__(self, responses=None, error=None):
        self.responses = responses or {}
        self.error = error

    def generate_structured(self, *, system_prompt, input_data, response_model):
        if self.error:
            raise self.error
        value = self.responses.get(response_model)
        return value.model_dump(mode="json") if hasattr(value, "model_dump") else value


def valid_agent_responses():
    evidence = EvidenceReview(stages=[
        StageEvidenceReview(
            stage="initial_access", status="supported", supported=True, confidence=0.9,
            event_ids=["evt-initial"], detection_ids=["initial"],
            edge_ids=[], explanation="supported",
        )
    ], overall_confidence=0.9)
    chain_review = ChainReview(
        status="supported", confidence=0.9, supported_stages=["initial_access"],
        evidence_ids=["initial"], summary="supported",
    )
    attribution = AttributionReview(
        techniques=["T1190"], ttp_pattern=["initial_access"],
        possible_profile="Unknown actor; TTP only.", confidence=0.2,
        evidence_ids=["initial"],
    )
    return evidence, chain_review, attribution


def test_complete_chain_has_structured_agent_reviews():
    result = TraceAgentOrchestrator().analyze([], chain())
    assert result["agent_status"] == {"enabled": True, "degraded": False, "errors": []}
    assert result["agent_analysis"]["chain_review"]["status"] == "supported"
    assert result["agent_analysis"]["report"]["attack_origin"] == "ip:203.0.113.8"
    assert result["agent_analysis"]["report"]["key_evidence_ids"]


def test_missing_lateral_movement_is_reported():
    detections = [chain()[0], chain()[2]]
    result = TraceAgentOrchestrator().analyze([], detections)
    assert "lateral_movement" in result["agent_analysis"]["chain_review"]["missing_stages"]


def test_low_confidence_path_is_weak():
    result = TraceAgentOrchestrator().analyze([], chain(0.3))
    assert result["agent_analysis"]["chain_review"]["status"] == "weak"
    assert result["agent_analysis"]["chain_review"]["suspicious_edges"]


def test_invalid_llm_result_degrades_to_grounded_fallback():
    result = TraceAgentOrchestrator(FakeLLM(responses={})).analyze([], chain())
    assert result["agent_status"]["degraded"] is True
    assert len(result["agent_status"]["errors"]) == 4
    assert result["agent_analysis"]["report"]["attack_origin"] == "ip:203.0.113.8"


def test_llm_timeout_degrades_without_losing_trace():
    result = TraceAgentOrchestrator(FakeLLM(error=TimeoutError("timeout"))).analyze([], chain())
    assert result["trace"]["graph"].edges
    assert result["agent_status"]["degraded"] is True
    assert any("TimeoutError" in error for error in result["agent_status"]["errors"])


def test_attribution_without_actor_knowledge_stays_ttp_only():
    result = TraceAgentOrchestrator().analyze([], chain())
    attribution = result["agent_analysis"]["attribution"]
    assert attribution["techniques"] == ["T1190", "T1021.002", "T1071.001"]
    assert "actor identity undetermined" in attribution["possible_profile"]
    assert attribution["confidence"] <= 0.6


def test_agents_do_not_cite_detection_event_ids_missing_from_input():
    result = TraceAgentOrchestrator().analyze([], chain())
    analysis = result["agent_analysis"]

    assert analysis["evidence"]["stages"][0]["event_ids"] == []
    assert not any(
        item.startswith("evt-")
        for item in analysis["chain_review"]["evidence_ids"]
    )
    assert not any(
        item.startswith("evt-")
        for item in analysis["report"]["key_evidence_ids"]
    )
    assert result["trace"]["graph"].edges[0].related_event_ids == ["evt-initial"]


def test_hallucinated_report_ip_and_technique_are_rejected():
    evidence, chain_review, attribution = valid_agent_responses()
    bad_report = TraceReport(
        attack_origin="ip:203.0.113.8", victim_hosts=["host:WEB01"],
        privilege_escalation="not evidenced", c2_communication="See 9.9.9.9 using T9999",
        data_exfiltration="not evidenced", techniques=["T1190"],
        key_evidence_ids=["initial"], overall_confidence=0.9,
        summary="Unsupported 9.9.9.9 and T9999",
    )
    fake = FakeLLM({EvidenceReview: evidence, ChainReview: chain_review,
                    AttributionReview: attribution, TraceReport: bad_report})
    result = TraceAgentOrchestrator(fake).analyze([], chain())
    assert result["agent_status"]["degraded"] is True
    report_text = str(result["agent_analysis"]["report"])
    assert "9.9.9.9" not in report_text and "T9999" not in report_text


def test_one_agent_failure_does_not_stop_other_agents():
    evidence, chain_review, attribution = valid_agent_responses()
    fake = FakeLLM({EvidenceReview: "invalid", ChainReview: chain_review,
                    AttributionReview: attribution})
    result = TraceAgentOrchestrator(fake).analyze([], chain())
    assert result["agent_status"]["degraded"] is True
    assert result["agent_analysis"]["chain_review"]["status"] == "supported"
    assert result["agent_analysis"]["attribution"]["techniques"] == ["T1190"]


def test_disabled_agents_leave_tracing_fully_operational():
    detections = chain()
    direct = AttackTraceService().analyze([], detections)
    result = TraceAgentOrchestrator(enabled=False).analyze([], detections)
    assert result["agent_status"] == {"enabled": False, "degraded": False, "errors": []}
    assert result["agent_analysis"] == {}
    assert result["trace"]["graph"] == direct["graph"]
