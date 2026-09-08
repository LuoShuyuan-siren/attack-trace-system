import json
import logging

import pytest

from app.analyzers.tracing.agents import TraceAgentOrchestrator
from app.analyzers.tracing.agents.llm import LLMAdapterError, LLMSettings, RealLLMClient, create_llm_client
from app.analyzers.tracing.agents.llm.base import LLMAuthenticationError, LLMResponseError, LLMServerError
from app.analyzers.tracing.agents.models import ChainReview
from app.schemas.detection import DetectionResult


def response(content, status=200):
    raw = json.dumps({"choices": [{"message": {"content": content}}]}).encode()
    return status, {"x-request-id": "req-test"}, raw


def valid_review():
    return {
        "status": "supported", "confidence": 0.9,
        "supported_stages": ["initial_access"], "weak_stages": [],
        "missing_stages": [], "suspicious_edges": [],
        "evidence_ids": [], "summary": "supported",
    }


def client(transport, retries=2, key="secret-key"):
    return RealLLMClient(
        LLMSettings(
            provider="openai_compatible", api_key=key, model="test-model",
            base_url="https://llm.invalid/v1", timeout=1, max_retries=retries,
        ),
        transport=transport, sleeper=lambda _: None,
    )


def test_factory_disabled():
    assert create_llm_client({"LLM_ENABLED": "false"}) is None


@pytest.mark.parametrize(
    "env",
    [
        {"LLM_ENABLED": "true", "LLM_PROVIDER": "openai_compatible", "LLM_MODEL": "m"},
        {"LLM_ENABLED": "true", "LLM_API_KEY": "k", "LLM_MODEL": "m"},
        {"LLM_ENABLED": "true", "LLM_PROVIDER": "openai_compatible", "LLM_API_KEY": "k"},
    ],
)
def test_factory_missing_required_configuration(env):
    assert create_llm_client(env) is None


def test_timeout_is_wrapped():
    def timeout(*_):
        raise TimeoutError("timed out")
    with pytest.raises(LLMAdapterError, match="TimeoutError"):
        client(timeout).generate_structured(
            system_prompt="safe", input_data={"small": True}, response_model=ChainReview
        )


def test_429_retries_then_succeeds():
    calls = []
    def transport(*_):
        calls.append(1)
        return response("rate", 429) if len(calls) == 1 else response(json.dumps(valid_review()))
    result = client(transport).generate_structured(
        system_prompt="safe", input_data={}, response_model=ChainReview
    )
    assert result["status"] == "supported"
    assert len(calls) == 2


def test_5xx_retries_then_fails():
    calls = []
    def transport(*_):
        calls.append(1)
        return response("error", 503)
    with pytest.raises(LLMServerError):
        client(transport, retries=2).generate_structured(
            system_prompt="safe", input_data={}, response_model=ChainReview
        )
    assert len(calls) == 3


def test_401_does_not_retry():
    calls = []
    def transport(*_):
        calls.append(1)
        return response("unauthorized", 401)
    with pytest.raises(LLMAuthenticationError):
        client(transport).generate_structured(
            system_prompt="safe", input_data={}, response_model=ChainReview
        )
    assert len(calls) == 1


def test_invalid_json():
    with pytest.raises(LLMResponseError, match="invalid structured JSON"):
        client(lambda *_: response("not-json")).generate_structured(
            system_prompt="safe", input_data={}, response_model=ChainReview
        )


def test_schema_validation_failure():
    with pytest.raises(LLMResponseError, match="schema validation"):
        client(lambda *_: response(json.dumps({"status": "supported"}))).generate_structured(
            system_prompt="safe", input_data={}, response_model=ChainReview
        )


def test_real_client_error_causes_agent_fallback():
    broken = client(lambda *_: response("", 503), retries=0)
    detection = DetectionResult(
        detection_id="det-1", timestamp="2026-09-08T10:00:00Z", analyzer="test",
        detection_type="malicious_behavior", title="initial", confidence=0.9,
        related_event_ids=["evt-1"],
        related_entity_ids=["ip:203.0.113.8", "host:WEB01"],
        attack_technique_id="T1190", tags=["initial_access"],
    )
    result = TraceAgentOrchestrator(broken).analyze([], [detection])
    assert result["agent_status"]["degraded"] is True
    assert result["trace"]["graph"].edges
    assert result["agent_analysis"]["evidence"]


def test_logs_do_not_contain_key_or_input(caplog):
    secret = "super-secret-key"
    sensitive = "user=alice file=C:/private/secret.txt"
    caplog.set_level(logging.INFO)
    client(lambda *_: response(json.dumps(valid_review())), key=secret).generate_structured(
        system_prompt="do not log", input_data={"evidence": sensitive},
        response_model=ChainReview,
    )
    logs = caplog.text
    assert secret not in logs
    assert sensitive not in logs
    assert "openai_compatible" in logs and "test-model" in logs
