import json

import pytest

from app.analyzers.tracing.agents.llm import DeepSeekClient, LLMSettings, create_llm_client
from app.analyzers.tracing.agents.llm.base import LLMResponseError
from app.analyzers.tracing.agents.models import ChainReview


def review():
    return {
        "status": "supported", "confidence": 0.9,
        "supported_stages": ["initial_access"], "weak_stages": [],
        "missing_stages": [], "suspicious_edges": [],
        "evidence_ids": [], "summary": "grounded",
    }


def response(value, status=200):
    envelope = {
        "id": "resp-test", "status": "completed",
        "output": [{"type": "message", "content": [
            {"type": "output_text", "text": json.dumps(value)}
        ]}],
    }
    return status, {"x-request-id": "req-deepseek"}, json.dumps(envelope).encode()


def settings(retries=1):
    return LLMSettings(
        provider="deepseek", api_key="test-key", model="deepseek-v4-pro",
        base_url="https://api.deepseek.com", timeout=2, max_retries=retries,
    )


def test_factory_creates_deepseek_client():
    client = create_llm_client({
        "LLM_ENABLED": "true", "LLM_PROVIDER": "deepseek",
        "LLM_API_KEY": "key", "LLM_MODEL": "deepseek-v4-pro",
    })
    assert isinstance(client, DeepSeekClient)
    assert client.settings.base_url == "https://api.deepseek.com"


def test_deepseek_uses_responses_json_schema():
    captured = {}

    def transport(url, headers, body, timeout):
        captured.update(url=url, headers=headers, body=json.loads(body), timeout=timeout)
        return response(review())

    result = DeepSeekClient(
        settings(), transport=transport, sleeper=lambda _: None
    ).generate_structured(
        system_prompt="Return grounded JSON.",
        input_data={"edge_ids": ["edge-1"]},
        response_model=ChainReview,
    )
    assert captured["url"] == "https://api.deepseek.com/responses"
    assert captured["body"]["instructions"] == "Return grounded JSON."
    assert json.loads(captured["body"]["input"]) == {"edge_ids": ["edge-1"]}
    assert captured["body"]["text"]["format"]["type"] == "json_schema"
    assert captured["body"]["text"]["format"]["schema"] == ChainReview.model_json_schema()
    assert result["status"] == "supported"


def test_deepseek_429_retry_uses_same_safe_request():
    calls = []

    def transport(*args):
        calls.append(args)
        return (429, {}, b"{}") if len(calls) == 1 else response(review())

    client = DeepSeekClient(settings(), transport=transport, sleeper=lambda _: None)
    assert client.generate_structured(
        system_prompt="JSON", input_data={}, response_model=ChainReview
    )["status"] == "supported"
    assert len(calls) == 2


@pytest.mark.parametrize(
    "payload",
    [
        {"id": "x", "status": "failed", "output": []},
        {"id": "x", "status": "completed", "output": []},
        {"id": "x", "status": "completed", "output": [
            {"type": "message", "content": [
                {"type": "output_text", "text": "not-json"}
            ]}
        ]},
    ],
)
def test_deepseek_rejects_failed_empty_or_invalid_output(payload):
    raw = json.dumps(payload).encode()
    client = DeepSeekClient(
        settings(0), transport=lambda *_: (200, {}, raw), sleeper=lambda _: None
    )
    with pytest.raises(LLMResponseError):
        client.generate_structured(
            system_prompt="JSON", input_data={}, response_model=ChainReview
        )
