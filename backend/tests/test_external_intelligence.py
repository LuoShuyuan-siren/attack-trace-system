from app.services.external_intelligence import ExternalC2Intelligence, IntelligenceResult


def test_intelligence_lookup_uses_shared_ttl_cache(monkeypatch) -> None:
    ExternalC2Intelligence.clear_cache()
    calls = {"whois": 0, "rdap": 0}

    def whois(self, indicator):
        calls["whois"] += 1
        return "whois-result"

    def rdap(self, indicator):
        calls["rdap"] += 1
        return {"domain": indicator}

    monkeypatch.setattr(ExternalC2Intelligence, "_whois", whois)
    monkeypatch.setattr(ExternalC2Intelligence, "_rdap", rdap)

    first = ExternalC2Intelligence(cache_ttl_seconds=60).lookup("Example.COM")
    second = ExternalC2Intelligence(cache_ttl_seconds=60).lookup("example.com")

    assert first == second == IntelligenceResult(
        indicator="example.com",
        whois="whois-result",
        rdap={"domain": "example.com"},
        passive_dns=None,
    )
    assert calls == {"whois": 1, "rdap": 1}


def test_invalid_cache_ttl_falls_back_to_default(monkeypatch) -> None:
    monkeypatch.setenv("PASSIVE_INTELLIGENCE_CACHE_TTL", "invalid")
    client = ExternalC2Intelligence()

    assert client.cache_ttl_seconds == 300.0
