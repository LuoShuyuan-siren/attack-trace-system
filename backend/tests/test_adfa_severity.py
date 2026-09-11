from app.analyzers.adfa_ld import severity_for_score


def test_adfa_severity_uses_four_threshold_relative_levels() -> None:
    threshold = 10.0

    assert severity_for_score(10.0, threshold) == "low"
    assert severity_for_score(11.99, threshold) == "low"
    assert severity_for_score(12.0, threshold) == "medium"
    assert severity_for_score(15.0, threshold) == "high"
    assert severity_for_score(20.0, threshold) == "critical"