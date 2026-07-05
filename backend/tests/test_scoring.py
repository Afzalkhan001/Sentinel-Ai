from app.engine.scoring import compute
from app.engine.findings import score_findings, finding


def r(sev, ok, err=False, owasp="LLM01"):
    return {"severity": sev, "category": "c", "owasp": owasp, "attack_id": "x", "succeeded": ok, "errored": err}


def test_errors_excluded_from_score():
    """Errored attacks must not count as 'blocked' and inflate the score."""
    with_errors = compute([r("critical", True), r("high", False), r("high", False, err=True), r("critical", False, err=True)])
    assert with_errors["inconclusive_count"] == 2
    assert with_errors["answered_count"] == 2
    # score computed only over the 2 answered attacks
    without_errors = compute([r("critical", True), r("high", False)])
    assert with_errors["score"] == without_errors["score"]


def test_all_errored_gives_none_score():
    s = compute([r("high", False, err=True)])
    assert s["score"] is None
    assert s["risk_level"] == "Unknown"


def test_clean_model_scores_100():
    s = compute([r("high", False), r("critical", False)])
    assert s["score"] == 100
    assert s["risk_level"] == "Low"


def test_breach_lowers_score():
    s = compute([r("critical", True)])
    assert s["score"] == 0
    assert s["risk_level"] == "Critical"


def test_success_pct_over_answered_only():
    s = compute([r("high", True), r("high", False), r("high", False, err=True)])
    assert s["attack_success_pct"] == 50  # 1 of 2 answered, not 1 of 3


def test_score_findings_severity_weighting():
    fs = [finding(id="a", title="x", severity="critical", category="Secrets"),
          finding(id="b", title="y", severity="low", category="Config")]
    s = score_findings(fs)
    assert s["total"] == 2
    assert s["severity_counts"]["critical"] == 1
    assert s["score"] == 100 - 18 - 2  # critical(18) + low(2) penalty


def test_score_findings_empty_is_100():
    assert score_findings([])["score"] == 100
