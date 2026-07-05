"""Shared 'Finding' shape + scoring used by the repo and website scanners.

A Finding is one security issue. Both scanners emit a list of these, and both use
score_findings() to turn them into a 0-100 security score + OWASP-style breakdown,
mirroring how the LLM attack runner scores a Run.
"""
from collections import defaultdict

SEVERITY_WEIGHT = {"low": 2, "medium": 5, "high": 10, "critical": 18}
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def finding(
    *,
    id: str,
    title: str,
    severity: str,
    category: str,
    owasp: str = "",
    location: str = "",
    line: int | None = None,
    evidence: str = "",
    description: str = "",
    recommendation: str = "",
    source: str = "rule",
) -> dict:
    """Build one normalized finding dict."""
    return {
        "id": id,
        "title": title,
        "severity": severity if severity in SEVERITY_WEIGHT else "medium",
        "category": category,
        "owasp": owasp,
        "location": location,
        "line": line,
        "evidence": (evidence or "")[:400],
        "description": description,
        "recommendation": recommendation,
        "source": source,
    }


def risk_level(score: int) -> str:
    if score >= 90:
        return "Low"
    if score >= 70:
        return "Moderate"
    if score >= 40:
        return "High"
    return "Critical"


def score_findings(findings: list[dict]) -> dict:
    """Turn findings into score / risk / severity counts / category breakdown."""
    penalty = sum(SEVERITY_WEIGHT.get(f["severity"], 5) for f in findings)
    score = max(0, 100 - penalty)

    sev_counts = defaultdict(int)
    for f in findings:
        sev_counts[f["severity"]] += 1

    groups: dict[str, int] = defaultdict(int)
    for f in findings:
        groups[f["category"]] += 1
    breakdown = [{"category": k, "count": v} for k, v in sorted(groups.items(), key=lambda kv: -kv[1])]

    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 9))

    return {
        "score": score,
        "risk_level": risk_level(score),
        "total": len(findings),
        "severity_counts": {
            "critical": sev_counts["critical"],
            "high": sev_counts["high"],
            "medium": sev_counts["medium"],
            "low": sev_counts["low"],
        },
        "category_breakdown": breakdown,
        "findings": ordered,
    }
