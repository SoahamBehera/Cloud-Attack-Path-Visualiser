"""Risk scoring and summary generation for the full analysis."""

from __future__ import annotations

from .models import AttackPath, Finding, Severity


_SEV_WEIGHTS: dict[str, int] = {
    "CRITICAL": 10,
    "HIGH": 7,
    "MEDIUM": 4,
    "LOW": 2,
    "INFO": 1,
}


def compute_risk_summary(findings: list[Finding], attack_paths: list[AttackPath]) -> dict:
    """Build a risk summary from findings and attack paths.

    Returns a dict with counts by severity, overall score (0-100),
    rating label, and category breakdown.
    """
    severity_counts: dict[str, int] = {s: 0 for s in _SEV_WEIGHTS}
    category_counts: dict[str, int] = {}

    for f in findings:
        sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        severity_counts[sev_str] = severity_counts.get(sev_str, 0) + 1
        category_counts[f.category] = category_counts.get(f.category, 0) + 1

    # Weighted finding score (0-100 scale)
    weighted = sum(
        _SEV_WEIGHTS.get(f.severity.value if hasattr(f.severity, "value") else str(f.severity), 1)
        for f in findings
    )
    max_possible = max(len(findings) * 10, 1)
    finding_score = min((weighted / max_possible) * 100, 100)

    # Attack-path contribution
    path_score = 0.0
    if attack_paths:
        max_risk = max(p.risk_score for p in attack_paths)
        path_score = max_risk * 10  # scale 0-10 to 0-100

    overall = min(round(finding_score * 0.5 + path_score * 0.5, 1), 100.0)

    if overall >= 80:
        rating = "CRITICAL"
    elif overall >= 60:
        rating = "HIGH"
    elif overall >= 40:
        rating = "MEDIUM"
    elif overall >= 20:
        rating = "LOW"
    else:
        rating = "MINIMAL"

    return {
        "overall_score": overall,
        "rating": rating,
        "severity_counts": severity_counts,
        "category_counts": category_counts,
        "total_findings": len(findings),
        "total_attack_paths": len(attack_paths),
        "highest_path_risk": round(max(p.risk_score for p in attack_paths), 1) if attack_paths else 0.0,
    }
