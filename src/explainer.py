"""Optional AI-powered explanation of findings and attack paths.

Uses OpenAI (if configured) to generate plain-English summaries.
This module NEVER performs security detection — only explains results
that were already found deterministically.
"""

from __future__ import annotations

import os

from .models import AnalysisReport


def _get_client():
    """Lazily create an OpenAI client. Returns None if no key is set."""
    api_key = os.environ.get("OPENAI_API_KEY", "")
    if not api_key or api_key.startswith("sk-..."):
        return None
    try:
        from openai import OpenAI
        return OpenAI(api_key=api_key)
    except Exception:
        return None


def explain_report(report: AnalysisReport) -> str:
    """Generate a natural-language explanation of the analysis report.

    Falls back to a simple template if OpenAI is unavailable.
    """
    client = _get_client()
    if client is None:
        return _template_explanation(report)

    prompt = _build_prompt(report)
    try:
        response = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are a cloud security analyst. Explain the following "
                        "security analysis results in clear, actionable language. "
                        "Focus on the most critical risks first. Be concise."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            max_tokens=1000,
            temperature=0.3,
        )
        return response.choices[0].message.content or _template_explanation(report)
    except Exception as e:
        return _template_explanation(report) + f"\n\n(AI explanation unavailable: {e})"


def _build_prompt(report: AnalysisReport) -> str:
    lines = [
        f"Account: {report.config_metadata.get('account_id', 'N/A')}",
        f"Region: {report.config_metadata.get('region', 'N/A')}",
        f"Resources scanned: {report.resources_count}",
        f"Overall risk score: {report.risk_summary.get('overall_score', 'N/A')}/100",
        f"Rating: {report.risk_summary.get('rating', 'N/A')}",
        "",
        "## Findings",
    ]
    for f in report.findings[:15]:
        sev_str = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        lines.append(f"- [{sev_str}] {f.title}: {f.description}")

    lines.append("")
    lines.append("## Attack Paths")
    for p in report.attack_paths[:5]:
        step_chain = " → ".join(s.resource_name for s in p.steps)
        lines.append(f"- (Risk {p.risk_score}/10) {step_chain}")

    return "\n".join(lines)


def _template_explanation(report: AnalysisReport) -> str:
    """Fallback plain-text explanation without AI."""
    summary = report.risk_summary
    lines = [
        f"## Security Analysis Summary",
        f"",
        f"**Overall Risk Score:** {summary.get('overall_score', 'N/A')}/100 "
        f"({summary.get('rating', 'N/A')})",
        f"",
        f"**Findings:** {summary.get('total_findings', 0)} issues found",
    ]
    counts = summary.get("severity_counts", {})
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        c = counts.get(sev, 0)
        if c > 0:
            lines.append(f"  - {sev}: {c}")

    paths = report.attack_paths
    if paths:
        lines.append(f"")
        lines.append(f"**Attack Paths:** {len(paths)} paths discovered")
        for p in paths[:5]:
            chain = " → ".join(s.resource_name for s in p.steps)
            lines.append(f"  - [{p.risk_score}/10] {chain}")

    crit_findings = [
        f for f in report.findings
        if (f.severity.value if hasattr(f.severity, "value") else str(f.severity)) == "CRITICAL"
    ]
    if crit_findings:
        lines.append(f"")
        lines.append("**Recommended immediate actions:**")
        for f in crit_findings[:5]:
            lines.append(f"  - Fix: {f.title} on {f.resource_name}")

    return "\n".join(lines)
