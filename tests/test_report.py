"""Unit tests for src/report.py verifying markdown security report generation."""

from pathlib import Path
import pytest

from src.loader import load_config
from src.pipeline import run_analysis
from src.report import build_markdown_report


@pytest.fixture
def scenarios_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "scenarios"


def test_build_markdown_report_scenario_01_no_paths(scenarios_dir: Path):
    """Test report generation for secure scenario with 0 attack paths."""
    cfg = load_config(scenarios_dir / "01_secure.json")
    result = run_analysis(cfg)
    report_md = build_markdown_report(result)

    assert isinstance(report_md, str)
    assert "# 🛡️ Cloud Security & Attack Path Analysis Report" in report_md
    assert "01_secure" in report_md
    assert "Executive Summary & Metrics" in report_md
    assert "🛡️ **No attack paths discovered.**" in report_md
    assert "Total Resources" in report_md


def test_build_markdown_report_scenario_05_with_paths_and_ai(scenarios_dir: Path):
    """Test report generation for multi-step attack with paths and AI explanations."""
    cfg = load_config(scenarios_dir / "05_multistep_attack.json")
    result = run_analysis(cfg)

    top_path = result.paths[0]
    explanations = {
        tuple(top_path.nodes): {
            "executive_summary": "Critical exposure chain reaching sensitive customer PII vault.",
            "summary": "Attacker traverses public EC2, assumes instance profile, and accesses S3.",
            "why_it_exists": "Unrestricted port 22 access coupled with broad S3 read policy.",
            "impact": "Exfiltration of sensitive customer data.",
            "remediation": [
                "Restrict security group port 22 access.",
                "Enforce least privilege IAM role policies."
            ],
            "source": "openai"
        }
    }

    report_md = build_markdown_report(result, explanations=explanations)

    assert "05_multistep_attack" in report_md
    assert "Detected Security Findings" in report_md
    assert "open_security_group_ingress" in report_md
    assert "Path 1:" in report_md
    assert "Attack Chain:" in report_md
    assert "Scoring Factors:" in report_md
    assert "Recommended Fixes:" in report_md
    assert "AI Security Analyst Assessment" in report_md
    assert "Critical exposure chain reaching sensitive customer PII vault." in report_md
    assert "Restrict security group port 22 access." in report_md
