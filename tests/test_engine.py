"""Tests for the full engine pipeline."""

from pathlib import Path

from src.engine import analyze, get_explanation
from src.models import AnalysisReport


def test_full_pipeline(sample_config_path: Path):
    report, graph = analyze(sample_config_path)
    assert isinstance(report, AnalysisReport)
    assert report.resources_count > 0
    assert len(report.findings) > 0
    assert len(report.attack_paths) > 0
    assert report.risk_summary["overall_score"] > 0


def test_full_pipeline_from_dict(sample_config_dict: dict):
    report, graph = analyze(sample_config_dict)
    assert isinstance(report, AnalysisReport)
    assert report.resources_count == len(sample_config_dict["resources"])


def test_explanation_returns_string(sample_config_path: Path):
    report, _ = analyze(sample_config_path)
    explanation = get_explanation(report)
    assert isinstance(explanation, str)
    assert len(explanation) > 50
