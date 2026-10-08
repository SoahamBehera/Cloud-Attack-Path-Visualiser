"""Tests for the risk scorer."""

from src.detectors import run_all_detectors
from src.graph_builder import build_graph
from src.models import CloudConfig
from src.pathfinder import find_attack_paths
from src.risk_scorer import compute_risk_summary


def test_risk_summary_structure(sample_config: CloudConfig):
    findings = run_all_detectors(sample_config.resources)
    G = build_graph(sample_config.resources, findings)
    paths = find_attack_paths(G)
    summary = compute_risk_summary(findings, paths)

    assert "overall_score" in summary
    assert "rating" in summary
    assert "severity_counts" in summary
    assert "total_findings" in summary
    assert "total_attack_paths" in summary
    assert 0 <= summary["overall_score"] <= 100


def test_risk_score_reflects_severity(sample_config: CloudConfig):
    findings = run_all_detectors(sample_config.resources)
    G = build_graph(sample_config.resources, findings)
    paths = find_attack_paths(G)
    summary = compute_risk_summary(findings, paths)

    # Our sample has critical findings → score should be at least MEDIUM
    assert summary["overall_score"] >= 40
    assert summary["rating"] in ("CRITICAL", "HIGH", "MEDIUM")


def test_empty_findings_low_risk():
    summary = compute_risk_summary([], [])
    assert summary["overall_score"] <= 20
    assert summary["total_findings"] == 0
