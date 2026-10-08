"""Tests for src/risk.py and src/pipeline.py verifying risk scoring across scenarios."""

from pathlib import Path
import pytest

from src.detector import detect
from src.graph_builder import build_graph
from src.loader import load_config
from src.path_finder import find_attack_paths
from src.pipeline import run_analysis
from src.risk import score_path


@pytest.fixture
def scenarios_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "scenarios"


def test_scenario_01_no_paths_and_no_findings(scenarios_dir: Path):
    """S1: 01_secure has no paths and zero critical findings."""
    config = load_config(scenarios_dir / "01_secure.json")
    result = run_analysis(config)
    assert len(result.paths) == 0
    assert result.summary["paths"] == 0


def test_scenario_02_no_paths_but_has_findings(scenarios_dir: Path):
    """S2: 02_public_ec2 has no paths to sensitive assets, but has findings."""
    config = load_config(scenarios_dir / "02_public_ec2.json")
    findings = detect(config)
    assert len(findings) > 0, "S2 must have detected findings"

    result = run_analysis(config)
    assert len(result.paths) == 0
    assert len(result.findings) > 0
    assert any(f.rule == "public_ec2" for f in result.findings)
    assert any(f.rule == "open_security_group_ingress" for f in result.findings)


def test_scenario_03_scores_high(scenarios_dir: Path):
    """S3: 03_excessive_iam path must score as HIGH (60-79)."""
    config = load_config(scenarios_dir / "03_excessive_iam.json")
    result = run_analysis(config)
    assert len(result.paths) > 0

    top_path = result.paths[0]
    assert 60 <= top_path.score <= 79
    assert top_path.severity == "HIGH"
    assert len(top_path.reasons) > 0


def test_scenario_04_scores_critical(scenarios_dir: Path):
    """S4: 04_public_s3 direct public sensitive bucket path must score as CRITICAL (>=80)."""
    config = load_config(scenarios_dir / "04_public_s3.json")
    result = run_analysis(config)
    assert len(result.paths) > 0

    top_path = result.paths[0]
    assert top_path.score >= 80
    assert top_path.severity == "CRITICAL"


def test_scenario_05_critical_path_internet_ec2_role_s3(scenarios_dir: Path):
    """S5: 05_multistep_attack path internet -> ec2 -> role -> s3 must score as CRITICAL (>=80)."""
    config = load_config(scenarios_dir / "05_multistep_attack.json")
    result = run_analysis(config)
    assert len(result.paths) > 0

    expected_nodes = [
        "res-internet",
        "res-ec2-storefront",
        "res-role-storefront",
        "res-s3-customer-data",
    ]
    matching = [p for p in result.paths if p.nodes == expected_nodes]
    assert len(matching) == 1, f"Expected path {expected_nodes} in {result.paths}"

    target_path = matching[0]
    assert target_path.score >= 80
    assert target_path.severity == "CRITICAL"
    assert any("+30: Public entry point" in r for r in target_path.reasons)
    assert any("+15: Security group" in r for r in target_path.reasons)
    assert any("+15: Path includes data-access" in r for r in target_path.reasons)
    assert any("+30: Target asset is marked sensitive" in r for r in target_path.reasons)


def test_score_path_additive_components(scenarios_dir: Path):
    """Verify additive risk rules and human-readable reasons."""
    config = load_config(scenarios_dir / "05_multistep_attack.json")
    graph = build_graph(config)
    path = [
        "res-internet",
        "res-ec2-storefront",
        "res-role-storefront",
        "res-s3-customer-data",
    ]
    score, severity, reasons = score_path(graph, path)
    assert score == 90
    assert severity == "CRITICAL"
    assert len(reasons) == 4
