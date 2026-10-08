"""Tests for src/path_finder.py verifying attack path discovery across scenarios."""

from pathlib import Path
import pytest

from src.graph_builder import build_graph
from src.loader import load_config
from src.path_finder import find_attack_paths


@pytest.fixture
def scenarios_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "scenarios"


def test_scenario_01_no_paths(scenarios_dir: Path):
    """S1 (01_secure): private isolated infrastructure must have NO attack paths."""
    config = load_config(scenarios_dir / "01_secure.json")
    graph = build_graph(config)
    paths = find_attack_paths(graph)
    assert len(paths) == 0, f"Expected 0 paths for S1, found {paths}"


def test_scenario_02_no_paths_to_sensitive_targets(scenarios_dir: Path):
    """S2 (02_public_ec2): bastion is public with findings, but has NO route to sensitive targets."""
    config = load_config(scenarios_dir / "02_public_ec2.json")
    graph = build_graph(config)
    paths = find_attack_paths(graph)
    assert len(paths) == 0, f"Expected 0 paths for S2, found {paths}"


def test_scenario_03_has_paths_to_sensitive_targets(scenarios_dir: Path):
    """S3 (03_excessive_iam): attack paths discovered from internet to sensitive assets."""
    config = load_config(scenarios_dir / "03_excessive_iam.json")
    graph = build_graph(config)
    paths = find_attack_paths(graph)
    assert len(paths) > 0, "Expected attack paths in S3 via wildcard IAM role"


def test_scenario_04_direct_path_to_sensitive_s3(scenarios_dir: Path):
    """S4 (04_public_s3): direct attack path from internet to public sensitive S3 bucket."""
    config = load_config(scenarios_dir / "04_public_s3.json")
    graph = build_graph(config)
    paths = find_attack_paths(graph)
    assert len(paths) > 0
    assert ["res-internet", "res-s3-leaked-kyc"] in paths


def test_scenario_05_multistep_attack_path(scenarios_dir: Path):
    """S5 (05_multistep_attack): discovers path internet -> ec2 -> role -> s3."""
    config = load_config(scenarios_dir / "05_multistep_attack.json")
    graph = build_graph(config)
    paths = find_attack_paths(graph)
    assert len(paths) > 0

    expected_chain = [
        "res-internet",
        "res-ec2-storefront",
        "res-role-storefront",
        "res-s3-customer-data",
    ]
    assert expected_chain in paths, f"Expected path {expected_chain} not found in {paths}"
