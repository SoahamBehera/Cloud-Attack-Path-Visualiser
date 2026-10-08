"""Tests verifying requirements for all 5 scenario JSON files."""

from pathlib import Path
import pytest
import networkx as nx

from src.loader import load_config
from src.models import CloudConfig


@pytest.fixture
def scenarios_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "scenarios"


def _build_scenario_graph(config: CloudConfig) -> nx.DiGraph:
    G = nx.DiGraph()
    for res in config.resources:
        G.add_node(res.id, **res.model_dump())
    for rel in config.relationships:
        G.add_edge(rel.source, rel.target, type=rel.type)
    return G


def test_scenario_01_secure(scenarios_dir: Path):
    """01_secure: private EC2, restricted IAM role, private S3; no path from the internet."""
    config = load_config(scenarios_dir / "01_secure.json")
    assert 5 <= len(config.resources) <= 10

    # Must contain internet resource
    internet_nodes = [r.id for r in config.resources if r.type == "internet"]
    assert len(internet_nodes) == 1
    internet_id = internet_nodes[0]

    # Verify no outgoing edges or path from internet
    G = _build_scenario_graph(config)
    reachable_from_internet = nx.descendants(G, internet_id)
    assert len(reachable_from_internet) == 0, "Internet must not reach any resource in 01_secure"


def test_scenario_02_public_ec2(scenarios_dir: Path):
    """02_public_ec2: public EC2 with SG open to 0.0.0.0/0 on port 22, no route to sensitive assets."""
    config = load_config(scenarios_dir / "02_public_ec2.json")
    assert 5 <= len(config.resources) <= 10

    # Public EC2 and open SG
    ec2_nodes = [r for r in config.resources if r.type == "ec2"]
    assert any(r.public for r in ec2_nodes)

    sg_nodes = [r for r in config.resources if r.type == "security_group"]
    assert any(
        any(rule.get("port") == 22 and rule.get("source") == "0.0.0.0/0" for rule in sg.properties.get("inbound_rules", []))
        for sg in sg_nodes
    )

    # Sensitive assets must NOT be reachable from internet
    G = _build_scenario_graph(config)
    internet_id = [r.id for r in config.resources if r.type == "internet"][0]
    reachable = nx.descendants(G, internet_id)

    sensitive_ids = {r.id for r in config.resources if r.sensitive}
    assert len(sensitive_ids) > 0
    assert not (reachable & sensitive_ids), "Sensitive assets must not be reachable in 02_public_ec2"


def test_scenario_03_excessive_iam(scenarios_dir: Path):
    """03_excessive_iam: EC2 whose role has '*' permissions reaching several resources."""
    config = load_config(scenarios_dir / "03_excessive_iam.json")
    assert 5 <= len(config.resources) <= 10

    roles = [r for r in config.resources if r.type == "iam_role"]
    assert any("*" in r.properties.get("policies", []) for r in roles)

    # Check that role has relationships reaching several resources
    wildcard_role = [r for r in roles if "*" in r.properties.get("policies", [])][0]
    targets = [rel.target for rel in config.relationships if rel.source == wildcard_role.id]
    assert len(set(targets)) >= 3, "Wildcard IAM role must reach several resources"


def test_scenario_04_public_s3(scenarios_dir: Path):
    """04_public_s3: public sensitive S3 bucket directly exposed to the internet."""
    config = load_config(scenarios_dir / "04_public_s3.json")
    assert 5 <= len(config.resources) <= 10

    # S3 bucket that is BOTH public and sensitive
    public_sensitive_s3 = [
        r for r in config.resources if r.type == "s3" and r.public and r.sensitive
    ]
    assert len(public_sensitive_s3) >= 1

    # Directly exposed to the internet
    internet_id = [r.id for r in config.resources if r.type == "internet"][0]
    target_bucket_id = public_sensitive_s3[0].id

    G = _build_scenario_graph(config)
    assert G.has_edge(internet_id, target_bucket_id), "Internet must directly expose the public sensitive S3 bucket"


def test_scenario_05_multistep_attack(scenarios_dir: Path):
    """05_multistep_attack: internet -> public EC2 (open SG) -> IAM role (s3:GetObject) -> sensitive S3 customer-data bucket."""
    config = load_config(scenarios_dir / "05_multistep_attack.json")
    assert 5 <= len(config.resources) <= 10

    internet_id = [r.id for r in config.resources if r.type == "internet"][0]
    sensitive_s3 = [r for r in config.resources if r.type == "s3" and r.sensitive][0]

    G = _build_scenario_graph(config)
    paths = list(nx.all_simple_paths(G, internet_id, sensitive_s3.id))
    assert len(paths) >= 1, "There must be an attack path from internet to sensitive S3 bucket"

    # Verify the path steps through EC2 and IAM role
    path = paths[0]
    res_map = {r.id: r for r in config.resources}
    types_in_path = [res_map[nid].type for nid in path]
    assert "internet" in types_in_path
    assert "security_group" in types_in_path
    assert "ec2" in types_in_path
    assert "iam_role" in types_in_path
    assert "s3" in types_in_path
