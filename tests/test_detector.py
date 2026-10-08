"""Tests for src/detector.py checking scenarios 2, 3, and 5 findings and graph building."""

from pathlib import Path
import pytest

from src.detector import detect
from src.graph_builder import build_graph
from src.loader import load_config
from src.models import CloudConfig, Resource


@pytest.fixture
def scenarios_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "scenarios"


# ── Scenario 2 Tests ────────────────────────────────────────────────


def test_scenario_02_findings(scenarios_dir: Path):
    """Scenario 02: Public EC2 and open SG on port 22."""
    config = load_config(scenarios_dir / "02_public_ec2.json")
    findings = detect(config)

    rules = [f.rule for f in findings]
    assert "public_ec2" in rules
    assert "open_security_group_ingress" in rules

    # Public EC2 finding validation
    ec2_finding = next(f for f in findings if f.rule == "public_ec2")
    assert ec2_finding.resource_id == "res-ec2-bastion"
    assert ec2_finding.severity == "HIGH"
    assert ec2_finding.recommendation == "block public access"

    # Open Security Group ingress on port 22 validation
    sg_finding = next(f for f in findings if f.rule == "open_security_group_ingress")
    assert sg_finding.resource_id == "res-sg-bastion"
    assert sg_finding.severity == "HIGH"
    assert sg_finding.recommendation == "restrict CIDR"


# ── Scenario 3 Tests ────────────────────────────────────────────────


def test_scenario_03_findings(scenarios_dir: Path):
    """Scenario 03: Overprivileged admin role with wildcard * permissions."""
    config = load_config(scenarios_dir / "03_excessive_iam.json")
    findings = detect(config)

    rules = [f.rule for f in findings]
    assert "admin_role" in rules
    assert "iam_wildcard_permissions" in rules

    # Admin role finding: CRITICAL
    admin_finding = next(f for f in findings if f.rule == "admin_role")
    assert admin_finding.resource_id == "res-role-superadmin"
    assert admin_finding.severity == "CRITICAL"
    assert admin_finding.recommendation == "least privilege"

    # IAM wildcard permissions: HIGH
    wildcard_finding = next(f for f in findings if f.rule == "iam_wildcard_permissions")
    assert wildcard_finding.resource_id == "res-role-superadmin"
    assert wildcard_finding.severity == "HIGH"
    assert wildcard_finding.recommendation == "least privilege"


# ── Scenario 5 Tests ────────────────────────────────────────────────


def test_scenario_05_findings(scenarios_dir: Path):
    """Scenario 05: Public EC2 and multi-port open SG (ports 22, 80, 443)."""
    config = load_config(scenarios_dir / "05_multistep_attack.json")
    findings = detect(config)

    rules = [f.rule for f in findings]
    assert "public_ec2" in rules
    assert "open_security_group_ingress" in rules

    # Public EC2
    ec2_finding = next(f for f in findings if f.rule == "public_ec2")
    assert ec2_finding.resource_id == "res-ec2-storefront"
    assert ec2_finding.severity == "HIGH"
    assert ec2_finding.recommendation == "block public access"

    # Open SG: Port 22 must be HIGH, ports 80/443 must be MEDIUM
    sg_findings = [f for f in findings if f.rule == "open_security_group_ingress"]
    assert len(sg_findings) == 3

    high_sg = [f for f in sg_findings if f.severity == "HIGH"]
    assert len(high_sg) == 1
    assert "port 22" in high_sg[0].description

    med_sg = [f for f in sg_findings if f.severity == "MEDIUM"]
    assert len(med_sg) == 2
    for f in sg_findings:
        assert f.recommendation == "restrict CIDR"


# ── Graph Builder Verification ──────────────────────────────────────


def test_build_graph_node_and_edge_attributes(scenarios_dir: Path):
    """Verify build_graph generates nodes and edges with exact required attributes."""
    config = load_config(scenarios_dir / "02_public_ec2.json")
    G = build_graph(config)

    # Check node attributes: type, name, public, sensitive, findings, permissions
    for node_id, data in G.nodes(data=True):
        if node_id == "INTERNET":
            continue
        assert "type" in data
        assert "name" in data
        assert "public" in data
        assert "sensitive" in data
        assert "findings" in data
        assert isinstance(data["findings"], list)
        assert "permissions" in data
        assert isinstance(data["permissions"], list)

    # Check edge attribute: type
    for u, v, data in G.edges(data=True):
        assert "type" in data

    # Verify edge internet -> any resource with public=True of type "exposes"
    internet_nodes = [r.id for r in config.resources if r.type == "internet"]
    assert len(internet_nodes) == 1
    int_id = internet_nodes[0]

    for r in config.resources:
        if r.public and r.id != int_id:
            assert G.has_edge(int_id, r.id)
            assert G[int_id][r.id]["type"] == "exposes"


def test_build_graph_ec2_security_group_link():
    """Verify linking ec2 -> its security_group via connects_to when properties.security_group is set."""
    cfg = CloudConfig(
        scenario_name="test_sg_link",
        resources=[
            Resource(id="net-1", type="internet", name="Internet", public=True),
            Resource(
                id="vm-1",
                type="ec2",
                name="WebServer",
                public=True,
                properties={"security_group": "sg-1"},
            ),
            Resource(
                id="sg-1",
                type="security_group",
                name="WebSG",
                public=True,
            ),
        ],
        relationships=[],
    )
    G = build_graph(cfg)
    assert G.has_edge("vm-1", "sg-1")
    assert G["vm-1"]["sg-1"]["type"] == "connects_to"
