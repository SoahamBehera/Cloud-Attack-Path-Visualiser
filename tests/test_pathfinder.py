"""Tests for graph builder and attack pathfinder."""

import networkx as nx

from src.detectors import run_all_detectors
from src.graph_builder import build_graph
from src.models import CloudConfig
from src.pathfinder import find_attack_paths


def test_graph_has_nodes(sample_config: CloudConfig):
    findings = run_all_detectors(sample_config.resources)
    G = build_graph(sample_config.resources, findings)
    # resources + INTERNET node
    assert len(G.nodes) == len(sample_config.resources) + 1
    assert "INTERNET" in G.nodes


def test_graph_has_edges(sample_config: CloudConfig):
    findings = run_all_detectors(sample_config.resources)
    G = build_graph(sample_config.resources, findings)
    assert len(G.edges) > 0


def test_internet_reaches_public_ec2(sample_config: CloudConfig):
    findings = run_all_detectors(sample_config.resources)
    G = build_graph(sample_config.resources, findings)
    # Web server has public IP → INTERNET should reach it
    assert G.has_edge("INTERNET", "i-webserver01")


def test_findings_attached_to_nodes(sample_config: CloudConfig):
    findings = run_all_detectors(sample_config.resources)
    G = build_graph(sample_config.resources, findings)
    total_attached = sum(d.get("finding_count", 0) for _, d in G.nodes(data=True))
    assert total_attached == len(findings)


def test_find_attack_paths(sample_config: CloudConfig):
    findings = run_all_detectors(sample_config.resources)
    G = build_graph(sample_config.resources, findings)
    paths = find_attack_paths(G)
    assert len(paths) > 0
    # Paths should be sorted by risk descending
    scores = [p.risk_score for p in paths]
    assert scores == sorted(scores, reverse=True)


def test_attack_paths_have_steps(sample_config: CloudConfig):
    findings = run_all_detectors(sample_config.resources)
    G = build_graph(sample_config.resources, findings)
    paths = find_attack_paths(G)
    for p in paths:
        assert len(p.steps) >= 2  # at least entry + target
        assert p.risk_score >= 1.0
        assert p.risk_score <= 10.0


def test_empty_config_no_paths():
    from src.models import CloudResource

    G = build_graph([], [])
    paths = find_attack_paths(G)
    assert len(paths) == 0
