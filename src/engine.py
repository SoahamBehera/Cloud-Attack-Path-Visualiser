"""High-level engine that orchestrates parsing → detection → graph → paths → scoring."""

from __future__ import annotations

from pathlib import Path
from typing import Union

import networkx as nx

from .detectors import run_all_detectors
from .explainer import explain_report
from .graph_builder import build_graph
from .models import AnalysisReport, CloudConfig
from .parser import parse_config
from .pathfinder import find_attack_paths
from .risk_scorer import compute_risk_summary


def analyze(source: Union[str, Path, dict]) -> tuple[AnalysisReport, nx.DiGraph]:
    """Run the full analysis pipeline.

    Args:
        source: File path, JSON string, or dict of the simulated config.

    Returns:
        A tuple of (AnalysisReport, networkx DiGraph).
    """
    config: CloudConfig = parse_config(source)
    findings = run_all_detectors(config.resources)
    graph = build_graph(config.resources, findings, config.relationships)
    attack_paths = find_attack_paths(graph)
    risk_summary = compute_risk_summary(findings, attack_paths)

    report = AnalysisReport(
        config=config,
        config_metadata=config.metadata,
        resources_count=len(config.resources),
        findings=findings,
        paths=attack_paths,
        attack_paths=attack_paths,
        summary=risk_summary,
        risk_summary=risk_summary,
    )
    return report, graph


def get_explanation(report: AnalysisReport) -> str:
    """Get an AI or template explanation for a report."""
    return explain_report(report)
