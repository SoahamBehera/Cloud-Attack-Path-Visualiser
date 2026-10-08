"""Pipeline module orchestrating detection, graph construction, path discovery, and risk scoring."""

from __future__ import annotations

from .detector import detect
from .graph_builder import build_graph
from .models import AnalysisResult, AttackPath, CloudConfig
from .path_finder import find_attack_paths
from .risk import score_path


def run_analysis(config: CloudConfig) -> AnalysisResult:
    """Run full defensive security analysis on a CloudConfig scenario.

    Pipeline steps:
    1. Detect deterministic misconfigurations.
    2. Build graph with nodes, explicit/inferred edges, and attributes.
    3. Find all attack paths from entry points to sensitive targets.
    4. Score discovered paths using the additive risk model.
    5. Aggregate results into AnalysisResult sorted by risk score descending.

    Args:
        config: Validated CloudConfig instance.

    Returns:
        AnalysisResult containing findings, scored paths, and summary counts.
    """
    # 1. Detect security misconfigurations
    findings = detect(config)

    # 2. Build graph with node & edge attributes and annotated findings
    graph = build_graph(config)

    # 3. Discover attack paths to sensitive targets
    raw_paths = find_attack_paths(graph)

    # 4. Score each attack path
    scored_paths: list[AttackPath] = []
    for path in raw_paths:
        score, severity, reasons = score_path(graph, path)

        # Collect relationship types along edges
        edges: list[str] = []
        for i in range(len(path) - 1):
            u, v = path[i], path[i + 1]
            edge_data = graph.get_edge_data(u, v) or {}
            edges.append(str(edge_data.get("type", "connects_to")))

        scored_paths.append(AttackPath(
            nodes=path,
            edges=edges,
            score=score,
            severity=severity,
            reasons=reasons,
            # Legacy helper fields
            id=f"PATH-{len(scored_paths) + 1:03d}",
            risk_score=float(score) / 10.0,
            description=" → ".join(path),
        ))

    # Sort paths by risk score descending
    scored_paths.sort(key=lambda p: p.score, reverse=True)

    # 5. Build summary metrics
    summary = {
        "resources": len(config.resources),
        "findings": len(findings),
        "paths": len(scored_paths),
        "critical": sum(1 for p in scored_paths if p.severity == "CRITICAL")
        + sum(1 for f in findings if f.severity == "CRITICAL"),
        "high": sum(1 for p in scored_paths if p.severity == "HIGH")
        + sum(1 for f in findings if f.severity == "HIGH"),
        "medium": sum(1 for p in scored_paths if p.severity == "MEDIUM")
        + sum(1 for f in findings if f.severity == "MEDIUM"),
        "low": sum(1 for p in scored_paths if p.severity == "LOW")
        + sum(1 for f in findings if f.severity == "LOW"),
        "path_critical": sum(1 for p in scored_paths if p.severity == "CRITICAL"),
        "path_high": sum(1 for p in scored_paths if p.severity == "HIGH"),
        "path_medium": sum(1 for p in scored_paths if p.severity == "MEDIUM"),
        "path_low": sum(1 for p in scored_paths if p.severity == "LOW"),
    }

    return AnalysisResult(
        config=config,
        findings=findings,
        paths=scored_paths,
        summary=summary,
        # Legacy attributes
        resources_count=len(config.resources),
        attack_paths=scored_paths,
        risk_summary=summary,
    )
