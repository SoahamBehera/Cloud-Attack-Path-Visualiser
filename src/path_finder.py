"""Graph traversal module discovering attack paths from entry points to sensitive targets."""

from __future__ import annotations

import networkx as nx

SENSITIVE_TYPES = {"rds", "secret"}


def find_attack_paths(graph: nx.DiGraph) -> list[list[str]]:
    """Discover all simple attack paths from entry points to sensitive targets.

    Searches from entry points (nodes with type == 'internet' or id 'INTERNET')
    to sensitive targets (nodes with sensitive=True or type in {'rds', 'secret'})
    using networkx.all_simple_paths with cutoff=6.
    Deduplicates and sorts results.

    Args:
        graph: Directed NetworkX graph built by graph_builder.

    Returns:
        List of paths, where each path is an ordered list of node IDs.
    """
    if not graph or len(graph.nodes) == 0:
        return []

    # 1. Identify entry points (prefer scenario internet node if present)
    internet_nodes = [
        nid for nid, data in graph.nodes(data=True)
        if data.get("type") == "internet" or nid == "res-internet"
    ]
    if not internet_nodes and "INTERNET" in graph:
        internet_nodes = ["INTERNET"]

    if not internet_nodes:
        return []

    # 2. Identify sensitive target nodes (exclude entry points)
    targets: list[str] = [
        nid for nid, data in graph.nodes(data=True)
        if nid not in internet_nodes
        and (bool(data.get("sensitive")) or data.get("type") in SENSITIVE_TYPES)
    ]

    if not targets:
        return []

    # 3. Find simple paths with cutoff=6
    discovered: list[list[str]] = []
    for entry in internet_nodes:
        for target in targets:
            try:
                for path in nx.all_simple_paths(graph, entry, target, cutoff=6):
                    discovered.append(path)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                continue

    # 4. Deduplicate paths while preserving structure
    seen: set[tuple[str, ...]] = set()
    unique_paths: list[list[str]] = []
    for p in discovered:
        key = tuple(p)
        if key not in seen:
            seen.add(key)
            unique_paths.append(p)

    # 5. Sort paths (by length, then node-ids lexicographically)
    unique_paths.sort(key=lambda p: (len(p), p))
    return unique_paths
