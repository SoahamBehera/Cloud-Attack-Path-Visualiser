"""Risk scoring engine for evaluated attack paths."""

from __future__ import annotations

import networkx as nx

SENSITIVE_PORTS = {22, 3389, 3306, 5432}
DATA_ACCESS_PERMS = {"s3:getobject", "can_read", "can_write"}


def score_path(graph: nx.DiGraph, path: list[str]) -> tuple[int, str, list[str]]:
    """Score an attack path using an additive risk model capped at 100.

    Additive model:
        +30 public entry point
        +15 if any security group on/near the path is open to 0.0.0.0/0 on ports 22/3389/3306/5432
        +25 if any IAM role on the path has wildcard/admin permissions
        +15 if the path includes a data-access permission (s3:GetObject, can_read, can_write)
        +30 if target is sensitive
        +20 if target sensitive AND public
        -3  per hop beyond 3

    Severity classification:
        >= 80: CRITICAL
        60-79: HIGH
        35-59: MEDIUM
        < 35:  LOW

    Args:
        graph: Directed NetworkX graph containing node and edge metadata.
        path: Ordered list of node IDs forming the attack chain.

    Returns:
        tuple of (score: int, severity: str, reasons: list[str])
    """
    if not path:
        return 0, "LOW", ["Empty attack path"]

    score = 0
    reasons: list[str] = []

    # ── 1. Public Entry Point (+30) ─────────────────────────────────
    # If path starts at 'internet', the cloud entry point is the first hopped resource
    entry_node_id = (
        path[1]
        if (len(path) > 1 and graph.nodes.get(path[0], {}).get("type") == "internet")
        else path[0]
    )
    entry_data = graph.nodes.get(entry_node_id, {})
    if bool(entry_data.get("public")):
        score += 30
        reasons.append("+30: Public entry point into cloud environment")

    # ── 2. Open Security Group on or near path (+15) ────────────────
    if _has_open_sg_on_or_near_path(graph, path):
        score += 15
        reasons.append("+15: Security group on/attached to path allows 0.0.0.0/0 on sensitive port (22/3389/3306/5432)")

    # ── 3. Wildcard / Admin IAM Role (+25) ───────────────────────────
    if _has_wildcard_iam_role(graph, path):
        score += 25
        reasons.append("+25: IAM role on path has wildcard or administrator permissions")

    # ── 4. Data-Access Permission on Path (+15) ─────────────────────
    if _has_data_access_permission(graph, path):
        score += 15
        reasons.append("+15: Path includes data-access permissions (s3:GetObject, can_read, can_write)")

    # ── 5. Sensitive Target (+30) ───────────────────────────────────
    target_id = path[-1]
    target_data = graph.nodes.get(target_id, {})
    is_sensitive = bool(target_data.get("sensitive")) or target_data.get("type") in {"rds", "secret"}
    if is_sensitive:
        score += 30
        reasons.append("+30: Target asset is marked sensitive")

    # ── 6. Target Sensitive AND Public (+20) ────────────────────────
    if is_sensitive and bool(target_data.get("public")):
        score += 20
        reasons.append("+20: Target asset is both sensitive and directly public")

    # ── 7. Hop Penalty (-3 per hop beyond 3) ────────────────────────
    hops = len(path) - 1
    if hops > 3:
        penalty = (hops - 3) * 3
        score -= penalty
        reasons.append(f"-{penalty}: Hop penalty for path length ({hops} hops, 3 allowed without penalty)")

    # Capping at 100 (and floor at 0)
    score = max(0, min(score, 100))

    # Severity classification
    if score >= 80:
        severity = "CRITICAL"
    elif score >= 60:
        severity = "HIGH"
    elif score >= 35:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return score, severity, reasons


def _has_open_sg_on_or_near_path(graph: nx.DiGraph, path: list[str]) -> bool:
    """Check if any security group on or connected to the path allows 0.0.0.0/0 on sensitive ports."""
    candidate_sgs: set[str] = set()

    for nid in path:
        data = graph.nodes.get(nid, {})
        if data.get("type") == "security_group":
            candidate_sgs.add(nid)
        # Check attached security groups (via connects_to / protected_by or properties)
        props = data.get("properties") or {}
        sg_prop = props.get("security_group") or props.get("security_groups")
        if sg_prop:
            if isinstance(sg_prop, str):
                candidate_sgs.add(sg_prop)
            elif isinstance(sg_prop, list):
                candidate_sgs.update(sg_prop)
        # Check adjacent nodes in graph
        for neighbor in list(graph.predecessors(nid)) + list(graph.successors(nid)):
            if graph.nodes.get(neighbor, {}).get("type") == "security_group":
                candidate_sgs.add(neighbor)

    for sg_id in candidate_sgs:
        sg_data = graph.nodes.get(sg_id, {})
        props = sg_data.get("properties") or {}
        rules = props.get("inbound_rules") or props.get("ingress") or []
        for r in rules:
            if not isinstance(r, dict):
                continue
            src = str(r.get("source") or r.get("cidr") or r.get("cidr_ip") or "")
            if src == "0.0.0.0/0":
                port = r.get("port") or r.get("from_port") or -1
                if port in SENSITIVE_PORTS or port == -1:
                    return True
    return False


def _has_wildcard_iam_role(graph: nx.DiGraph, path: list[str]) -> bool:
    """Check if any IAM role along the path has admin or wildcard permissions."""
    for nid in path:
        data = graph.nodes.get(nid, {})
        if data.get("type") in ("iam_role", "iamrole"):
            perms = data.get("permissions") or []
            if any(p == "*" or str(p).endswith(":*") or ":*" in str(p) for p in perms):
                return True
            findings = data.get("findings") or []
            if "admin_role" in findings or "iam_wildcard_permissions" in findings:
                return True
    return False


def _has_data_access_permission(graph: nx.DiGraph, path: list[str]) -> bool:
    """Check if the path includes data-access operations (s3:GetObject, can_read, can_write)."""
    # Check edges along the path
    for i in range(len(path) - 1):
        u, v = path[i], path[i + 1]
        edge_data = graph.get_edge_data(u, v) or {}
        rel_type = str(edge_data.get("type") or edge_data.get("relation") or "").lower()
        if rel_type in DATA_ACCESS_PERMS or "s3:getobject" in rel_type:
            return True

    # Check node permissions on path
    for nid in path:
        data = graph.nodes.get(nid, {})
        perms = data.get("permissions") or []
        for p in perms:
            p_low = str(p).lower()
            if p_low in DATA_ACCESS_PERMS or "s3:getobject" in p_low:
                return True
    return False
