"""Deterministic attack-path discovery on the resource graph.

Walks from internet-facing entry points to high-value targets (databases,
admin roles, secrets) and builds AttackPath objects.
"""

from __future__ import annotations

import networkx as nx

from .models import AttackPath, AttackStep


# High-value target heuristics
_TARGET_TYPES = {"RDS", "S3Bucket"}
_ADMIN_POLICY_KEYWORDS = {"admin", "full-access"}


def _is_high_value(node_id: str, data: dict) -> bool:
    """Return True if a node is a high-value target."""
    if data.get("resource_type") in _TARGET_TYPES:
        return True
    # IAM roles with admin-level policies
    if data.get("resource_type") == "IAMRole":
        policies = data.get("properties", {}).get("policies", [])
        for p in policies:
            if any(kw in p.lower() for kw in _ADMIN_POLICY_KEYWORDS):
                return True
    # Lambda with hardcoded secrets
    if data.get("resource_type") == "Lambda":
        if data.get("finding_count", 0) > 0:
            return True
    return False


def _has_findings(data: dict) -> bool:
    return data.get("finding_count", 0) > 0


def find_attack_paths(G: nx.DiGraph, max_paths: int = 20) -> list[AttackPath]:
    """Find attack paths from INTERNET to high-value targets.

    Uses BFS/DFS from the INTERNET node through the *undirected* view of the
    graph (attacker can traverse any relationship direction).

    Args:
        G: The resource graph built by graph_builder.
        max_paths: Cap on how many paths to return.

    Returns:
        A list of AttackPath objects sorted by risk score descending.
    """
    if "INTERNET" not in G:
        return []

    # Build undirected view for traversal (attacker ignores edge direction)
    U = G.to_undirected()

    # Identify targets
    targets: list[str] = []
    for nid, data in G.nodes(data=True):
        if nid == "INTERNET":
            continue
        if _is_high_value(nid, data):
            targets.append(nid)

    # Find simple paths from INTERNET to each target
    raw_paths: list[list[str]] = []
    for target in targets:
        try:
            for path in nx.all_simple_paths(U, "INTERNET", target, cutoff=8):
                if len(path) >= 3:  # at least INTERNET → entry → target
                    raw_paths.append(path)
                    if len(raw_paths) >= max_paths * 3:
                        break
        except nx.NetworkXError:
            continue

    # Deduplicate and score
    seen: set[tuple[str, ...]] = set()
    attack_paths: list[AttackPath] = []
    for i, path_nodes in enumerate(raw_paths):
        key = tuple(path_nodes)
        if key in seen:
            continue
        seen.add(key)

        steps: list[AttackStep] = []
        for nid in path_nodes:
            if nid == "INTERNET":
                continue
            data = G.nodes[nid]
            technique = _infer_technique(nid, data, G)
            steps.append(AttackStep(
                resource_id=nid,
                resource_name=data.get("label", nid),
                resource_type=data.get("resource_type", "Unknown"),
                technique=technique,
            ))

        score = _score_path(steps, G)
        desc = _describe_path(steps)
        attack_paths.append(AttackPath(
            id=f"PATH-{len(attack_paths)+1:03d}",
            description=desc,
            steps=steps,
            risk_score=round(score, 1),
        ))

    # Sort by risk descending, limit
    attack_paths.sort(key=lambda p: p.risk_score, reverse=True)
    return attack_paths[:max_paths]


def _infer_technique(node_id: str, data: dict, G: nx.DiGraph) -> str:
    """Infer the attack technique used at this step."""
    rtype = data.get("type") or data.get("resource_type", "")
    rtype_low = rtype.lower()
    findings = data.get("findings", [])
    finding_titles = [f if isinstance(f, str) else f.get("title", "") for f in findings]
    finding_text = " ".join(str(t) for t in finding_titles).lower()

    if rtype_low in ("ec2",):
        if "ssh" in finding_text or "open_security_group_ingress" in finding_text:
            return "Exploit open SSH access"
        if data.get("public") or data.get("properties", {}).get("public_ip"):
            return "Access via public IP"
        return "Lateral movement to EC2"
    if rtype_low in ("iam_role", "iamrole"):
        if "admin" in finding_text or "permissive" in finding_text or "wildcard" in finding_text:
            return "Abuse overly permissive role"
        return "Assume IAM role"
    if rtype_low in ("security_group", "securitygroup"):
        return "Traverse permissive security group"
    if rtype_low in ("subnet",):
        if data.get("public") or data.get("properties", {}).get("public"):
            return "Move through public subnet"
        return "Move through private subnet"
    if rtype_low in ("rds",):
        if "public" in finding_text or data.get("public") or data.get("properties", {}).get("publicly_accessible"):
            return "Access publicly exposed database"
        return "Reach database instance"
    if rtype_low in ("s3", "s3bucket"):
        if "public" in finding_text or data.get("public") or data.get("properties", {}).get("public_access"):
            return "Access public S3 bucket"
        return "Access S3 bucket via assumed role"
    if rtype_low in ("lambda",):
        if "secret" in finding_text or "hardcoded" in finding_text:
            return "Extract hardcoded secrets from Lambda"
        return "Invoke Lambda function"
    if rtype_low in ("vpc",):
        return "Traverse VPC network"
    return "Access resource"


def _score_path(steps: list[AttackStep], G: nx.DiGraph) -> float:
    """Compute a risk score (0-10) for an attack path.

    Factors: path length (shorter = riskier), severity of findings along
    the path, and whether targets are critical resources.
    """
    if not steps:
        return 0.0

    severity_weights = {"CRITICAL": 3.0, "HIGH": 2.0, "MEDIUM": 1.0, "LOW": 0.5, "INFO": 0.1}
    total_severity = 0.0
    finding_count = 0

    for step in steps:
        data = G.nodes.get(step.resource_id, {})
        finding_objs = data.get("finding_objects")
        if finding_objs:
            for f in finding_objs:
                sev = f.get("severity", "INFO")
                total_severity += severity_weights.get(sev, 0.1)
                finding_count += 1
        else:
            for rule in data.get("findings", []):
                total_severity += 2.0
                finding_count += 1

    # Base score from findings
    base = min(total_severity, 10.0)

    # Shorter paths are more dangerous (easier to exploit)
    length_bonus = max(0, 3 - len(steps)) * 0.5

    # Bonus if path has many findings
    density_bonus = min(finding_count * 0.3, 2.0)

    score = min(base + length_bonus + density_bonus, 10.0)
    return max(score, 1.0)  # at least 1.0 if path exists


def _describe_path(steps: list[AttackStep]) -> str:
    """Generate a human-readable one-liner for the path."""
    if len(steps) < 2:
        return f"Direct access to {steps[0].resource_name}" if steps else "Empty path"
    return f"Internet → {steps[0].resource_name} → … → {steps[-1].resource_name}"
