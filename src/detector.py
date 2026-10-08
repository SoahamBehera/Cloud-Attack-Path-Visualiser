"""Deterministic security detector for CloudConfig scenarios."""

from __future__ import annotations

from typing import Any

from .models import CloudConfig, Finding, Resource


HIGH_RISK_PORTS = {22, 3389, 3306, 5432}
STORAGE_TYPES = {"s3", "rds"}


def detect(config: CloudConfig) -> list[Finding]:
    """Analyze a CloudConfig scenario and return a list of security findings.

    Rules evaluated:
    - public EC2 (HIGH, recommendation: block public access)
    - public S3 (HIGH / CRITICAL if sensitive, recommendation: block public access)
    - security group ingress from 0.0.0.0/0 (HIGH on ports 22/3389/3306/5432, else MEDIUM, recommendation: restrict CIDR)
    - IAM wildcard permissions ("*" or "service:*") as HIGH (recommendation: least privilege)
    - admin role (permissions contain "*") as CRITICAL (recommendation: least privilege)
    - sensitive storage without encryption as MEDIUM (recommendation: enable encryption)

    Args:
        config: Validated CloudConfig instance.

    Returns:
        List of detected Finding objects.
    """
    findings: list[Finding] = []
    counter = 0

    def next_id() -> str:
        nonlocal counter
        counter += 1
        return f"FIND-{counter:04d}"

    for res in config.resources:
        rtype = res.type.lower()
        props = res.properties or {}

        # ── 1. Public EC2 ───────────────────────────────────────────
        if rtype == "ec2":
            is_public = res.public or bool(props.get("public_ip"))
            if is_public:
                findings.append(Finding(
                    id=next_id(),
                    rule="public_ec2",
                    resource_id=res.id,
                    severity="HIGH",
                    description=f"EC2 instance '{res.name}' is publicly accessible from the internet.",
                    recommendation="block public access",
                    resource_name=res.name,
                    title="Public EC2 instance exposed",
                    category="Compute",
                ))

        # ── 2. Public S3 ────────────────────────────────────────────
        if rtype == "s3":
            is_public = (
                res.public
                or props.get("public_access") is True
                or props.get("block_public_access") is False
                or "public" in str(props.get("acl", "")).lower()
            )
            if is_public:
                sev = "CRITICAL" if res.sensitive else "HIGH"
                findings.append(Finding(
                    id=next_id(),
                    rule="public_s3",
                    resource_id=res.id,
                    severity=sev,
                    description=f"S3 bucket '{res.name}' is publicly accessible.",
                    recommendation="block public access",
                    resource_name=res.name,
                    title="Public S3 bucket",
                    category="Storage",
                ))

        # ── 3. Security Group Ingress from 0.0.0.0/0 ─────────────────
        if rtype == "security_group":
            rules = props.get("inbound_rules") or props.get("ingress") or []
            for r in rules:
                if not isinstance(r, dict):
                    continue
                source = str(r.get("source") or r.get("cidr") or r.get("cidr_ip") or "")
                if source == "0.0.0.0/0":
                    port = r.get("port") or r.get("from_port") or -1
                    is_high = port in HIGH_RISK_PORTS or port == -1
                    sev = "HIGH" if is_high else "MEDIUM"
                    port_str = f"port {port}" if port != -1 else "all ports"
                    findings.append(Finding(
                        id=next_id(),
                        rule="open_security_group_ingress",
                        resource_id=res.id,
                        severity=sev,
                        description=f"Security group '{res.name}' permits ingress traffic from 0.0.0.0/0 on {port_str}.",
                        recommendation="restrict CIDR",
                        resource_name=res.name,
                        title=f"Open security group ingress on {port_str}",
                        category="Network",
                    ))

        # ── 4 & 5. IAM Wildcard Permissions & Admin Role ─────────────
        if rtype in ("iam_role", "iam_user"):
            perms = _extract_permissions(props)

            # Admin role check (permissions contain "*")
            has_star = any(p == "*" for p in perms)
            if rtype == "iam_role" and has_star:
                findings.append(Finding(
                    id=next_id(),
                    rule="admin_role",
                    resource_id=res.id,
                    severity="CRITICAL",
                    description=f"IAM role '{res.name}' has administrator access with wildcard '*' permissions.",
                    recommendation="least privilege",
                    resource_name=res.name,
                    title="Admin IAM role with wildcard permissions",
                    category="IAM",
                ))

            # IAM wildcard permissions ("*" or "service:*")
            has_wildcard = any(_is_wildcard_permission(p) for p in perms)
            if has_wildcard:
                findings.append(Finding(
                    id=next_id(),
                    rule="iam_wildcard_permissions",
                    resource_id=res.id,
                    severity="HIGH",
                    description=f"IAM resource '{res.name}' grants overly permissive wildcard actions.",
                    recommendation="least privilege",
                    resource_name=res.name,
                    title="IAM wildcard permissions granted",
                    category="IAM",
                ))

        # ── 6. Sensitive Storage without Encryption ──────────────────
        if res.sensitive and rtype in STORAGE_TYPES:
            if not _is_encrypted(props):
                findings.append(Finding(
                    id=next_id(),
                    rule="unencrypted_sensitive_storage",
                    resource_id=res.id,
                    severity="MEDIUM",
                    description=f"Sensitive {rtype.upper()} resource '{res.name}' does not have encryption at rest enabled.",
                    recommendation="enable encryption",
                    resource_name=res.name,
                    title=f"Unencrypted sensitive {rtype.upper()}",
                    category="Storage",
                ))

    return findings


def _extract_permissions(props: dict[str, Any]) -> list[str]:
    """Collect all permission and policy strings from resource properties."""
    perms: list[str] = []
    if isinstance(props.get("policies"), list):
        perms.extend(str(p) for p in props["policies"])
    if isinstance(props.get("permissions"), list):
        perms.extend(str(p) for p in props["permissions"])
    for stmt in props.get("statement", []):
        if isinstance(stmt, dict):
            action = stmt.get("Action", [])
            if isinstance(action, str):
                perms.append(action)
            elif isinstance(action, list):
                perms.extend(str(a) for a in action)
    return perms


def _is_wildcard_permission(perm: str) -> bool:
    """Check if permission is a wildcard ('*' or 'service:*')."""
    clean = perm.strip()
    if clean == "*":
        return True
    if clean.endswith(":*") or ":*" in clean:
        return True
    if clean.lower() == "administratoraccess":
        return True
    return False


def _is_encrypted(props: dict[str, Any]) -> bool:
    """Check if resource properties indicate encryption is enabled."""
    if props.get("encrypted") is True:
        return True
    enc = props.get("encryption")
    if enc is not None:
        enc_str = str(enc).strip().lower()
        if enc_str and enc_str not in ("none", "false", "disabled"):
            return True
    return False
