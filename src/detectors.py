"""Deterministic security-misconfiguration detectors.

Each detector function receives the full list of CloudResources and returns
a list of Finding objects.  No LLM calls — pure rule-based logic.
"""

from __future__ import annotations

from .models import CloudResource, Finding, Severity

# ── Helpers ─────────────────────────────────────────────────────────

_counter = 0


def _next_id() -> str:
    global _counter
    _counter += 1
    return f"FIND-{_counter:04d}"


def reset_counter() -> None:
    """Reset the finding ID counter (useful in tests)."""
    global _counter
    _counter = 0


def _by_type(resources: list[CloudResource], rtype: str) -> list[CloudResource]:
    return [r for r in resources if r.type == rtype]


# ── Individual detectors ───────────────────────────────────────────


def detect_public_ssh(resources: list[CloudResource]) -> list[Finding]:
    """Flag security groups that allow SSH (port 22) from 0.0.0.0/0."""
    findings: list[Finding] = []
    for sg in _by_type(resources, "SecurityGroup"):
        for rule in sg.properties.get("inbound_rules", []):
            if rule.get("port") == 22 and rule.get("source") == "0.0.0.0/0":
                findings.append(Finding(
                    id=_next_id(),
                    resource_id=sg.id,
                    resource_name=sg.name,
                    title="SSH open to the internet",
                    description=f"Security group '{sg.name}' allows SSH (port 22) from 0.0.0.0/0.",
                    severity=Severity.CRITICAL,
                    category="Network",
                ))
    return findings


def detect_public_db_port(resources: list[CloudResource]) -> list[Finding]:
    """Flag security groups that expose database ports to 0.0.0.0/0."""
    db_ports = {3306, 5432, 1433, 1521, 27017, 6379}
    findings: list[Finding] = []
    for sg in _by_type(resources, "SecurityGroup"):
        for rule in sg.properties.get("inbound_rules", []):
            port = rule.get("port")
            if port in db_ports and rule.get("source") == "0.0.0.0/0":
                findings.append(Finding(
                    id=_next_id(),
                    resource_id=sg.id,
                    resource_name=sg.name,
                    title=f"Database port {port} open to the internet",
                    description=f"Security group '{sg.name}' exposes port {port} to 0.0.0.0/0.",
                    severity=Severity.CRITICAL,
                    category="Network",
                ))
    return findings


def detect_public_s3(resources: list[CloudResource]) -> list[Finding]:
    """Flag S3 buckets with public access enabled."""
    findings: list[Finding] = []
    for bucket in _by_type(resources, "S3Bucket"):
        if bucket.properties.get("public_access"):
            findings.append(Finding(
                id=_next_id(),
                resource_id=bucket.id,
                resource_name=bucket.name,
                title="S3 bucket is publicly accessible",
                description=f"Bucket '{bucket.name}' has public access enabled.",
                severity=Severity.HIGH,
                category="Storage",
            ))
    return findings


def detect_unencrypted_s3(resources: list[CloudResource]) -> list[Finding]:
    """Flag S3 buckets without encryption."""
    findings: list[Finding] = []
    for bucket in _by_type(resources, "S3Bucket"):
        enc = bucket.properties.get("encryption", "none")
        if enc.lower() == "none":
            findings.append(Finding(
                id=_next_id(),
                resource_id=bucket.id,
                resource_name=bucket.name,
                title="S3 bucket is not encrypted",
                description=f"Bucket '{bucket.name}' has no server-side encryption.",
                severity=Severity.MEDIUM,
                category="Storage",
            ))
    return findings


def detect_public_rds(resources: list[CloudResource]) -> list[Finding]:
    """Flag RDS instances that are publicly accessible."""
    findings: list[Finding] = []
    for rds in _by_type(resources, "RDS"):
        if rds.properties.get("publicly_accessible"):
            findings.append(Finding(
                id=_next_id(),
                resource_id=rds.id,
                resource_name=rds.name,
                title="RDS instance is publicly accessible",
                description=f"RDS '{rds.name}' is configured with publicly_accessible=true.",
                severity=Severity.CRITICAL,
                category="Database",
            ))
    return findings


def detect_unencrypted_rds(resources: list[CloudResource]) -> list[Finding]:
    """Flag RDS instances without encryption at rest."""
    findings: list[Finding] = []
    for rds in _by_type(resources, "RDS"):
        if not rds.properties.get("encrypted"):
            findings.append(Finding(
                id=_next_id(),
                resource_id=rds.id,
                resource_name=rds.name,
                title="RDS instance is not encrypted",
                description=f"RDS '{rds.name}' does not have encryption at rest enabled.",
                severity=Severity.HIGH,
                category="Database",
            ))
    return findings


def detect_overly_permissive_roles(resources: list[CloudResource]) -> list[Finding]:
    """Flag IAM roles that include admin / full-access policies."""
    findings: list[Finding] = []
    danger_keywords = {"admin", "full-access", "poweruser", "*"}
    for role in _by_type(resources, "IAMRole"):
        for policy in role.properties.get("policies", []):
            if any(kw in policy.lower() for kw in danger_keywords):
                findings.append(Finding(
                    id=_next_id(),
                    resource_id=role.id,
                    resource_name=role.name,
                    title="Overly permissive IAM role",
                    description=f"IAM role '{role.name}' has policy '{policy}' which is overly broad.",
                    severity=Severity.HIGH,
                    category="IAM",
                ))
    return findings


def detect_hardcoded_secrets(resources: list[CloudResource]) -> list[Finding]:
    """Flag Lambda functions with secrets in environment variables."""
    findings: list[Finding] = []
    secret_keys = {"password", "secret", "api_key", "token", "private_key"}
    for fn in _by_type(resources, "Lambda"):
        env_vars = fn.properties.get("env_variables", {})
        for key in env_vars:
            if any(s in key.lower() for s in secret_keys):
                findings.append(Finding(
                    id=_next_id(),
                    resource_id=fn.id,
                    resource_name=fn.name,
                    title="Hardcoded secret in Lambda environment",
                    description=f"Lambda '{fn.name}' has env var '{key}' that looks like a secret.",
                    severity=Severity.CRITICAL,
                    category="Secrets",
                ))
    return findings


def detect_ec2_public_ip_with_admin_role(resources: list[CloudResource]) -> list[Finding]:
    """Flag EC2 instances with public IPs that have admin-level IAM roles."""
    findings: list[Finding] = []
    role_map = {r.id: r for r in _by_type(resources, "IAMRole")}
    for ec2 in _by_type(resources, "EC2"):
        if not ec2.properties.get("public_ip"):
            continue
        role_id = ec2.properties.get("iam_role", "")
        role = role_map.get(role_id)
        if not role:
            continue
        for policy in role.properties.get("policies", []):
            if "admin" in policy.lower() or "full-access" in policy.lower():
                findings.append(Finding(
                    id=_next_id(),
                    resource_id=ec2.id,
                    resource_name=ec2.name,
                    title="Public EC2 with admin-level role",
                    description=(
                        f"EC2 '{ec2.name}' has a public IP and IAM role '{role.name}' "
                        f"with policy '{policy}'."
                    ),
                    severity=Severity.CRITICAL,
                    category="IAM",
                ))
    return findings


# ── Aggregate runner ───────────────────────────────────────────────

ALL_DETECTORS = [
    detect_public_ssh,
    detect_public_db_port,
    detect_public_s3,
    detect_unencrypted_s3,
    detect_public_rds,
    detect_unencrypted_rds,
    detect_overly_permissive_roles,
    detect_hardcoded_secrets,
    detect_ec2_public_ip_with_admin_role,
]


def run_all_detectors(resources: list[CloudResource]) -> list[Finding]:
    """Run every registered detector and return combined findings."""
    reset_counter()
    findings: list[Finding] = []
    for detector in ALL_DETECTORS:
        findings.extend(detector(resources))
    return findings
