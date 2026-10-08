"""Pydantic models for cloud resources, relationships, findings, attack paths, and analysis results."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal
from pydantic import BaseModel, Field, field_validator, model_validator


# ── Allowed Type Constants ──────────────────────────────────────────

VALID_RESOURCE_TYPES: set[str] = {
    "internet",
    "ec2",
    "s3",
    "iam_user",
    "iam_role",
    "security_group",
    "rds",
    "secret",
}

VALID_RELATIONSHIP_TYPES: set[str] = {
    "exposes",
    "assumes",
    "can_read",
    "can_write",
    "connects_to",
    "trusts",
    "has_permission",
}

# Mapping to accept legacy resource types smoothly if encountered
LEGACY_RESOURCE_TYPE_MAP: dict[str, str] = {
    "s3bucket": "S3Bucket",
    "securitygroup": "SecurityGroup",
    "iamrole": "IAMRole",
    "iamuser": "iam_user",
    "lambda": "Lambda",
    "internetgateway": "InternetGateway",
    "vpc": "VPC",
    "subnet": "Subnet",
}

ResourceType = Literal[
    "internet",
    "ec2",
    "s3",
    "iam_user",
    "iam_role",
    "security_group",
    "rds",
    "secret",
]

RelationshipType = Literal[
    "exposes",
    "assumes",
    "can_read",
    "can_write",
    "connects_to",
    "trusts",
    "has_permission",
]


# ── Resource & Relationship Models ──────────────────────────────────


class Resource(BaseModel):
    """A cloud infrastructure resource in a scenario."""

    id: str
    type: str
    name: str
    public: bool = False
    sensitive: bool = False
    properties: dict[str, Any] = Field(default_factory=dict)

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        low = v.lower()
        if low in VALID_RESOURCE_TYPES:
            if v in {"EC2", "RDS"}:
                return v
            return low
        if low in LEGACY_RESOURCE_TYPE_MAP:
            return LEGACY_RESOURCE_TYPE_MAP[low]
        raise ValueError(
            f"Invalid resource type '{v}'. Allowed types are: {sorted(VALID_RESOURCE_TYPES)}"
        )


class Relationship(BaseModel):
    """A directed relationship from a source resource to a target resource."""

    source: str
    target: str
    type: str

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        low = v.lower()
        if low not in VALID_RELATIONSHIP_TYPES:
            raise ValueError(
                f"Invalid relationship type '{v}'. Allowed types are: {sorted(VALID_RELATIONSHIP_TYPES)}"
            )
        return low


class CloudConfig(BaseModel):
    """Scenario configuration representing resources and relationships."""

    scenario_name: str = "default"
    resources: list[Resource] = Field(default_factory=list)
    relationships: list[Relationship] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_scenario_integrity(self) -> CloudConfig:
        seen_ids: set[str] = set()
        for res in self.resources:
            if res.id in seen_ids:
                raise ValueError(f"Duplicate resource id '{res.id}' found in scenario resources")
            seen_ids.add(res.id)

        for rel in self.relationships:
            if rel.source not in seen_ids:
                raise ValueError(
                    f"Relationship source '{rel.source}' does not exist in resources"
                )
            if rel.target not in seen_ids:
                raise ValueError(
                    f"Relationship target '{rel.target}' does not exist in resources"
                )

        return self


# ── Finding & Attack Path Models ────────────────────────────────────


class Finding(BaseModel):
    """A detected security misconfiguration finding."""

    id: str
    rule: str = ""
    resource_id: str
    severity: str = "INFO"
    description: str = ""
    recommendation: str = ""

    # Optional metadata fields for interoperability
    resource_name: str = ""
    title: str = ""
    category: str = ""


class AttackStep(BaseModel):
    """One hop in an attack path sequence."""

    resource_id: str
    resource_name: str = ""
    resource_type: str = ""
    technique: str = ""


class AttackPath(BaseModel):
    """An discovered attack path through the cloud graph."""

    nodes: list[str] = Field(default_factory=list)
    edges: list[str] = Field(default_factory=list)
    score: int = 0
    severity: str = "INFO"
    reasons: list[str] = Field(default_factory=list)

    # Optional legacy attributes for backwards-compatible consumers
    id: str = ""
    description: str = ""
    steps: list[AttackStep] = Field(default_factory=list)
    risk_score: float = 0.0


class AnalysisResult(BaseModel):
    """Aggregate result of cloud attack path analysis."""

    config: CloudConfig = Field(default_factory=CloudConfig)
    findings: list[Finding] = Field(default_factory=list)
    paths: list[AttackPath] = Field(default_factory=list)
    summary: dict[str, Any] = Field(default_factory=dict)

    # Optional legacy attributes for backward compatibility
    config_metadata: dict[str, Any] = Field(default_factory=dict)
    resources_count: int = 0
    attack_paths: list[AttackPath] = Field(default_factory=list)
    risk_summary: dict[str, Any] = Field(default_factory=dict)
    report: Any = None
    explanation: str = ""


# ── Compatibility Aliases ───────────────────────────────────────────


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


CloudResource = Resource
AnalysisReport = AnalysisResult
