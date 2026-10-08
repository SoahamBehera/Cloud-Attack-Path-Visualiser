"""Build a NetworkX graph from a CloudConfig scenario or resource list."""

from __future__ import annotations

from typing import Any, Union
import networkx as nx

from .detector import detect, _extract_permissions
from .models import CloudConfig, Finding, Resource


def build_graph(
    config_or_resources: Union[CloudConfig, list[Resource]],
    findings: list[Finding] | None = None,
    relationships: list[Any] | None = None,
) -> nx.DiGraph:
    """Create a directed NetworkX graph representing the cloud configuration.

    Node attributes:
        - type: Resource type string (e.g. 'ec2', 's3', 'internet')
        - name: Resource name string
        - public: Boolean indicating public internet exposure
        - sensitive: Boolean indicating sensitive asset
        - findings: List of rule names triggered on this resource
        - permissions: List of permissions/policies associated with this resource

    Edge attributes:
        - type: Relationship type string (e.g. 'exposes', 'assumes', 'connects_to')

    Also:
        - Adds an edge internet -> any resource with public=True of type "exposes" if missing.
        - Links ec2 -> its security_group via connects_to when properties.security_group is set.

    Args:
        config_or_resources: CloudConfig instance or list of Resources.
        findings: Optional precomputed list of Findings (auto-detected if None).
        relationships: Optional explicit list of Relationships for legacy callers.

    Returns:
        A networkx.DiGraph instance.
    """
    if isinstance(config_or_resources, CloudConfig):
        config = config_or_resources
    else:
        config = CloudConfig(
            resources=config_or_resources,
            relationships=relationships or [],
        )

    # Automatically compute findings using detector if not supplied
    if findings is None:
        findings = detect(config)

    # Index findings by resource ID: map resource_id -> list of rule names
    findings_by_res: dict[str, list[str]] = {}
    finding_objs_by_res: dict[str, list[dict[str, Any]]] = {}
    for f in findings:
        findings_by_res.setdefault(f.resource_id, []).append(f.rule)
        finding_objs_by_res.setdefault(f.resource_id, []).append(f.model_dump())

    G = nx.DiGraph()
    res_map: dict[str, Resource] = {r.id: r for r in config.resources}

    # ── 1. Add Nodes with required attributes ───────────────────────
    for r in config.resources:
        rule_names = findings_by_res.get(r.id, [])
        perms = _extract_permissions(r.properties or {})

        G.add_node(
            r.id,
            type=r.type,
            name=r.name,
            public=bool(r.public),
            sensitive=bool(r.sensitive),
            findings=rule_names,
            permissions=perms,
            # Additional metadata for visualization compatibility
            label=r.name,
            resource_type=r.type,
            properties=r.properties or {},
            finding_count=len(rule_names),
            finding_objects=finding_objs_by_res.get(r.id, []),
        )

    # ── 2. Add Explicit Relationships (Edge attribute: type) ────────
    for rel in config.relationships:
        G.add_edge(
            rel.source,
            rel.target,
            type=rel.type,
            relation=rel.type,
        )

    # ── 3. Link EC2 -> its security_group via connects_to ───────────
    for r in config.resources:
        if r.type.lower() == "ec2":
            props = r.properties or {}
            sg_val = props.get("security_group") or props.get("security_groups")
            if sg_val:
                sg_ids = [sg_val] if isinstance(sg_val, str) else list(sg_val)
                for sg_id in sg_ids:
                    if sg_id in res_map and not G.has_edge(r.id, sg_id):
                        G.add_edge(r.id, sg_id, type="connects_to", relation="connects_to")

    # ── 4. Add edge internet -> public=True resources (type="exposes")
    internet_res = next((r for r in config.resources if r.type.lower() == "internet"), None)
    if internet_res:
        internet_id = internet_res.id
        for r in config.resources:
            if r.id != internet_id and r.public:
                if not G.has_edge(internet_id, r.id):
                    G.add_edge(internet_id, r.id, type="exposes", relation="exposes")

    # ── 5. Backward compatibility for legacy AWS configs ────────────
    for r in config.resources:
        props = r.properties or {}
        if r.type == "InternetGateway":
            vpc_id = props.get("attached_vpc")
            if vpc_id and vpc_id in res_map and not G.has_edge(r.id, vpc_id):
                G.add_edge(r.id, vpc_id, type="attached_to", relation="attached_to")
        if r.type in ("Subnet", "SecurityGroup"):
            vpc_id = props.get("vpc_id")
            if vpc_id and vpc_id in res_map and not G.has_edge(r.id, vpc_id):
                G.add_edge(r.id, vpc_id, type="belongs_to", relation="belongs_to")
        if r.type in ("EC2", "RDS"):
            sub_id = props.get("subnet_id")
            if sub_id and sub_id in res_map and not G.has_edge(r.id, sub_id):
                G.add_edge(r.id, sub_id, type="deployed_in", relation="deployed_in")
            role_id = props.get("iam_role")
            if role_id and role_id in res_map and not G.has_edge(r.id, role_id):
                G.add_edge(r.id, role_id, type="assumes_role", relation="assumes_role")

    # Virtual INTERNET node for legacy pathfinder tests if needed
    if "INTERNET" not in G and internet_res:
        G.add_node(
            "INTERNET",
            label="Internet",
            name="Internet",
            type="External",
            resource_type="External",
            public=True,
            sensitive=False,
            findings=[],
            permissions=[],
            properties={},
            finding_count=0,
        )
        G.add_edge("INTERNET", internet_res.id, type="entry_point", relation="entry_point")
        for r in config.resources:
            if r.public and r.id != internet_res.id:
                G.add_edge("INTERNET", r.id, type="can_reach", relation="can_reach")
    elif "INTERNET" not in G:
        G.add_node(
            "INTERNET",
            label="Internet",
            name="Internet",
            type="External",
            resource_type="External",
            public=True,
            sensitive=False,
            findings=[],
            permissions=[],
            properties={},
            finding_count=0,
        )
        for r in config.resources:
            if r.public or (r.type == "EC2" and r.properties.get("public_ip")):
                G.add_edge("INTERNET", r.id, type="can_reach", relation="can_reach")

    return G
