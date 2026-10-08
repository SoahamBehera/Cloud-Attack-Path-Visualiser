"""AI-powered security analyst module for explaining attack paths.

Uses the OpenAI Python SDK to provide structured, plain-English explanations
of deterministic attack paths. Falls back cleanly to a deterministic
template if no API key is provided or if network/API calls fail.
"""

from __future__ import annotations

import json
import os
from typing import Any
import networkx as nx

from .models import AnalysisResult, AttackPath, Finding


def _get_api_key() -> str | None:
    """Safely retrieve the OpenAI API key from environment variables or Streamlit secrets."""
    # 1. Check environment variable
    key = os.environ.get("OPENAI_API_KEY", "").strip()
    if key and not key.startswith("sk-..."):
        return key

    # 2. Check Streamlit secrets safely without throwing errors
    try:
        import streamlit as st

        if hasattr(st, "secrets") and "OPENAI_API_KEY" in st.secrets:
            s_key = str(st.secrets["OPENAI_API_KEY"]).strip()
            if s_key and not s_key.startswith("sk-..."):
                return s_key
    except Exception:
        pass

    return None


get_openai_api_key = _get_api_key


def explain_path(
    path_result: AttackPath | dict[str, Any] | list[str],
    graph_context: nx.DiGraph | AnalysisResult | dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate structured explanations for a discovered attack path.

    Returns a dictionary with the following keys:
        - executive_summary (str): Brief high-level summary for leadership
        - summary (str): Clear walkthrough of the attack chain progression
        - why_it_exists (str): Root cause misconfigurations and permissions
        - impact (str): Potential business and technical fallout
        - remediation (list[str]): Actionable, prioritized steps to break path
        - source (str): 'openai' if generated via LLM, else 'fallback'

    Args:
        path_result: AttackPath instance, dict, or list of node IDs.
        graph_context: Optional NetworkX DiGraph or AnalysisResult containing
            node/edge metadata and findings.

    Returns:
        dict[str, Any] with all required explanation sections and source flag.
    """
    # 1. Normalize path_result inputs
    if isinstance(path_result, AttackPath):
        nodes = list(path_result.nodes)
        edges = list(path_result.edges)
        score = int(path_result.score)
        severity = str(path_result.severity)
        reasons = list(path_result.reasons)
    elif isinstance(path_result, dict):
        nodes = list(path_result.get("nodes", []))
        edges = list(path_result.get("edges", []))
        score = int(path_result.get("score", 0))
        severity = str(path_result.get("severity", "LOW"))
        reasons = list(path_result.get("reasons", []))
    elif isinstance(path_result, (list, tuple)):
        nodes = list(path_result)
        edges = []
        score = 0
        severity = "LOW"
        reasons = []
    else:
        nodes = []
        edges = []
        score = 0
        severity = "LOW"
        reasons = []

    # 2. Extract node metadata and relevant findings from graph_context
    node_details: dict[str, dict[str, Any]] = {}
    path_findings: list[dict[str, Any]] = []

    if isinstance(graph_context, nx.DiGraph):
        for nid in nodes:
            ndata = graph_context.nodes.get(nid, {})
            node_details[nid] = {
                "name": ndata.get("name", nid),
                "type": ndata.get("type") or ndata.get("resource_type") or "resource",
                "public": bool(ndata.get("public")),
                "sensitive": bool(ndata.get("sensitive")),
                "permissions": ndata.get("permissions") or [],
            }
            for f in ndata.get("finding_objects") or []:
                if isinstance(f, dict):
                    path_findings.append(f)
    elif isinstance(graph_context, AnalysisResult):
        for nid in nodes:
            res_obj = next((r for r in graph_context.config.resources if r.id == nid), None)
            if res_obj:
                node_details[nid] = {
                    "name": res_obj.name,
                    "type": res_obj.type,
                    "public": res_obj.public,
                    "sensitive": res_obj.sensitive,
                    "properties": res_obj.properties,
                }
        for f in graph_context.findings:
            if f.resource_id in nodes:
                path_findings.append(f.model_dump())

    # 3. Check for API key
    api_key = _get_api_key()
    if not api_key:
        return _build_fallback_explanation(
            nodes=nodes,
            edges=edges,
            score=score,
            severity=severity,
            reasons=reasons,
            node_details=node_details,
            path_findings=path_findings,
        )

    # 4. Attempt OpenAI call
    try:
        from openai import OpenAI

        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        client = OpenAI(api_key=api_key, timeout=20.0)

        system_prompt = (
            "You are a cloud security analyst. Explain ONLY the provided deterministic findings. "
            "Do not invent resources or vulnerabilities. Use cautious wording such as 'could potentially'. "
            "Output must be strictly valid JSON."
        )

        user_content = {
            "path_chain": nodes,
            "relationships": edges,
            "risk_score": score,
            "severity": severity,
            "evaluated_reasons": reasons,
            "node_metadata": node_details,
            "findings_along_path": [
                {
                    "rule": f.get("rule", ""),
                    "resource": f.get("resource_id", ""),
                    "description": f.get("description", ""),
                    "recommendation": f.get("recommendation", ""),
                }
                for f in path_findings
            ],
            "instructions": (
                "Provide a JSON object with keys: "
                "'executive_summary' (string), "
                "'summary' (string), "
                "'why_it_exists' (string), "
                "'impact' (string), "
                "'remediation' (array of strings)."
            ),
        }

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": json.dumps(user_content)},
            ],
            response_format={"type": "json_object"},
            temperature=0.2,
            timeout=20.0,
        )

        content = response.choices[0].message.content or "{}"
        parsed = json.loads(content)

        remediation_items = parsed.get("remediation")
        if isinstance(remediation_items, str):
            remediation_list = [remediation_items]
        elif isinstance(remediation_items, list):
            remediation_list = [str(item) for item in remediation_items]
        else:
            remediation_list = []

        # Validate that essential keys exist
        if not parsed.get("summary") or not parsed.get("why_it_exists"):
            raise ValueError("Incomplete JSON fields from OpenAI")

        return {
            "executive_summary": str(parsed.get("executive_summary") or "").strip(),
            "summary": str(parsed.get("summary") or "").strip(),
            "why_it_exists": str(parsed.get("why_it_exists") or "").strip(),
            "impact": str(parsed.get("impact") or "").strip(),
            "remediation": remediation_list,
            "source": "openai",
        }

    except Exception:
        # Fall back gracefully on network errors, invalid key, rate limits, or timeouts
        return _build_fallback_explanation(
            nodes=nodes,
            edges=edges,
            score=score,
            severity=severity,
            reasons=reasons,
            node_details=node_details,
            path_findings=path_findings,
        )


def _build_fallback_explanation(
    nodes: list[str],
    edges: list[str],
    score: int,
    severity: str,
    reasons: list[str],
    node_details: dict[str, dict[str, Any]],
    path_findings: list[dict[str, Any]],
) -> dict[str, Any]:
    """Construct a deterministic template-based explanation from path metadata."""
    if not nodes:
        return {
            "executive_summary": "No active attack paths identified in this scenario.",
            "summary": "No path discovered from entry points to sensitive cloud targets.",
            "why_it_exists": "Infrastructure isolation and security boundaries prevented path formation.",
            "impact": "No immediate external compromise path detected.",
            "remediation": ["Maintain current boundary controls and regular auditing."],
            "source": "fallback",
        }

    entry_node = nodes[0]
    target_node = nodes[-1]
    hop_count = max(0, len(nodes) - 1)
    chain_str = " ➔ ".join(nodes)

    # 1. Executive Summary
    exec_summary = (
        f"An attack path evaluated at {severity} severity (risk score: {score}/100) "
        f"could potentially allow an external attacker to traverse from '{entry_node}' "
        f"to sensitive asset '{target_node}' across {hop_count} hops."
    )

    # 2. Summary
    summary = (
        f"Discovered attack chain initiates at entry point '{entry_node}' and reaches "
        f"sensitive destination '{target_node}'. The full traversed sequence is: {chain_str}. "
        f"The additive risk model scored this chain at {score}/100 based on public exposure, "
        f"IAM permission boundaries, and high-value target assets."
    )

    # 3. Why It Exists
    why_lines = [
        "This attack path could potentially exist due to the following evaluated factors:"
    ]
    if reasons:
        for r in reasons:
            why_lines.append(f"• {r}")
    else:
        why_lines.append(f"• Permissive network and identity relationships linking {entry_node} to {target_node}")

    if path_findings:
        why_lines.append("\nDetected security findings on path resources:")
        for f in path_findings:
            f_rule = f.get("rule", "misconfiguration")
            f_sev = f.get("severity", "MEDIUM")
            f_res = f.get("resource_id", "")
            f_desc = f.get("description", "")
            why_lines.append(f"• [{f_sev}] {f_rule} on {f_res}: {f_desc}")

    why_it_exists = "\n".join(why_lines)

    # 4. Impact
    target_type = (
        node_details.get(target_node, {}).get("type", "sensitive resource")
        if node_details
        else "sensitive asset"
    )
    impact = (
        f"If traversed, an adversary could potentially compromise or exfiltrate data from "
        f"'{target_node}' ({target_type}). Any administrative role or open ingress along this chain "
        f"could potentially facilitate lateral movement and privilege escalation across the cloud environment."
    )

    # 5. Remediation Plan
    remediations: list[str] = []
    # Collect specific recommendations from path findings
    for f in path_findings:
        rec = f.get("recommendation")
        if rec and rec not in remediations:
            remediations.append(rec)

    # Add general best-practice remediations based on path traits
    if any("0.0.0.0/0" in r or "security group" in r.lower() for r in reasons):
        remediations.append(
            "Restrict security group ingress: remove 0.0.0.0/0 on sensitive ports (22, 3389, 3306, 5432) and require VPN/bastion access."
        )
    if any("wildcard" in r.lower() or "admin" in r.lower() for r in reasons):
        remediations.append(
            "Apply least-privilege IAM policies: eliminate wildcard actions ('*') and scope role policies to specific resource ARNs."
        )
    if any("public" in r.lower() for r in reasons):
        remediations.append(
            f"Review public exposure of entry point '{entry_node}' and place workload behind an API gateway or internal subnet."
        )

    if not remediations:
        remediations.append(
            "Enforce strict network segmentation between external tiers and internal data stores."
        )
        remediations.append(
            "Implement multi-layer defense with encryption at rest and least-privilege service roles."
        )

    return {
        "executive_summary": exec_summary,
        "summary": summary,
        "why_it_exists": why_it_exists,
        "impact": impact,
        "remediation": remediations,
        "source": "fallback",
    }
