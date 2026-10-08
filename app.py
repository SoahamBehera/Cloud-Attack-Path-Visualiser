"""Polished Streamlit dashboard for Cloud Attack Path Visualiser.

Provides interactive visualization of cloud attack paths, security findings,
and resource graph analysis.
"""

from __future__ import annotations

import json
from pathlib import Path
import sys
from typing import Any

import altair as alt
import networkx as nx
import pandas as pd
from pyvis.network import Network
import streamlit as st

# Ensure project root is in sys.path
_project_root = str(Path(__file__).resolve().parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

from src.ai_explainer import explain_path, get_openai_api_key
from src.graph_builder import build_graph
from src.loader import load_config
from src.models import AnalysisResult, AttackPath, CloudConfig, Finding, Resource
from src.pipeline import run_analysis
from src.report import build_markdown_report

# ── Page Configuration ────────────────────────────────────────────────
st.set_page_config(
    page_title="Cloud Attack Path Visualiser",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ── Custom CSS for Dark-Friendly Theme ────────────────────────────────
st.markdown(
    """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=JetBrains+Mono:wght@400;600&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

code, pre {
    font-family: 'JetBrains Mono', monospace !important;
}

/* Metric card styling */
div[data-testid="stMetric"] {
    background: linear-gradient(135deg, #111827 0%, #1e293b 100%);
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 12px;
    padding: 18px 22px;
    box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
    transition: transform 0.2s ease, border-color 0.2s ease;
}

div[data-testid="stMetric"]:hover {
    border-color: rgba(59, 130, 246, 0.5);
    transform: translateY(-2px);
}

div[data-testid="stMetric"] label {
    color: #94a3b8 !important;
    font-size: 0.85rem !important;
    font-weight: 600 !important;
    text-transform: uppercase;
    letter-spacing: 0.6px;
}

div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    font-size: 2.1rem !important;
    font-weight: 800 !important;
    color: #f8fafc !important;
}

/* Badges */
.badge-critical {
    background: linear-gradient(135deg, #ef4444, #b91c1c);
    color: #ffffff; padding: 4px 12px; border-radius: 9999px;
    font-weight: 700; font-size: 0.75rem; letter-spacing: 0.5px;
    display: inline-block; box-shadow: 0 2px 8px rgba(239, 68, 68, 0.4);
}
.badge-high {
    background: linear-gradient(135deg, #f97316, #c2410c);
    color: #ffffff; padding: 4px 12px; border-radius: 9999px;
    font-weight: 700; font-size: 0.75rem; letter-spacing: 0.5px;
    display: inline-block; box-shadow: 0 2px 8px rgba(249, 115, 22, 0.4);
}
.badge-medium {
    background: linear-gradient(135deg, #eab308, #ca8a04);
    color: #0f172a; padding: 4px 12px; border-radius: 9999px;
    font-weight: 700; font-size: 0.75rem; letter-spacing: 0.5px;
    display: inline-block; box-shadow: 0 2px 8px rgba(234, 179, 8, 0.3);
}
.badge-low {
    background: linear-gradient(135deg, #22c55e, #15803d);
    color: #ffffff; padding: 4px 12px; border-radius: 9999px;
    font-weight: 700; font-size: 0.75rem; letter-spacing: 0.5px;
    display: inline-block; box-shadow: 0 2px 8px rgba(34, 197, 94, 0.3);
}
.badge-info {
    background: #3b82f6; color: #ffffff; padding: 4px 12px; border-radius: 9999px;
    font-weight: 700; font-size: 0.75rem; display: inline-block;
}

/* Attack path chain display */
.path-container {
    background: #0f172a;
    border: 1px solid #1e293b;
    border-radius: 12px;
    padding: 20px;
    margin: 16px 0;
}

.step-node {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: #1e293b;
    border: 1px solid #334155;
    border-radius: 8px;
    padding: 8px 14px;
    color: #f1f5f9;
    font-weight: 600;
    font-size: 0.88rem;
}

.step-edge {
    display: inline-flex;
    align-items: center;
    color: #ef4444;
    font-weight: 600;
    font-size: 0.8rem;
    padding: 0 8px;
}

.reason-card {
    background: rgba(30, 41, 59, 0.7);
    border-left: 4px solid #3b82f6;
    border-radius: 0 8px 8px 0;
    padding: 10px 14px;
    margin-bottom: 8px;
    color: #e2e8f0;
    font-size: 0.9rem;
}
.reason-card.plus {
    border-left-color: #ef4444;
}
.reason-card.minus {
    border-left-color: #22c55e;
}

/* Header style */
.header-box {
    padding: 10px 0 24px 0;
    border-bottom: 1px solid rgba(255, 255, 255, 0.08);
    margin-bottom: 24px;
}
.header-title {
    font-size: 2.2rem;
    font-weight: 800;
    background: linear-gradient(135deg, #38bdf8 0%, #818cf8 50%, #c084fc 100%);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin: 0;
}
.header-subtitle {
    color: #94a3b8;
    font-size: 1rem;
    margin-top: 6px;
}
</style>
""",
    unsafe_allow_html=True,
)


# ── Constants & Helpers ───────────────────────────────────────────────
SCENARIOS_DIR = Path(__file__).resolve().parent / "data" / "scenarios"

SCENARIO_CONFIGS = {
    "05_multistep_attack.json": "🔥 05: Multi-Step Attack (Internet → EC2 → Role → S3)",
    "demo_scenario.json": "🌟 Live Demo: FinTech & E-Commerce Breach (Full Multi-Path)",
    "01_secure.json": "🛡️ 01: Secure Architecture (Isolated, No Attack Paths)",
    "02_public_ec2.json": "⚠️ 02: Public EC2 Bastion (SSH Open, Sensitive Isolated)",
    "03_excessive_iam.json": "🚨 03: Excessive IAM Permissions (Wildcard Role to RDS)",
    "04_public_s3.json": "🔓 04: Public S3 Bucket (Sensitive KYC Leak)",
}

TYPE_STYLES = {
    "internet": {"color": "#ef4444", "shape": "diamond", "icon": "🌐"},
    "ec2": {"color": "#3b82f6", "shape": "box", "icon": "💻"},
    "iam_role": {"color": "#8b5cf6", "shape": "dot", "icon": "🛡️"},
    "iam_user": {"color": "#a855f7", "shape": "ellipse", "icon": "👤"},
    "s3": {"color": "#06b6d4", "shape": "square", "icon": "🪣"},
    "rds": {"color": "#ec4899", "shape": "database", "icon": "🗄️"},
    "secret": {"color": "#f43f5e", "shape": "triangle", "icon": "🔑"},
    "security_group": {"color": "#f59e0b", "shape": "hexagon", "icon": "🔒"},
}


def get_node_style(raw_type: str) -> dict[str, str]:
    """Retrieve visual style (color, shape, icon) for a given resource type."""
    t = str(raw_type).lower()
    if "internet" in t:
        return TYPE_STYLES["internet"]
    elif "ec2" in t:
        return TYPE_STYLES["ec2"]
    elif "role" in t:
        return TYPE_STYLES["iam_role"]
    elif "user" in t:
        return TYPE_STYLES["iam_user"]
    elif "s3" in t or "bucket" in t:
        return TYPE_STYLES["s3"]
    elif "rds" in t or "db" in t or "database" in t:
        return TYPE_STYLES["rds"]
    elif "secret" in t:
        return TYPE_STYLES["secret"]
    elif "security_group" in t or "sg" in t:
        return TYPE_STYLES["security_group"]
    return {"color": "#64748b", "shape": "dot", "icon": "📦"}


def render_severity_badge(severity: str) -> str:
    """Return colored HTML badge for a severity string."""
    sev = severity.upper()
    if sev == "CRITICAL":
        return '<span class="badge-critical">🔴 CRITICAL</span>'
    elif sev == "HIGH":
        return '<span class="badge-high">🟠 HIGH</span>'
    elif sev == "MEDIUM":
        return '<span class="badge-medium">🟡 MEDIUM</span>'
    elif sev == "LOW":
        return '<span class="badge-low">🟢 LOW</span>'
    return f'<span class="badge-info">ℹ️ {sev}</span>'


def build_pyvis_network(
    graph: nx.DiGraph,
    selected_path: AttackPath | None = None,
) -> str:
    """Generate an interactive PyVis network graph HTML."""
    net = Network(
        height="640px",
        width="100%",
        bgcolor="#0b0f19",
        font_color="#e2e8f0",
        directed=True,
    )

    path_nodes = set(selected_path.nodes) if selected_path else set()
    path_edges: set[tuple[str, str]] = set()
    if selected_path and len(selected_path.nodes) > 1:
        for i in range(len(selected_path.nodes) - 1):
            path_edges.add((selected_path.nodes[i], selected_path.nodes[i + 1]))

    # Add Nodes
    for nid, data in graph.nodes(data=True):
        # Exclude legacy virtual INTERNET node if scenario res-internet exists
        if nid == "INTERNET" and "res-internet" in graph:
            continue

        raw_type = data.get("type") or data.get("resource_type") or "unknown"
        style = get_node_style(raw_type)
        is_sensitive = bool(data.get("sensitive")) or raw_type.lower() in {"rds", "secret"}
        is_on_path = nid in path_nodes
        findings = data.get("finding_objects") or []

        # Color & Border determination
        if is_on_path:
            bg_color = "#dc2626"
            border_color = "#fef08a" if is_sensitive else "#ffffff"
            border_width = 4
            size = 28
        elif is_sensitive:
            bg_color = style["color"]
            border_color = "#ef4444"
            border_width = 4
            size = 24
        else:
            bg_color = style["color"]
            border_color = style["color"]
            border_width = 1
            size = 20

        # Rich HTML Hover Tooltip
        tooltip_lines = [
            f"<div style='font-family: Inter, sans-serif; padding: 6px; font-size: 12px; color: #f8fafc; "
            f"background: #0f172a; border-radius: 6px; border: 1px solid #334155;'>",
            f"<div style='font-weight: 700; font-size: 13px; color: #38bdf8; margin-bottom: 4px;'>"
            f"{style['icon']} {data.get('name', nid)}</div>",
            f"<div><b>ID:</b> <code>{nid}</code></div>",
            f"<div><b>Type:</b> {raw_type}</div>",
            f"<div><b>Public:</b> {'🚨 Yes' if data.get('public') else 'No'}</div>",
            f"<div><b>Sensitive:</b> {'⚠️ Yes' if is_sensitive else 'No'}</div>",
        ]

        perms = data.get("permissions") or []
        if perms:
            perm_str = ", ".join(perms[:3]) + ("..." if len(perms) > 3 else "")
            tooltip_lines.append(f"<div style='margin-top: 4px;'><b>Permissions:</b> {perm_str}</div>")

        props = data.get("properties") or {}
        if props:
            tooltip_lines.append("<div style='margin-top: 4px; border-top: 1px solid #334155; padding-top: 4px;'><b>Properties:</b></div>")
            for k, v in list(props.items())[:3]:
                tooltip_lines.append(f"<div style='color: #94a3b8;'>• {k}: {str(v)[:28]}</div>")

        if findings:
            tooltip_lines.append(f"<div style='margin-top: 4px; border-top: 1px solid #ef4444; padding-top: 4px; color: #ef4444; font-weight: bold;'>⚠️ {len(findings)} Finding(s):</div>")
            for f in findings:
                f_sev = f.get("severity", "MEDIUM")
                f_rule = f.get("rule") or f.get("title") or "Misconfiguration"
                tooltip_lines.append(f"<div style='color: #fca5a5;'>• [{f_sev}] {f_rule}</div>")

        tooltip_lines.append("</div>")
        node_title = "".join(tooltip_lines)

        label = f"{style['icon']} {data.get('name', nid)}"
        net.add_node(
            nid,
            label=label,
            title=node_title,
            color={"background": bg_color, "border": border_color},
            borderWidth=border_width,
            shape=style["shape"],
            size=size,
            font={"size": 12, "color": "#f8fafc"},
        )

    # Add Edges
    for u, v, edata in graph.edges(data=True):
        if (u == "INTERNET" or v == "INTERNET") and "res-internet" in graph:
            continue

        rel_type = str(edata.get("type") or edata.get("relation") or "connects_to")
        is_path_edge = (u, v) in path_edges

        if is_path_edge:
            edge_color = "#ef4444"
            edge_width = 4.5
        else:
            edge_color = "rgba(148, 163, 184, 0.4)"
            edge_width = 1.5

        net.add_edge(
            u,
            v,
            label=rel_type,
            title=rel_type,
            color=edge_color,
            width=edge_width,
            arrows="to",
            font={
                "size": 10,
                "color": "#cbd5e1",
                "strokeWidth": 2,
                "strokeColor": "#0b0f19",
                "align": "middle",
            },
            smooth={"type": "curvedCW", "roundness": 0.12},
        )

    # Vis.js physics and interaction settings
    net.set_options(
        """
    {
        "physics": {
            "forceAtlas2Based": {
                "gravitationalConstant": -70,
                "centralGravity": 0.015,
                "springLength": 130,
                "springConstant": 0.06,
                "damping": 0.42
            },
            "solver": "forceAtlas2Based",
            "stabilization": {"iterations": 150}
        },
        "interaction": {
            "hover": true,
            "tooltipDelay": 80,
            "zoomView": true,
            "dragView": true
        }
    }
    """
    )

    return net.generate_html()


# ── Initialization & Sidebar ──────────────────────────────────────────

# Header
st.markdown(
    """
<div class="header-box">
    <h1 class="header-title">🛡️ Cloud Attack Path Visualiser</h1>
    <p class="header-subtitle">Graph-Based Discovery, Deterministic Misconfiguration Detection & Risk Assessment</p>
</div>
""",
    unsafe_allow_html=True,
)

# Sidebar configuration
with st.sidebar:
    st.markdown("### 📁 Configuration Source")
    st.caption("Select a pre-built scenario or upload custom JSON.")

    source_mode = st.radio(
        "Source mode",
        ["🎯 Pre-built Scenarios", "📤 Upload your own JSON"],
        label_visibility="collapsed",
    )

    selected_scenario_file: str | None = None
    uploaded_config_dict: dict[str, Any] | None = None

    if source_mode == "🎯 Pre-built Scenarios":
        # Default to scenario 5 on initial run
        scenario_keys = list(SCENARIO_CONFIGS.keys())
        default_index = 0  # 05_multistep_attack.json is first

        selected_scenario_file = st.selectbox(
            "Select Scenario",
            options=scenario_keys,
            index=default_index,
            format_func=lambda k: SCENARIO_CONFIGS[k],
        )
    else:
        uploaded_file = st.file_uploader("Upload JSON configuration", type=["json"])
        if uploaded_file is not None:
            try:
                uploaded_config_dict = json.loads(uploaded_file.read().decode("utf-8"))
                st.success(f"Loaded {uploaded_file.name}")
            except Exception as e:
                st.error(f"Invalid JSON file: {e}")

    run_btn = st.button("🚀 Run Analysis", type="primary", use_container_width=True)

    if "analysis_result" in st.session_state and st.session_state["analysis_result"]:
        active_res = st.session_state["analysis_result"]
        report_md_sidebar = build_markdown_report(
            active_res, st.session_state.get("ai_explanations")
        )
        report_filename = f"{st.session_state.get('scenario_name', 'cloud_scenario')}_report.md"
        st.download_button(
            label="📥 Download Security Report (.md)",
            data=report_md_sidebar,
            file_name=report_filename,
            mime="text/markdown",
            use_container_width=True,
        )

    st.markdown("---")
    st.markdown("### ℹ️ Defensive Rules")
    st.caption(
        "• Deterministic security detectors evaluate public resources, open ports, and excessive IAM.<br>"
        "• NetworkX evaluates simple paths from entry points to sensitive targets (cutoff=6).<br>"
        "• Additive risk model calculates path impact, capping scores at 100.<br>"
        "• <b>Simulated AWS JSON only</b> — never contacts real cloud APIs.",
        unsafe_allow_html=True,
    )

# ── Session State Analysis Execution ─────────────────────────────────

# Auto-run scenario 5 on first load if not initialized
if "analysis_result" not in st.session_state:
    try:
        init_file = SCENARIOS_DIR / "05_multistep_attack.json"
        cfg = load_config(init_file)
        init_result = run_analysis(cfg)
        init_graph = build_graph(cfg, findings=init_result.findings)
        st.session_state["analysis_result"] = init_result
        st.session_state["graph"] = init_graph
        st.session_state["scenario_name"] = "05_multistep_attack.json"
        st.session_state["selected_path_idx"] = 0
    except Exception as e:
        st.error(f"Initialization error: {e}")

# Re-run when "Run Analysis" button is clicked
if run_btn:
    try:
        with st.spinner("Analyzing cloud configuration..."):
            if source_mode == "🎯 Pre-built Scenarios" and selected_scenario_file:
                target_path = SCENARIOS_DIR / selected_scenario_file
                active_cfg = load_config(target_path)
                active_name = selected_scenario_file
            elif source_mode == "📤 Upload your own JSON" and uploaded_config_dict:
                active_cfg = load_config(uploaded_config_dict)
                active_name = active_cfg.scenario_name or "uploaded_config.json"
            else:
                st.warning("Please upload a valid JSON file before analyzing.")
                st.stop()

            res = run_analysis(active_cfg)
            g = build_graph(active_cfg, findings=res.findings)
            st.session_state["analysis_result"] = res
            st.session_state["graph"] = g
            st.session_state["scenario_name"] = active_name
            st.session_state["selected_path_idx"] = 0
            st.toast("Analysis complete!", icon="✅")
    except Exception as exc:
        st.error(f"Analysis failed: {exc}")
        st.stop()

# Retrieve cached analysis results
result: AnalysisResult | None = st.session_state.get("analysis_result")
graph: nx.DiGraph | None = st.session_state.get("graph")

if not result or not graph:
    st.info("Please select a scenario and click **Run Analysis** to start.")
    st.stop()

# ── 5 Main Tabs ───────────────────────────────────────────────────────
tab_overview, tab_findings, tab_paths, tab_graph, tab_ai = st.tabs(
    ["📊 Overview", "🔍 Findings", "🛤️ Attack Paths", "🌐 Graph Visualizer", "🤖 AI Security Analyst"]
)

# ══════════════════════════════════════════════════════════════════════
# TAB 1: OVERVIEW
# ══════════════════════════════════════════════════════════════════════
with tab_overview:
    col_ov_title, col_ov_btn = st.columns([3, 1])
    with col_ov_title:
        st.markdown("#### Scenario Overview & Risk Summary")
        st.caption(f"Active Scenario: **{st.session_state.get('scenario_name', result.config.scenario_name)}**")
    with col_ov_btn:
        report_md_overview = build_markdown_report(
            result, st.session_state.get("ai_explanations")
        )
        st.download_button(
            label="📥 Download Security Report (.md)",
            data=report_md_overview,
            file_name=f"{st.session_state.get('scenario_name', 'cloud_scenario')}_report.md",
            mime="text/markdown",
            use_container_width=True,
            key="dl_report_overview",
        )

    # Metric Cards
    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        st.metric("Resources", len(result.config.resources))
    with c2:
        st.metric("Findings", len(result.findings))
    with c3:
        st.metric("Attack Paths", len(result.paths))
    with c4:
        crit_count = sum(1 for p in result.paths if p.severity == "CRITICAL")
        st.metric("Critical Paths", crit_count)
    with c5:
        high_risk_count = sum(1 for p in result.paths if p.severity == "HIGH")
        st.metric("High Risk Paths", high_risk_count)

    st.markdown("---")

    # Severity distribution bar chart
    st.markdown("#### Severity Distribution")

    # Aggregate counts for findings & paths
    sev_categories = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    chart_data = []

    for sev in sev_categories:
        f_count = sum(1 for f in result.findings if f.severity.upper() == sev)
        p_count = sum(1 for p in result.paths if p.severity.upper() == sev)
        chart_data.append({"Severity": sev, "Type": "Security Findings", "Count": f_count})
        chart_data.append({"Severity": sev, "Type": "Attack Paths", "Count": p_count})

    df_chart = pd.DataFrame(chart_data)

    sev_color_scale = alt.Scale(
        domain=["Security Findings", "Attack Paths"],
        range=["#38bdf8", "#ef4444"],
    )

    chart = (
        alt.Chart(df_chart)
        .mark_bar(cornerRadiusTopLeft=5, cornerRadiusTopRight=5)
        .encode(
            x=alt.X("Severity:N", sort=sev_categories, title="Severity Level"),
            y=alt.Y("Count:Q", title="Total Detected"),
            color=alt.Color("Type:N", scale=sev_color_scale, title="Category"),
            xOffset="Type:N",
            tooltip=["Severity", "Type", "Count"],
        )
        .properties(height=320)
    )

    st.altair_chart(chart, use_container_width=True)

# ══════════════════════════════════════════════════════════════════════
# TAB 2: FINDINGS
# ══════════════════════════════════════════════════════════════════════
with tab_findings:
    st.markdown("#### Detected Misconfigurations")
    st.caption("Deterministic rule-based findings evaluated across resources.")

    col_filter, col_search = st.columns([2, 2])
    with col_filter:
        sev_filter = st.multiselect(
            "Filter by Severity",
            options=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
            default=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        )
    with col_search:
        search_query = st.text_input("Search findings", placeholder="Filter by rule, resource, or keyword...")

    filtered_findings = [
        f
        for f in result.findings
        if f.severity.upper() in sev_filter
        and (
            not search_query
            or search_query.lower() in f.rule.lower()
            or search_query.lower() in f.resource_id.lower()
            or search_query.lower() in f.description.lower()
            or search_query.lower() in f.recommendation.lower()
        )
    ]

    if not filtered_findings:
        st.info("No security findings match the selected filter criteria.")
    else:
        st.caption(f"Showing **{len(filtered_findings)}** of {len(result.findings)} findings")

        # Render styled HTML table with badges
        table_rows = []
        for f in filtered_findings:
            badge = render_severity_badge(f.severity)
            row = f"""
            <tr style="border-bottom: 1px solid rgba(255, 255, 255, 0.08); vertical-align: top;">
                <td style="padding: 12px 10px;">{badge}</td>
                <td style="padding: 12px 10px; font-weight: 600; color: #f8fafc;"><code>{f.id}</code></td>
                <td style="padding: 12px 10px; color: #38bdf8;"><b>{f.rule}</b></td>
                <td style="padding: 12px 10px; color: #cbd5e1;"><code>{f.resource_id}</code></td>
                <td style="padding: 12px 10px; color: #94a3b8; font-size: 0.9rem;">{f.description}</td>
                <td style="padding: 12px 10px; color: #86efac; font-size: 0.88rem;">💡 {f.recommendation}</td>
            </tr>
            """
            table_rows.append(row)

        table_html = f"""
        <div style="overflow-x: auto; background: #0f172a; border-radius: 10px; border: 1px solid #1e293b; padding: 6px;">
        <table style="width: 100%; border-collapse: collapse; text-align: left; font-size: 0.92rem;">
            <thead>
                <tr style="border-bottom: 2px solid #334155; color: #94a3b8; font-size: 0.8rem; text-transform: uppercase;">
                    <th style="padding: 10px;">Severity</th>
                    <th style="padding: 10px;">ID</th>
                    <th style="padding: 10px;">Rule</th>
                    <th style="padding: 10px;">Target Resource</th>
                    <th style="padding: 10px;">Description</th>
                    <th style="padding: 10px;">Recommendation</th>
                </tr>
            </thead>
            <tbody>
                {''.join(table_rows)}
            </tbody>
        </table>
        </div>
        """
        st.markdown(table_html, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════
# TAB 3: ATTACK PATHS
# ══════════════════════════════════════════════════════════════════════
with tab_paths:
    st.markdown("#### Discovered Multi-Step Attack Paths")

    if len(result.paths) == 0:
        st.success("🛡️ **No attack path found!** All sensitive targets (RDS, Secrets, S3) are isolated from external entry points.")
    else:
        st.caption(f"Found **{len(result.paths)}** attack paths reaching sensitive assets (sorted by score desc).")

        # Summary Table
        table_data = []
        for idx, p in enumerate(result.paths):
            source = p.nodes[0]
            target = p.nodes[-1]
            hops = len(p.nodes) - 1
            table_data.append(
                {
                    "Path #": f"Path {idx + 1}",
                    "Source": source,
                    "Target": target,
                    "Hops": hops,
                    "Score": p.score,
                    "Severity": p.severity,
                }
            )

        df_paths = pd.DataFrame(table_data)
        st.dataframe(
            df_paths,
            use_container_width=True,
            column_config={
                "Score": st.column_config.ProgressColumn(
                    "Score",
                    min_value=0,
                    max_value=100,
                    format="%d",
                ),
            },
            hide_index=True,
        )

        st.markdown("---")
        st.markdown("#### Path Inspector & Risk Breakdown")

        # Selection widget
        path_options = [
            f"Path {i + 1}: {p.nodes[0]} ➔ {p.nodes[-1]} (Score: {p.score}, {p.severity})"
            for i, p in enumerate(result.paths)
        ]
        chosen_idx = st.selectbox(
            "Select attack path to inspect:",
            options=list(range(len(result.paths))),
            format_func=lambda i: path_options[i],
            key="path_inspect_select",
        )
        st.session_state["selected_path_idx"] = chosen_idx
        selected_p = result.paths[chosen_idx]

        # Path metrics
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.metric("Path Score", f"{selected_p.score}/100")
        with m2:
            st.markdown(f"**Severity:** {render_severity_badge(selected_p.severity)}", unsafe_allow_html=True)
        with m3:
            st.metric("Total Hops", len(selected_p.nodes) - 1)
        with m4:
            target_res = next((r for r in result.config.resources if r.id == selected_p.nodes[-1]), None)
            target_type = target_res.type if target_res else "unknown"
            st.metric("Target Asset Type", target_type)

        # Step-by-Step Chain
        st.markdown("##### ⛓️ Step-by-Step Attack Chain")
        step_elements = []
        for i, nid in enumerate(selected_p.nodes):
            res_obj = next((r for r in result.config.resources if r.id == nid), None)
            res_type = res_obj.type if res_obj else ("internet" if "internet" in nid else "resource")
            style = get_node_style(res_type)

            step_elements.append(
                f'<span class="step-node">{style["icon"]} <code>{nid}</code> <small style="color:#94a3b8">({res_type})</small></span>'
            )
            if i < len(selected_p.nodes) - 1:
                edge_label = selected_p.edges[i] if i < len(selected_p.edges) else "connects_to"
                step_elements.append(f'<span class="step-edge">━━[{edge_label}]━━▶</span>')

        st.markdown(
            f'<div class="path-container">{" ".join(step_elements)}</div>',
            unsafe_allow_html=True,
        )

        # Reasons for score
        st.markdown("##### 📝 Additive Risk Model Reasons")
        if selected_p.reasons:
            for r in selected_p.reasons:
                cls = "plus" if r.startswith("+") else ("minus" if r.startswith("-") else "")
                st.markdown(f'<div class="reason-card {cls}">{r}</div>', unsafe_allow_html=True)
        else:
            st.caption("No individual additive adjustments recorded for this path.")

# ══════════════════════════════════════════════════════════════════════
# TAB 4: GRAPH
# ══════════════════════════════════════════════════════════════════════
with tab_graph:
    st.markdown("#### Interactive Infrastructure & Attack Path Network")
    st.caption("Nodes colored by type. Sensitive targets have a red border. The selected attack path is highlighted in bright red with thicker edges.")

    # Highlighting option
    col_g1, col_g2 = st.columns([3, 1])
    with col_g1:
        if result.paths:
            graph_path_options = ["None (Show Entire Topology)"] + [
                f"Path {i + 1}: {p.nodes[0]} ➔ {p.nodes[-1]} ({p.severity})"
                for i, p in enumerate(result.paths)
            ]
            current_choice = st.session_state.get("selected_path_idx", 0) + 1
            chosen_graph_opt = st.selectbox(
                "Highlight Attack Path:",
                options=list(range(len(graph_path_options))),
                index=current_choice if current_choice < len(graph_path_options) else 0,
                format_func=lambda i: graph_path_options[i],
            )
            active_highlight_path = (
                result.paths[chosen_graph_opt - 1] if chosen_graph_opt > 0 else None
            )
        else:
            st.info("No attack paths to highlight. Showing full topology.")
            active_highlight_path = None

    with col_g2:
        st.markdown(
            """
        <div style="font-size: 0.8rem; color: #94a3b8; background: #0f172a; padding: 10px; border-radius: 8px; border: 1px solid #1e293b;">
            <b>Node Legend:</b><br>
            🌐 Internet &nbsp;|&nbsp; 💻 EC2 &nbsp;|&nbsp; 🛡️ Role<br>
            🪣 S3 &nbsp;|&nbsp; 🗄️ RDS &nbsp;|&nbsp; 🔑 Secret<br>
            <span style="color: #ef4444;">🔴 Red Border: Sensitive Target</span>
        </div>
        """,
            unsafe_allow_html=True,
        )

    # Render PyVis Network HTML
    net_html = build_pyvis_network(graph, selected_path=active_highlight_path)
    st.components.v1.html(net_html, height=650, scrolling=False)

# ══════════════════════════════════════════════════════════════════════
# TAB 5: AI SECURITY ANALYST
# ══════════════════════════════════════════════════════════════════════
with tab_ai:
    st.markdown("#### 🤖 AI Security Analyst")
    st.caption("Synthesizes deterministic path discovery and risk scoring into actionable intelligence for engineering and leadership.")

    if not result.paths:
        st.success("🛡️ **No attack paths identified** in this configuration. All sensitive assets are protected from external entry points.")
    else:
        # Initialize session state cache for explanations if not present
        if "ai_explanations" not in st.session_state:
            st.session_state["ai_explanations"] = {}

        ai_path_options = [
            f"Path {i + 1}: {p.nodes[0]} ➔ {p.nodes[-1]} (Score: {p.score}, {p.severity})"
            for i, p in enumerate(result.paths)
        ]
        default_ai_idx = st.session_state.get("selected_path_idx", 0)
        if default_ai_idx >= len(result.paths):
            default_ai_idx = 0

        selected_ai_idx = st.selectbox(
            "Select attack path to analyze:",
            options=list(range(len(result.paths))),
            index=default_ai_idx,
            format_func=lambda i: ai_path_options[i],
            key="ai_path_selector_widget",
        )

        chosen_ai_path = result.paths[selected_ai_idx]
        active_scenario_name = st.session_state.get("scenario_name", result.config.scenario_name)
        cache_key = f"{active_scenario_name}_{tuple(chosen_ai_path.nodes)}"

        col_btn, col_info = st.columns([2, 3])
        with col_btn:
            generate_btn = st.button("✨ Generate explanation", type="primary", use_container_width=True)
        with col_info:
            has_api_key = bool(get_openai_api_key())
            if has_api_key:
                st.caption("🟢 OpenAI API key configured (model: `OPENAI_MODEL` or default `gpt-4o-mini`).")
            else:
                st.caption("ℹ️ No OpenAI key detected. Using deterministic template fallback.")

        if generate_btn:
            with st.spinner("Analyzing attack path with AI Security Analyst..."):
                expl = explain_path(chosen_ai_path, graph)
                st.session_state["ai_explanations"][cache_key] = expl

        cached_expl = st.session_state["ai_explanations"].get(cache_key)

        if cached_expl:
            source_type = cached_expl.get("source", "fallback")
            if source_type == "openai":
                badge_html = '<span class="badge-low" style="background: linear-gradient(135deg, #10b981, #059669); color: white; padding: 4px 14px; border-radius: 9999px; font-weight: 700; font-size: 0.8rem; display: inline-block;">🤖 Source: OpenAI (gpt-4o-mini)</span>'
            else:
                badge_html = '<span class="badge-medium" style="background: linear-gradient(135deg, #6366f1, #4f46e5); color: #ffffff; padding: 4px 14px; border-radius: 9999px; font-weight: 700; font-size: 0.8rem; display: inline-block;">🛡️ Source: Fallback (Deterministic Template)</span>'

            st.markdown(f"<div style='margin: 16px 0 16px 0;'>{badge_html}</div>", unsafe_allow_html=True)

            # Executive Summary
            st.markdown("### 📋 Executive Summary")
            st.markdown(
                f"""<div style="background: #0f172a; border-left: 4px solid #38bdf8; border-radius: 6px; padding: 14px; margin-bottom: 18px; color: #f8fafc; font-size: 0.98rem; line-height: 1.6;">
                {cached_expl.get('executive_summary', '')}
                </div>""",
                unsafe_allow_html=True,
            )

            # Technical Summary
            st.markdown("### 🔍 Technical Summary")
            st.markdown(
                f"""<div style="background: rgba(30, 41, 59, 0.6); border: 1px solid #1e293b; border-radius: 8px; padding: 14px; margin-bottom: 18px; color: #e2e8f0; line-height: 1.6;">
                {cached_expl.get('summary', '')}
                </div>""",
                unsafe_allow_html=True,
            )

            # Why It Exists
            st.markdown("### ⚠️ Why It Exists")
            why_text = cached_expl.get('why_it_exists', '')
            st.markdown(
                f"""<div style="background: rgba(30, 41, 59, 0.6); border: 1px solid #1e293b; border-radius: 8px; padding: 14px; margin-bottom: 18px; color: #cbd5e1; white-space: pre-line; line-height: 1.6;">
                {why_text}
                </div>""",
                unsafe_allow_html=True,
            )

            # Potential Impact
            st.markdown("### 💥 Potential Impact")
            st.markdown(
                f"""<div style="background: rgba(30, 41, 59, 0.6); border: 1px solid #1e293b; border-radius: 8px; padding: 14px; margin-bottom: 18px; color: #fca5a5; line-height: 1.6;">
                {cached_expl.get('impact', '')}
                </div>""",
                unsafe_allow_html=True,
            )

            # Remediation Plan
            st.markdown("### 🛠️ Remediation Plan")
            remediations = cached_expl.get('remediation', [])
            if isinstance(remediations, list) and remediations:
                for step_idx, step_desc in enumerate(remediations, start=1):
                    st.markdown(
                        f"""<div style="background: #0f172a; border-left: 4px solid #22c55e; border-radius: 6px; padding: 10px 14px; margin-bottom: 8px; color: #f0fdf4;">
                        <b>{step_idx}.</b> {step_desc}
                        </div>""",
                        unsafe_allow_html=True,
                    )
            else:
                st.info("No explicit remediation actions listed.")
        else:
            st.info("Select a path above and click **✨ Generate explanation** to synthesize an analysis.")


# ══════════════════════════════════════════════════════════════════════
# RESOURCE-DETAILS PANEL (DEEP-DIVE)
# ══════════════════════════════════════════════════════════════════════
st.markdown("---")
st.markdown("### 🔍 Resource Deep-Dive")
st.caption("Inspect configuration properties, attached permissions, and tailored remediation recommendations.")

if result.config.resources:
    res_list = result.config.resources
    res_map = {r.id: r for r in res_list}

    selected_res_id = st.selectbox(
        "Choose resource to inspect:",
        options=[r.id for r in res_list],
        format_func=lambda rid: f"{res_map[rid].name} ({res_map[rid].type}) — {rid}",
    )

    inspected = res_map[selected_res_id]
    inspected_style = get_node_style(inspected.type)

    # Details Layout
    col_d1, col_d2 = st.columns([1, 2])

    with col_d1:
        st.markdown(
            f"""
        <div style="background: #0f172a; border: 1px solid #1e293b; border-radius: 10px; padding: 16px;">
            <h4 style="margin: 0; color: #38bdf8;">{inspected_style['icon']} {inspected.name}</h4>
            <div style="margin: 8px 0; color: #94a3b8; font-size: 0.85rem;">ID: <code>{inspected.id}</code></div>
            <div style="margin: 4px 0;"><b>Type:</b> <code>{inspected.type}</code></div>
            <div style="margin: 4px 0;"><b>Public Exposure:</b> {'🚨 Yes' if inspected.public else '✅ No'}</div>
            <div style="margin: 4px 0;"><b>Sensitive Asset:</b> {'⚠️ Yes' if inspected.sensitive else 'No'}</div>
        </div>
        """,
            unsafe_allow_html=True,
        )

        # Permissions view
        perms = inspected.properties.get("policies") or inspected.properties.get("permissions") or []
        if isinstance(perms, str):
            perms = [perms]
        st.markdown("##### 🔑 Granted Permissions / Policies")
        if perms:
            for p in perms:
                st.markdown(f"- <code>{p}</code>", unsafe_allow_html=True)
        else:
            st.caption("No explicit IAM policies or permissions attached.")

    with col_d2:
        # Findings & Recommendations on this resource
        res_findings = [f for f in result.findings if f.resource_id == inspected.id]
        st.markdown(f"##### ⚠️ Security Findings ({len(res_findings)})")

        if res_findings:
            for f in res_findings:
                st.markdown(
                    f"""
                <div style="background: rgba(30, 41, 59, 0.7); border-left: 4px solid #ef4444; border-radius: 6px; padding: 12px; margin-bottom: 10px;">
                    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                        <strong style="color: #f8fafc;">{f.rule}</strong>
                        {render_severity_badge(f.severity)}
                    </div>
                    <div style="color: #cbd5e1; font-size: 0.88rem; margin-bottom: 6px;">{f.description}</div>
                    <div style="color: #86efac; font-size: 0.85rem;">💡 <b>Recommendation:</b> {f.recommendation}</div>
                </div>
                """,
                    unsafe_allow_html=True,
                )
        else:
            st.success("✅ **No misconfigurations detected.** Follow least-privilege principles and baseline monitoring.")

        # Expandable raw properties
        with st.expander("🛠️ Raw Resource Properties (JSON)"):
            st.json(inspected.properties)
