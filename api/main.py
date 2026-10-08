"""FastAPI REST API for Cloud Attack Path Visualiser.

Provides endpoints for health checks, scenario discovery, deterministic security
analysis, and AI-powered attack path explanation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from src.ai_explainer import explain_path
from src.loader import load_config
from src.models import AnalysisResult, AttackPath, CloudConfig
from src.pipeline import run_analysis

load_dotenv()

SCENARIOS_DIR = Path(__file__).resolve().parent.parent / "data" / "scenarios"

app = FastAPI(
    title="Cloud Attack Path Visualiser API",
    description="Analyze simulated AWS configs for security misconfigurations, attack paths, and AI explanations.",
    version="2.0.0",
)


class HealthResponse(BaseModel):
    status: str = "ok"


class ExplainRequest(BaseModel):
    """Request model for explaining an attack path."""

    path: Any = Field(
        ...,
        description="Attack path as an AttackPath object, dict, or list of node IDs",
    )
    context: Any = Field(
        default=None,
        description="Optional graph context, node metadata, or findings",
    )


@app.get("/health", response_model=HealthResponse)
def health_check():
    """Health check endpoint."""
    return HealthResponse()


@app.get("/scenarios")
def list_scenarios():
    """List all available pre-built scenarios."""
    scenarios = []
    if SCENARIOS_DIR.exists():
        for f in sorted(SCENARIOS_DIR.glob("*.json")):
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                scenarios.append({
                    "file": f.name,
                    "scenario_name": data.get("scenario_name", f.stem),
                    "resources_count": len(data.get("resources", [])),
                    "relationships_count": len(data.get("relationships", [])),
                    "description": data.get("metadata", {}).get("description", ""),
                })
            except Exception:
                continue
    return {"scenarios": scenarios}


@app.post("/analyze", response_model=AnalysisResult)
def analyze_config(body: dict[str, Any]):
    """Analyze a CloudConfig JSON scenario and return the AnalysisResult."""
    try:
        # Support both {"config": {...}} and raw CloudConfig JSON
        raw_config = body.get("config") if (isinstance(body, dict) and "config" in body and isinstance(body["config"], dict)) else body
        config = load_config(raw_config)
        result = run_analysis(config)

        # Backwards-compatible attributes for legacy consumers/tests
        result_dict = result.model_dump()
        result.report = result_dict
        result.explanation = (
            f"Scenario '{config.scenario_name}' analyzed: "
            f"{len(result.findings)} findings and {len(result.paths)} attack paths discovered."
        )
        return result
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/explain")
def explain_attack_path(body: ExplainRequest):
    """Generate an AI-powered (or deterministic fallback) explanation for a path."""
    try:
        explanation = explain_path(body.path, body.context)
        return explanation
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


# ── Backwards-compatible helper endpoints ────────────────────────────


@app.post("/findings")
def get_findings(body: dict[str, Any]):
    """Return only detected misconfiguration findings."""
    try:
        raw_config = body.get("config") if (isinstance(body, dict) and "config" in body and isinstance(body["config"], dict)) else body
        config = load_config(raw_config)
        result = run_analysis(config)
        return {"findings": [f.model_dump() for f in result.findings]}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post("/attack-paths")
def get_attack_paths(body: dict[str, Any]):
    """Return only discovered attack paths."""
    try:
        raw_config = body.get("config") if (isinstance(body, dict) and "config" in body and isinstance(body["config"], dict)) else body
        try:
            config = load_config(raw_config)
            result = run_analysis(config)
            if result.paths:
                return {"attack_paths": [p.model_dump() for p in result.paths]}
        except Exception:
            pass

        from src.engine import analyze
        report, _ = analyze(raw_config)
        return {"attack_paths": [p.model_dump() for p in report.attack_paths]}
    except Exception as exc:
        raise HTTPException(status_code=400, detail=str(exc))
