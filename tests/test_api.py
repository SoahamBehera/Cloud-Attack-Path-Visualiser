"""Tests for the FastAPI REST API."""

import json
from pathlib import Path

from fastapi.testclient import TestClient

from api.main import app

client = TestClient(app)


def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_analyze_endpoint(sample_config_dict: dict):
    resp = client.post("/analyze", json={"config": sample_config_dict})
    assert resp.status_code == 200
    data = resp.json()
    assert "report" in data
    assert "explanation" in data
    assert data["report"]["resources_count"] > 0
    assert len(data["report"]["findings"]) > 0


def test_findings_endpoint(sample_config_dict: dict):
    resp = client.post("/findings", json={"config": sample_config_dict})
    assert resp.status_code == 200
    assert len(resp.json()["findings"]) > 0


def test_attack_paths_endpoint(sample_config_dict: dict):
    resp = client.post("/attack-paths", json={"config": sample_config_dict})
    assert resp.status_code == 200
    assert len(resp.json()["attack_paths"]) > 0


def test_analyze_invalid_config():
    resp = client.post("/analyze", json={"config": {"resources": "not-a-list"}})
    assert resp.status_code == 400


def test_scenarios_endpoint():
    resp = client.get("/scenarios")
    assert resp.status_code == 200
    data = resp.json()
    assert "scenarios" in data
    assert len(data["scenarios"]) >= 5
    names = [s["file"] for s in data["scenarios"]]
    assert "01_secure.json" in names
    assert "05_multistep_attack.json" in names


def test_analyze_endpoint_direct_cloud_config(sample_config_dict: dict):
    resp = client.post("/analyze", json=sample_config_dict)
    assert resp.status_code == 200
    data = resp.json()
    assert "findings" in data
    assert "paths" in data
    assert "summary" in data


def test_explain_endpoint():
    path_data = ["res-internet", "res-ec2-storefront", "res-role-storefront", "res-s3-customer-data"]
    resp = client.post("/explain", json={"path": path_data, "context": None})
    assert resp.status_code == 200
    data = resp.json()
    assert "summary" in data
    assert "why_it_exists" in data
    assert "impact" in data
    assert "remediation" in data
    assert "executive_summary" in data
    assert data["source"] in ("fallback", "openai")
