"""Unit tests for src/ai_explainer.py testing both OpenAI and Fallback modes."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch
import pytest

from src.ai_explainer import explain_path
from src.graph_builder import build_graph
from src.loader import load_config
from src.pipeline import run_analysis


@pytest.fixture
def sample_analysis():
    scenario_path = Path(__file__).resolve().parent.parent / "data" / "scenarios" / "05_multistep_attack.json"
    cfg = load_config(scenario_path)
    res = run_analysis(cfg)
    g = build_graph(cfg, findings=res.findings)
    return res.paths[0], g


def test_explain_path_fallback_mode_without_key(sample_analysis, monkeypatch):
    """Test deterministic fallback mode when no OPENAI_API_KEY is configured."""
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    path, graph = sample_analysis

    result = explain_path(path, graph)

    assert isinstance(result, dict)
    assert result["source"] == "fallback"
    assert "summary" in result and isinstance(result["summary"], str)
    assert "why_it_exists" in result and isinstance(result["why_it_exists"], str)
    assert "impact" in result and isinstance(result["impact"], str)
    assert "remediation" in result and isinstance(result["remediation"], list)
    assert len(result["remediation"]) > 0
    assert "executive_summary" in result and isinstance(result["executive_summary"], str)
    assert "CRITICAL" in result["executive_summary"]


def test_explain_path_openai_mode_with_mocked_key(sample_analysis, monkeypatch):
    """Test OpenAI mode when OPENAI_API_KEY is configured and API responds successfully."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-mock-api-key-12345")
    path, graph = sample_analysis

    mock_llm_json = {
        "executive_summary": "A multi-step attack chain could potentially permit unauthorized access to customer records.",
        "summary": "External traffic traverses an exposed storefront EC2 instance, leverages assumed IAM role credentials, and accesses the customer data S3 bucket.",
        "why_it_exists": "Security group permits unrestricted SSH (port 22) ingress and IAM role possesses broad S3 read policies.",
        "impact": "Potential exfiltration of confidential customer PII data.",
        "remediation": [
            "Restrict security group port 22 access to authorized management subnets.",
            "Enforce least-privilege scoping on StorefrontEC2InstanceProfileRole.",
            "Enable S3 bucket policy restrictions and KMS CMK encryption."
        ]
    }

    mock_choice = MagicMock()
    mock_choice.message.content = json.dumps(mock_llm_json)
    mock_response = MagicMock()
    mock_response.choices = [mock_choice]

    with patch("openai.OpenAI") as mock_openai_cls:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.return_value = mock_response

        result = explain_path(path, graph)

    assert isinstance(result, dict)
    assert result["source"] == "openai"
    assert result["executive_summary"] == mock_llm_json["executive_summary"]
    assert result["summary"] == mock_llm_json["summary"]
    assert result["why_it_exists"] == mock_llm_json["why_it_exists"]
    assert result["impact"] == mock_llm_json["impact"]
    assert result["remediation"] == mock_llm_json["remediation"]


def test_explain_path_handles_api_failure_gracefully(sample_analysis, monkeypatch):
    """Test that OpenAI errors fallback cleanly without breaking."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-mock-api-key-12345")
    path, graph = sample_analysis

    with patch("openai.OpenAI") as mock_openai_cls:
        mock_client = MagicMock()
        mock_openai_cls.return_value = mock_client
        mock_client.chat.completions.create.side_effect = RuntimeError("OpenAI connection timeout")

        result = explain_path(path, graph)

    assert isinstance(result, dict)
    assert result["source"] == "fallback"
    assert "summary" in result
    assert "remediation" in result
    assert isinstance(result["remediation"], list)
