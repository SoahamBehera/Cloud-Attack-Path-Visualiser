"""Tests for the config parser."""

from pathlib import Path

from src.models import CloudConfig
from src.parser import parse_config


def test_parse_from_file(sample_config_path: Path):
    config = parse_config(sample_config_path)
    assert isinstance(config, CloudConfig)
    assert len(config.resources) > 0


def test_parse_from_string(sample_config_path: Path):
    raw = sample_config_path.read_text(encoding="utf-8")
    config = parse_config(raw)
    assert isinstance(config, CloudConfig)
    assert len(config.resources) > 0


def test_parse_from_dict(sample_config_dict: dict):
    config = parse_config(sample_config_dict)
    assert isinstance(config, CloudConfig)
    assert config.metadata.get("account_id") == "123456789012"


def test_parse_resource_types(sample_config: CloudConfig):
    types = {r.type for r in sample_config.resources}
    assert "EC2" in types
    assert "S3Bucket" in types
    assert "IAMRole" in types


def test_parse_empty_config():
    config = parse_config({"resources": []})
    assert len(config.resources) == 0
