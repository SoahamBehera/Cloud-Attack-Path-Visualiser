"""Tests for src/loader.py and scenario validation."""

from pathlib import Path
import pytest

from src.loader import load_config
from src.models import CloudConfig


@pytest.fixture
def scenarios_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "scenarios"


def test_load_all_five_scenarios_from_files(scenarios_dir: Path):
    scenario_files = [
        "01_secure.json",
        "02_public_ec2.json",
        "03_excessive_iam.json",
        "04_public_s3.json",
        "05_multistep_attack.json",
    ]
    for filename in scenario_files:
        path = scenarios_dir / filename
        assert path.exists(), f"Missing scenario file: {filename}"
        config = load_config(path)
        assert isinstance(config, CloudConfig)
        assert config.scenario_name == filename.replace(".json", "")
        assert 5 <= len(config.resources) <= 10
        # Verify an "internet" resource is present in every scenario
        assert any(r.type == "internet" for r in config.resources)


def test_load_config_from_dict():
    raw_dict = {
        "scenario_name": "test_dict",
        "resources": [
            {"id": "net-1", "type": "internet", "name": "Internet", "public": True},
            {"id": "ec2-1", "type": "ec2", "name": "AppServer", "public": False},
        ],
        "relationships": [
            {"source": "net-1", "target": "ec2-1", "type": "exposes"},
        ],
    }
    config = load_config(raw_dict)
    assert config.scenario_name == "test_dict"
    assert len(config.resources) == 2
    assert len(config.relationships) == 1


def test_load_config_from_json_string():
    raw_json = """
    {
        "scenario_name": "test_string",
        "resources": [
            {"id": "net-1", "type": "internet", "name": "Internet", "public": true}
        ],
        "relationships": []
    }
    """
    config = load_config(raw_json)
    assert config.scenario_name == "test_string"
    assert len(config.resources) == 1


def test_load_config_file_not_found():
    with pytest.raises(FileNotFoundError):
        load_config("data/scenarios/non_existent_scenario.json")


def test_load_config_invalid_json():
    with pytest.raises(ValueError, match="Invalid JSON"):
        load_config("not { valid json")


def test_load_config_invalid_input_type():
    with pytest.raises(ValueError):
        load_config(None)  # type: ignore

    with pytest.raises(ValueError):
        load_config([1, 2, 3])  # type: ignore


def test_load_config_invalid_resource_type():
    bad_data = {
        "scenario_name": "bad_res",
        "resources": [
            {"id": "x-1", "type": "invalid_resource_type", "name": "BadResource"}
        ],
        "relationships": [],
    }
    with pytest.raises(ValueError, match="Invalid resource type"):
        load_config(bad_data)


def test_load_config_invalid_relationship_type():
    bad_data = {
        "scenario_name": "bad_rel",
        "resources": [
            {"id": "r-1", "type": "ec2", "name": "R1"},
            {"id": "r-2", "type": "s3", "name": "R2"},
        ],
        "relationships": [
            {"source": "r-1", "target": "r-2", "type": "invalid_rel_type"}
        ],
    }
    with pytest.raises(ValueError, match="Invalid relationship type"):
        load_config(bad_data)


def test_load_config_missing_relationship_target():
    bad_data = {
        "scenario_name": "broken_ref",
        "resources": [
            {"id": "r-1", "type": "ec2", "name": "R1"},
        ],
        "relationships": [
            {"source": "r-1", "target": "non-existent-r2", "type": "connects_to"}
        ],
    }
    with pytest.raises(ValueError, match="Relationship target 'non-existent-r2' does not exist"):
        load_config(bad_data)


def test_load_config_duplicate_resource_ids():
    bad_data = {
        "scenario_name": "dup_ids",
        "resources": [
            {"id": "dup-id", "type": "ec2", "name": "VM1"},
            {"id": "dup-id", "type": "s3", "name": "Bucket1"},
        ],
        "relationships": [],
    }
    with pytest.raises(ValueError, match="Duplicate resource id"):
        load_config(bad_data)
