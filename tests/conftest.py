"""Shared test fixtures."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from src.models import CloudConfig
from src.parser import parse_config


@pytest.fixture
def sample_config_path() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "sample_config.json"


@pytest.fixture
def sample_config(sample_config_path: Path) -> CloudConfig:
    return parse_config(sample_config_path)


@pytest.fixture
def sample_config_dict(sample_config_path: Path) -> dict:
    return json.loads(sample_config_path.read_text(encoding="utf-8"))
