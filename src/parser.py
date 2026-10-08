"""Parse simulated AWS-style JSON configs into Pydantic models."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Union

from .models import CloudConfig


def parse_config(source: Union[str, Path, dict]) -> CloudConfig:
    """Parse a JSON config from a file path, raw JSON string, or dict.

    Args:
        source: A file path (str/Path), a JSON string, or an already-parsed dict.

    Returns:
        A validated CloudConfig instance.
    """
    if isinstance(source, dict):
        return CloudConfig.model_validate(source)

    text = source
    if isinstance(source, Path) or (isinstance(source, str) and not source.lstrip().startswith("{")):
        path = Path(source)
        text = path.read_text(encoding="utf-8")

    data = json.loads(text)
    return CloudConfig.model_validate(data)
