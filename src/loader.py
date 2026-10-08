"""Loader module to parse, validate, and return CloudConfig scenarios."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Union

from pydantic import ValidationError

from .models import CloudConfig


def load_config(path_or_dict: Union[str, Path, dict[str, Any]]) -> CloudConfig:
    """Load, validate, and return a CloudConfig scenario.

    Accepts a filesystem Path, a path string, a JSON string, or a Python dict.
    Raises ValueError or FileNotFoundError with clear messages on invalid input.

    Args:
        path_or_dict: File path (str/Path), JSON string, or dict containing scenario data.

    Returns:
        Validated CloudConfig instance.

    Raises:
        FileNotFoundError: If a referenced configuration file does not exist.
        ValueError: If input format, JSON syntax, or scenario schema is invalid.
    """
    if path_or_dict is None:
        raise ValueError("Cannot load configuration from None.")

    data: Any = None

    if isinstance(path_or_dict, dict):
        data = path_or_dict

    elif isinstance(path_or_dict, Path):
        if not path_or_dict.is_file():
            raise FileNotFoundError(f"Configuration file not found: {path_or_dict}")
        try:
            content = path_or_dict.read_text(encoding="utf-8")
            data = json.loads(content)
        except json.JSONDecodeError as err:
            raise ValueError(f"Invalid JSON format in file '{path_or_dict}': {err}") from err

    elif isinstance(path_or_dict, str):
        trimmed = path_or_dict.strip()
        path = Path(path_or_dict)

        # Check if it's an existing file on the filesystem
        if path.is_file():
            try:
                content = path.read_text(encoding="utf-8")
                data = json.loads(content)
            except json.JSONDecodeError as err:
                raise ValueError(f"Invalid JSON format in file '{path_or_dict}': {err}") from err
        # If it contains JSON-like structure (e.g. braces, brackets, multiple lines)
        elif "{" in trimmed or "[" in trimmed or trimmed.endswith("}"):
            try:
                data = json.loads(trimmed)
            except json.JSONDecodeError as err:
                raise ValueError(f"Invalid JSON string format: {err}") from err
        elif trimmed.endswith(".json") or "/" in trimmed or "\\" in trimmed:
            raise FileNotFoundError(f"Configuration file not found: {path_or_dict}")
        else:
            try:
                data = json.loads(trimmed)
            except json.JSONDecodeError as err:
                raise FileNotFoundError(f"Configuration file not found: {path_or_dict}") from err

    else:
        raise ValueError(
            f"Expected a file path (str/Path), JSON string, or dict; got {type(path_or_dict).__name__}."
        )

    if not isinstance(data, dict):
        raise ValueError(
            f"Configuration data must be a JSON object (dict), got {type(data).__name__}."
        )

    try:
        return CloudConfig.model_validate(data)
    except ValidationError as err:
        errors = [
            f"- {' -> '.join(str(loc) for loc in e['loc'])}: {e['msg']}"
            for e in err.errors()
        ]
        raise ValueError(
            f"Scenario validation failed for configuration:\n" + "\n".join(errors)
        ) from err
