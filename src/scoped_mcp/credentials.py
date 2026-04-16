"""Credential provider — reads secrets from env vars or a YAML secrets file.

Credential values are injected into module contexts at startup. They are
never logged, never returned in tool responses, and never exposed in error
messages (only the key name is referenced in errors, never the value).
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml

from .exceptions import CredentialError


def resolve_credentials(
    source: str,
    required_keys: list[str],
    file_path: str | None = None,
) -> dict[str, str]:
    """Resolve a list of credential keys from the configured source.

    Args:
        source: "env" to read from environment variables, "file" to read
                from a YAML secrets file.
        required_keys: list of credential key names to resolve.
        file_path: path to the YAML secrets file (required when source="file").

    Returns:
        Dict mapping key names to their resolved values.

    Raises:
        CredentialError: if a required key is missing or the source is misconfigured.
    """
    if source == "env":
        return _from_env(required_keys)
    elif source == "file":
        if not file_path:
            raise CredentialError("Credential source is 'file' but no path was provided")
        return _from_file(required_keys, file_path)
    else:
        raise CredentialError(f"Unknown credential source: '{source}'. Expected 'env' or 'file'")


def _from_env(keys: list[str]) -> dict[str, str]:
    result: dict[str, str] = {}
    missing: list[str] = []

    for key in keys:
        value = os.environ.get(key)
        if value is None:
            missing.append(key)
        else:
            result[key] = value

    if missing:
        raise CredentialError(f"Missing required environment variable(s): {', '.join(missing)}")

    return result


def _from_file(keys: list[str], file_path: str) -> dict[str, str]:
    path = Path(file_path)
    if not path.exists():
        raise CredentialError(f"Secrets file not found: {file_path}")

    try:
        raw: Any = yaml.safe_load(path.read_text())
    except yaml.YAMLError as e:
        raise CredentialError(f"Failed to parse secrets file '{file_path}': {e}") from e

    if not isinstance(raw, dict):
        raise CredentialError(f"Secrets file '{file_path}' must be a YAML mapping at the top level")

    result: dict[str, str] = {}
    missing: list[str] = []

    for key in keys:
        if key not in raw:
            missing.append(key)
        else:
            result[key] = str(raw[key])

    if missing:
        raise CredentialError(f"Missing credential key(s) in '{file_path}': {', '.join(missing)}")

    return result
