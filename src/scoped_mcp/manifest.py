"""Manifest loading and validation.

Manifests are YAML (or JSON) files that declare which modules to load,
their mode (read/write), per-module config, and credential source.

The manifest is the source of truth — if a module isn't listed here,
the registry will not load it, even if it exists in the modules directory.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, field_validator, model_validator

from .exceptions import ManifestError


class CredentialSourceConfig(BaseModel):
    """Specifies where to read credentials from."""

    source: Literal["env", "file"] = "env"
    # Required when source == "file"
    path: str | None = None
    # Enforce mode 0600 + matching owner on the secrets file. Set to False
    # to downgrade the check to a warning (operator opt-out, audit M6).
    strict_permissions: bool = True

    @model_validator(mode="after")
    def _check_file_has_path(self) -> "CredentialSourceConfig":
        if self.source == "file" and not self.path:
            raise ValueError("credentials.path is required when source is 'file'")
        return self


class ModuleConfig(BaseModel):
    """Per-module configuration from the manifest."""

    # None means "all tools" (used for write-only notification modules)
    mode: Literal["read", "write"] | None = None
    config: dict[str, Any] = {}

    @field_validator("mode", mode="before")
    @classmethod
    def _normalise_mode(cls, v: Any) -> Any:
        if v == "":
            return None
        return v


class Manifest(BaseModel):
    """Top-level manifest model."""

    agent_type: str
    description: str = ""
    modules: dict[str, ModuleConfig]
    credentials: CredentialSourceConfig = CredentialSourceConfig()

    @field_validator("agent_type")
    @classmethod
    def _agent_type_nonempty(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("agent_type must not be empty")
        return v

    @field_validator("modules")
    @classmethod
    def _modules_nonempty(cls, v: dict) -> dict:
        if not v:
            raise ValueError("manifest must declare at least one module")
        return v


def load_manifest(path: str) -> Manifest:
    """Load and validate a manifest file (YAML or JSON).

    Raises ManifestError on file-not-found, parse errors, or validation failures.
    """
    manifest_path = Path(path)
    if not manifest_path.exists():
        raise ManifestError(f"Manifest file not found: {path}")

    try:
        raw = yaml.safe_load(manifest_path.read_text())
    except yaml.YAMLError as e:
        raise ManifestError(f"Failed to parse manifest '{path}': {e}") from e

    if not isinstance(raw, dict):
        raise ManifestError(f"Manifest '{path}' must be a YAML/JSON object at the top level")

    try:
        return Manifest.model_validate(raw)
    except Exception as e:
        raise ManifestError(f"Manifest '{path}' failed validation: {e}") from e
