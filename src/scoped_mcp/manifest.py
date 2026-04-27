"""Manifest loading and validation.

Manifests are YAML (or JSON) files that declare which modules to load,
their mode (read/write), per-module config, and credential source.

The manifest is the source of truth — if a module isn't listed here,
the registry will not load it, even if it exists in the modules directory.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, field_validator, model_validator

from .exceptions import ManifestError

# Pattern for valid agent_type values.
_AGENT_TYPE_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,62}$")

# Rate limit spec format: "<N>/<unit>" e.g. "100/minute", "50/hour", "10/second".
_RATE_LIMIT_RE = re.compile(r"^\d+/(second|minute|hour)$")

# Module config fields that are actually required (cause an error at module __init__ if absent).
# Keys in this dict must match the actual validation in each module's __init__.
_MODULE_REQUIRED_KEYS: dict[str, list[str]] = {
    "filesystem": ["base_path"],
    "sqlite": ["db_dir"],
    "http_proxy": ["allowed_services"],
    "smtp": ["from_address", "allowed_recipients"],
    "matrix": ["allowed_rooms"],
    # mcp_proxy requires url OR command — validated separately in _validate_module_configs
}


class VaultConfig(BaseModel):
    """HashiCorp Vault auth and path config (used when credentials.source == 'vault')."""

    model_config = ConfigDict(extra="forbid")

    addr: str
    auth: Literal["approle"] = "approle"
    role_id_env: str = "VAULT_ROLE_ID"
    secret_id_env: str = "VAULT_SECRET_ID"
    path: str
    kv_version: int = 2


class CredentialSourceConfig(BaseModel):
    """Specifies where to read credentials from."""

    model_config = ConfigDict(extra="forbid")

    source: Literal["env", "file", "vault"] = "env"
    # Required when source == "file"
    path: str | None = None
    # Required when source == "vault"
    vault: VaultConfig | None = None
    # Enforce mode 0600 + matching owner on the secrets file. Set to False
    # to downgrade the check to a warning (operator opt-out, audit M6).
    strict_permissions: bool = True

    @model_validator(mode="after")
    def _check_source_requirements(self) -> CredentialSourceConfig:
        if self.source == "file" and not self.path:
            raise ValueError("credentials.path is required when source is 'file'")
        if self.source == "vault" and not self.vault:
            raise ValueError(
                "credentials.vault (addr, auth, path) is required when source is 'vault'"
            )
        return self


class StateBackendConfig(BaseModel):
    """Config for the shared state backend (rate limiting, HITL)."""

    model_config = ConfigDict(extra="forbid")

    type: Literal["in_process", "dragonfly"] = "in_process"
    # Required when type == "dragonfly"
    url: str | None = None

    @model_validator(mode="after")
    def _check_dragonfly_url(self) -> StateBackendConfig:
        if self.type == "dragonfly" and not self.url:
            raise ValueError("state_backend.url is required when type is 'dragonfly'")
        return self


class RateLimitsConfig(BaseModel):
    """Rate limit declarations from the manifest."""

    model_config = ConfigDict(extra="forbid")

    # Catch-all global limit across all tools for this agent
    global_limit: str | None = None
    # Per-tool limits (supports glob patterns like "mcp_proxy.*")
    per_tool: dict[str, str] = {}

    @model_validator(mode="before")
    @classmethod
    def _extract_global(cls, data: Any) -> Any:
        # "global" is a Python keyword; map it to global_limit
        if isinstance(data, dict) and "global" in data:
            data = dict(data)
            data["global_limit"] = data.pop("global")
        return data

    @field_validator("global_limit", mode="before")
    @classmethod
    def _validate_global(cls, v: Any) -> Any:
        if v is not None and not _RATE_LIMIT_RE.match(str(v)):
            raise ValueError(f"rate_limits.global must be '<N>/second|minute|hour', got {v!r}")
        return v

    @field_validator("per_tool", mode="before")
    @classmethod
    def _validate_per_tool(cls, v: Any) -> Any:
        if not isinstance(v, dict):
            return v
        for key, val in v.items():
            if not _RATE_LIMIT_RE.match(str(val)):
                raise ValueError(
                    f"rate_limits.per_tool[{key!r}] must be '<N>/second|minute|hour', got {val!r}"
                )
        return v


class ArgumentFilterRule(BaseModel):
    """A single argument-content filter rule from the manifest."""

    model_config = ConfigDict(extra="forbid")

    name: str
    pattern: str
    fields: list[str] = ["*"]
    action: Literal["block", "warn"] = "block"
    decode: list[Literal["base64", "url"]] = []
    case_insensitive: bool = False

    @field_validator("fields")
    @classmethod
    def _fields_nonempty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("argument_filters[*].fields must not be empty")
        return v

    @field_validator("pattern")
    @classmethod
    def _pattern_compiles(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as e:
            raise ValueError(f"argument_filters[*].pattern is not a valid regex: {e}") from e
        return v


class ModuleConfig(BaseModel):
    """Per-module configuration from the manifest."""

    model_config = ConfigDict(extra="forbid")

    # None means "all tools" (used for write-only notification modules)
    mode: Literal["read", "write"] | None = None
    # Optional: override the class looked up by manifest key.
    # Use when multiple instances of the same module class are needed.
    # Example: type: mcp_proxy with key: task-queue and key: agent-bus
    type: str | None = None
    config: dict[str, Any] = {}

    @field_validator("mode", mode="before")
    @classmethod
    def _normalise_mode(cls, v: Any) -> Any:
        if v == "":
            return None
        return v


class Manifest(BaseModel):
    """Top-level manifest model."""

    model_config = ConfigDict(extra="forbid")

    agent_type: str
    description: str = ""
    modules: dict[str, ModuleConfig]
    credentials: CredentialSourceConfig = CredentialSourceConfig()
    state_backend: StateBackendConfig = StateBackendConfig()
    rate_limits: RateLimitsConfig | None = None
    argument_filters: list[ArgumentFilterRule] | None = None

    @field_validator("agent_type")
    @classmethod
    def _agent_type_pattern(cls, v: str) -> str:
        if not _AGENT_TYPE_RE.match(v):
            raise ValueError(f"agent_type must match ^[a-z0-9][a-z0-9_-]{{0,62}}$, got {v!r}")
        return v

    @field_validator("modules")
    @classmethod
    def _modules_nonempty(cls, v: dict) -> dict:
        if not v:
            raise ValueError("manifest must declare at least one module")
        return v

    @model_validator(mode="after")
    def _validate_module_configs(self) -> Manifest:
        errors: list[str] = []
        for key, mod_cfg in self.modules.items():
            # Resolve the actual module name (type: field overrides the key)
            module_name = mod_cfg.type or key
            required = _MODULE_REQUIRED_KEYS.get(module_name, [])
            for field in required:
                if not mod_cfg.config.get(field):
                    errors.append(
                        f"modules.{key}: missing required config field '{field}'"
                        f" (required for '{module_name}' module)"
                    )
            # mcp_proxy requires url OR command (not both, not neither)
            has_connection = mod_cfg.config.get("url") or mod_cfg.config.get("command")
            if module_name == "mcp_proxy" and not has_connection:
                errors.append(
                    f"modules.{key}: mcp_proxy requires either 'url' (HTTP) or"
                    " 'command' (stdio) in config"
                )
        if errors:
            raise ValueError("\n".join(errors))
        return self


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
