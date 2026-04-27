"""Shared exception types for scoped-mcp."""


class ConfigError(Exception):
    """Raised when required configuration is missing or invalid."""


class CredentialError(Exception):
    """Raised when a required credential is missing or cannot be resolved."""


class ManifestError(Exception):
    """Raised when a manifest fails validation."""


class ScopeViolation(Exception):
    """Raised when a tool call attempts to access resources outside its scope."""


class HitlRejectedError(Exception):
    """Raised when a tool call is rejected via HITL approval (explicit reject or timeout)."""
