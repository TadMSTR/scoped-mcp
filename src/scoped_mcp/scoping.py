"""Scoping strategies for resource isolation between agents.

Scope enforcement is the security boundary of scoped-mcp. Every tool call
passes through enforce() before any backend operation. Do not bypass it.

Invariant: enforce() MUST be called before any backend operation. The
@audited decorator in audit.py calls enforce() — module authors do not
call it directly. This prevents accidental omission.
"""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from pathlib import Path

from .exceptions import ScopeViolation
from .identity import AgentContext


class ScopeStrategy(ABC):
    """Base class for scoping strategies."""

    @abstractmethod
    def apply(self, value: str, agent_ctx: AgentContext) -> str:
        """Transform a value to its scoped equivalent."""

    @abstractmethod
    def enforce(self, value: str, agent_ctx: AgentContext) -> None:
        """Raise ScopeViolation if value is outside the agent's scope."""


class PrefixScope(ScopeStrategy):
    """Path/key prefix enforcement.

    Ensures all paths resolve under agents/{agent_id}/ relative to a
    configured base path. Defends against traversal attacks and symlink escapes.
    """

    def __init__(self, base_path: str) -> None:
        self._base = Path(base_path).resolve()

    def _agent_root(self, agent_ctx: AgentContext) -> Path:
        return self._base / "agents" / agent_ctx.agent_id

    def apply(self, value: str, agent_ctx: AgentContext) -> str:
        """Return the scoped path for a relative value."""
        return str(self._agent_root(agent_ctx) / value)

    def enforce(self, value: str, agent_ctx: AgentContext) -> None:
        """Raise ScopeViolation if the path escapes the agent's root.

        Resolves symlinks before checking — a symlink pointing outside the
        root is treated as an escape attempt.
        """
        agent_root = self._agent_root(agent_ctx)
        target = Path(value)

        # Resolve to absolute path, following symlinks if the path exists.
        # If the path doesn't exist yet (e.g. a write target), resolve the
        # closest existing ancestor and reconstruct the full path.
        if target.exists():
            resolved = target.resolve()
        else:
            # Walk up to the first existing ancestor, resolve it, then reattach.
            parts = target.parts
            for i in range(len(parts), 0, -1):
                ancestor = Path(*parts[:i])
                if ancestor.exists():
                    resolved = ancestor.resolve() / Path(*parts[i:])
                    break
            else:
                resolved = Path(os.path.abspath(value))

        try:
            resolved.relative_to(agent_root)
        except ValueError:
            raise ScopeViolation(
                f"Path '{value}' is outside the agent scope for '{agent_ctx.agent_id}'. "
                f"Expected prefix: {agent_root}"
            )


class SchemaScope(ScopeStrategy):
    """Database schema restriction.

    Enforces that all table references belong to the agent's schema.
    SQL parsing (AST-level enforcement) is the responsibility of the
    sqlite module — this strategy provides the schema name and enforce check.
    """

    def apply(self, value: str, agent_ctx: AgentContext) -> str:
        """Return the schema name for this agent."""
        return f"agent_{agent_ctx.agent_id}"

    def enforce(self, value: str, agent_ctx: AgentContext) -> None:
        """Raise ScopeViolation if schema name does not match the agent's schema."""
        expected = self.apply("", agent_ctx)
        if value != expected:
            raise ScopeViolation(
                f"Schema '{value}' is outside the agent scope for '{agent_ctx.agent_id}'. "
                f"Expected: {expected}"
            )


class NamespaceScope(ScopeStrategy):
    """Key-value namespace prefixing.

    Prepends {agent_id}: to every key, ensuring agents cannot collide
    in shared key-value stores (InfluxDB buckets, cache keys, etc.).
    """

    def apply(self, value: str, agent_ctx: AgentContext) -> str:
        """Return the namespaced key."""
        return f"{agent_ctx.agent_id}:{value}"

    def enforce(self, value: str, agent_ctx: AgentContext) -> None:
        """Raise ScopeViolation if the key does not carry the agent's namespace prefix."""
        prefix = f"{agent_ctx.agent_id}:"
        if not value.startswith(prefix):
            raise ScopeViolation(
                f"Key '{value}' is outside the agent namespace for '{agent_ctx.agent_id}'. "
                f"Expected prefix: {prefix}"
            )
