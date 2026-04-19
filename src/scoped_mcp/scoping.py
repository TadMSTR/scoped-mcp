"""Scoping strategies for resource isolation between agents.

Scope enforcement is the security boundary of scoped-mcp. Every tool call
must pass through enforce() (or an equivalent allowlist / validation check)
before any backend operation. Do not bypass it.

Invariant: every tool method in a ToolModule subclass must call
``self.scoping.enforce(value, self.agent_ctx)`` on each argument that
addresses a backend resource — or, for modules that scope via an allowlist
rather than a transformable value (e.g. Grafana datasource names, SMTP
recipients, ntfy topics), validate the argument against that allowlist
before issuing the backend call. The ``@audited`` decorator applied by the
registry provides logging; it does NOT enforce scope. See ``AGENTS.md`` for
the module-author enforcement checklist.

Two built-in strategies are provided: ``PrefixScope`` (file-per-agent path
enforcement) and ``NamespaceScope`` (key-prefix enforcement for shared stores).
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
        root is treated as an escape attempt. For paths that don't yet exist,
        the resolve-nearest-ancestor fallback is followed by an explicit
        walk of each existing ancestor component looking for symlinks that
        escape (defense in depth for audit finding M8).
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
            ) from None

        self._check_ancestor_symlinks(Path(os.path.abspath(value)), agent_root, value, agent_ctx)

    @staticmethod
    def _check_ancestor_symlinks(
        abs_target: Path, agent_root: Path, orig_value: str, agent_ctx: AgentContext
    ) -> None:
        """Walk each existing component of ``abs_target`` under ``agent_root``
        and raise if any component is a symlink whose target escapes
        ``agent_root``. Protects against operator-seeded symlinks in the
        non-existent-tail case where the single ``resolve`` call would not
        traverse them.
        """
        try:
            relative = abs_target.relative_to(agent_root)
        except ValueError:
            return

        current = agent_root
        for part in relative.parts:
            current = current / part
            if not current.is_symlink() and not current.exists():
                return
            if current.is_symlink():
                resolved = current.resolve()
                try:
                    resolved.relative_to(agent_root)
                except ValueError:
                    raise ScopeViolation(
                        f"Path '{orig_value}' crosses a symlink at '{current}' that "
                        f"escapes the agent scope for '{agent_ctx.agent_id}'."
                    ) from None


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
