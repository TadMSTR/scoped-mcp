"""Tests for scoping.py — PrefixScope, NamespaceScope.

Scoping tests are the most critical tests in this repo. They verify that
the security boundary holds under normal use AND adversarial inputs.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scoped_mcp.exceptions import ScopeViolation
from scoped_mcp.identity import AgentContext
from scoped_mcp.scoping import NamespaceScope, PrefixScope

# ── PrefixScope ───────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_base(tmp_path: Path) -> Path:
    """A temporary base directory for PrefixScope tests."""
    (tmp_path / "agents" / "test-agent-1").mkdir(parents=True)
    (tmp_path / "agents" / "test-agent-2").mkdir(parents=True)
    return tmp_path


def test_prefix_scope_apply(tmp_base: Path, agent_ctx: AgentContext) -> None:
    scope = PrefixScope(str(tmp_base))
    scoped = scope.apply("notes/file.txt", agent_ctx)
    assert scoped == str(tmp_base / "agents" / "test-agent-1" / "notes" / "file.txt")


def test_prefix_scope_enforce_valid(tmp_base: Path, agent_ctx: AgentContext) -> None:
    scope = PrefixScope(str(tmp_base))
    valid_path = str(tmp_base / "agents" / "test-agent-1" / "file.txt")
    # Should not raise
    scope.enforce(valid_path, agent_ctx)


def test_prefix_scope_enforce_cross_agent(
    tmp_base: Path, agent_ctx: AgentContext, other_agent_ctx: AgentContext
) -> None:
    scope = PrefixScope(str(tmp_base))
    other_path = str(tmp_base / "agents" / "test-agent-2" / "secret.txt")
    with pytest.raises(ScopeViolation):
        scope.enforce(other_path, agent_ctx)


def test_prefix_scope_dotdot_traversal(tmp_base: Path, agent_ctx: AgentContext) -> None:
    scope = PrefixScope(str(tmp_base))
    traversal = str(tmp_base / "agents" / "test-agent-1" / ".." / ".." / "etc" / "passwd")
    with pytest.raises(ScopeViolation):
        scope.enforce(traversal, agent_ctx)


def test_prefix_scope_absolute_escape(tmp_base: Path, agent_ctx: AgentContext) -> None:
    scope = PrefixScope(str(tmp_base))
    with pytest.raises(ScopeViolation):
        scope.enforce("/etc/passwd", agent_ctx)


def test_prefix_scope_symlink_escape(tmp_base: Path, agent_ctx: AgentContext) -> None:
    """A symlink inside the agent root pointing outside must be blocked."""
    agent_root = tmp_base / "agents" / "test-agent-1"
    outside_dir = tmp_base / "outside"
    outside_dir.mkdir()
    (outside_dir / "secret.txt").write_text("sensitive")

    link = agent_root / "escape_link"
    link.symlink_to(outside_dir)

    scope = PrefixScope(str(tmp_base))
    with pytest.raises(ScopeViolation):
        scope.enforce(str(link / "secret.txt"), agent_ctx)


def test_prefix_scope_write_target_nonexistent(tmp_base: Path, agent_ctx: AgentContext) -> None:
    """Enforce should work for paths that don't exist yet (e.g. write targets)."""
    scope = PrefixScope(str(tmp_base))
    new_file = str(tmp_base / "agents" / "test-agent-1" / "new_dir" / "new_file.txt")
    # Should not raise — path is within scope even if it doesn't exist yet
    scope.enforce(new_file, agent_ctx)


def test_prefix_scope_symlink_ancestor_with_nonexistent_tail(
    tmp_base: Path, agent_ctx: AgentContext
) -> None:
    """M8: operator-seeded symlink to an existing directory, with a non-existent tail.

    ``link`` exists, so the first check resolves it and rejects the path before the
    ancestor walk runs. The dangling-link case below is the one only the walk catches.
    """
    agent_root = tmp_base / "agents" / "test-agent-1"
    outside_dir = tmp_base / "outside"
    outside_dir.mkdir()

    link = agent_root / "escape_link"
    link.symlink_to(outside_dir)

    scope = PrefixScope(str(tmp_base))
    new_path = str(link / "new_file.txt")
    # Match the message, not "symlink": pytest names tmp_path after the test, so that
    # word is in the path and would match any error (vikunja#1219).
    with pytest.raises(ScopeViolation, match="is outside the agent scope"):
        scope.enforce(new_path, agent_ctx)


def test_prefix_scope_dangling_symlink_ancestor_is_caught(
    tmp_base: Path, agent_ctx: AgentContext
) -> None:
    """M8, the case only the ancestor walk catches (vikunja#1219).

    A dangling link does not exist(), so the first check resolves the agent root and
    reattaches ``pending/payload.txt`` under it, which passes. Writing there would
    create ``outside/not-yet/payload.txt``.
    """
    agent_root = tmp_base / "agents" / "test-agent-1"
    outside = tmp_base / "outside"
    outside.mkdir()
    link = agent_root / "pending"
    link.symlink_to(outside / "not-yet")
    assert not link.exists()  # dangling

    scope = PrefixScope(str(tmp_base))
    with pytest.raises(ScopeViolation, match="crosses a symlink at"):
        scope.enforce(str(link / "payload.txt"), agent_ctx)


# ── NamespaceScope ────────────────────────────────────────────────────────────


def test_namespace_scope_apply(agent_ctx: AgentContext) -> None:
    scope = NamespaceScope()
    assert scope.apply("mykey", agent_ctx) == "test-agent-1:mykey"


def test_namespace_scope_enforce_valid(agent_ctx: AgentContext) -> None:
    scope = NamespaceScope()
    scope.enforce("test-agent-1:mykey", agent_ctx)


def test_namespace_scope_enforce_wrong_prefix(agent_ctx: AgentContext) -> None:
    scope = NamespaceScope()
    with pytest.raises(ScopeViolation):
        scope.enforce("test-agent-2:mykey", agent_ctx)


def test_namespace_scope_enforce_no_prefix(agent_ctx: AgentContext) -> None:
    scope = NamespaceScope()
    with pytest.raises(ScopeViolation):
        scope.enforce("mykey", agent_ctx)
