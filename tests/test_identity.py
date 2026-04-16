"""Tests for identity.py — AgentContext environment parsing."""

from __future__ import annotations

import pytest

from scoped_mcp.exceptions import ConfigError
from scoped_mcp.identity import AgentContext


def test_from_env_success(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_ID", "agent-abc")
    monkeypatch.setenv("AGENT_TYPE", "research")
    ctx = AgentContext.from_env()
    assert ctx.agent_id == "agent-abc"
    assert ctx.agent_type == "research"


def test_from_env_missing_agent_id(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_ID", raising=False)
    monkeypatch.setenv("AGENT_TYPE", "research")
    with pytest.raises(ConfigError, match="AGENT_ID"):
        AgentContext.from_env()


def test_from_env_missing_agent_type(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_ID", "agent-abc")
    monkeypatch.delenv("AGENT_TYPE", raising=False)
    with pytest.raises(ConfigError, match="AGENT_TYPE"):
        AgentContext.from_env()


def test_from_env_both_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_ID", raising=False)
    monkeypatch.delenv("AGENT_TYPE", raising=False)
    with pytest.raises(ConfigError):
        AgentContext.from_env()


def test_from_env_whitespace_only(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_ID", "   ")
    monkeypatch.setenv("AGENT_TYPE", "research")
    with pytest.raises(ConfigError, match="AGENT_ID"):
        AgentContext.from_env()


def test_agent_context_is_frozen() -> None:
    ctx = AgentContext(agent_id="agent-x", agent_type="build")
    with pytest.raises(Exception):
        ctx.agent_id = "modified"  # type: ignore[misc]
