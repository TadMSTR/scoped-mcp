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


# ── M5: agent_id / agent_type format validation ──────────────────────────────


@pytest.mark.parametrize(
    "bad_id",
    [
        "agent/bad",
        "../escape",
        "agent with space",
        "UPPERCASE",
        "-leadinghyphen",
        "a" * 64,  # over 63 chars
        "bad.id",
        "bad_id",  # underscore not allowed in agent_id
    ],
)
def test_from_env_rejects_bad_agent_id(monkeypatch: pytest.MonkeyPatch, bad_id: str) -> None:
    monkeypatch.setenv("AGENT_ID", bad_id)
    monkeypatch.setenv("AGENT_TYPE", "research")
    with pytest.raises(ConfigError, match="AGENT_ID"):
        AgentContext.from_env()


@pytest.mark.parametrize(
    "bad_type",
    [
        "research/pipeline",
        "has space",
        "UPPERCASE",
        "-leadinghyphen",
        "a" * 64,
    ],
)
def test_from_env_rejects_bad_agent_type(monkeypatch: pytest.MonkeyPatch, bad_type: str) -> None:
    monkeypatch.setenv("AGENT_ID", "agent-01")
    monkeypatch.setenv("AGENT_TYPE", bad_type)
    with pytest.raises(ConfigError, match="AGENT_TYPE"):
        AgentContext.from_env()


@pytest.mark.parametrize(
    "good_id, good_type",
    [
        ("a", "a"),
        ("agent-01", "research"),
        ("01-agent", "build-1"),
        ("a" * 63, "a" * 63),
        ("agent-01", "build_pipeline"),
    ],
)
def test_from_env_accepts_valid_ids(
    monkeypatch: pytest.MonkeyPatch, good_id: str, good_type: str
) -> None:
    monkeypatch.setenv("AGENT_ID", good_id)
    monkeypatch.setenv("AGENT_TYPE", good_type)
    ctx = AgentContext.from_env()
    assert ctx.agent_id == good_id
    assert ctx.agent_type == good_type
