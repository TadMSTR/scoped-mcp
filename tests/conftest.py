"""Shared test fixtures for scoped-mcp tests."""

from __future__ import annotations

import pytest

from scoped_mcp.identity import AgentContext


@pytest.fixture
def agent_ctx() -> AgentContext:
    """A default mock AgentContext for tests."""
    return AgentContext(agent_id="test-agent-1", agent_type="research")


@pytest.fixture
def other_agent_ctx() -> AgentContext:
    """A second agent — used in cross-agent isolation tests."""
    return AgentContext(agent_id="test-agent-2", agent_type="build")


@pytest.fixture
def mock_credentials() -> dict[str, str]:
    """Placeholder credentials that satisfy required_credentials checks."""
    return {
        "EXAMPLE_TOKEN": "EXAMPLE_TOKEN_VALUE",
        "EXAMPLE_URL": "http://test.localhost",
    }
