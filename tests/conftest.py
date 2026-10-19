"""Shared test fixtures for scoped-mcp tests."""

from __future__ import annotations

import socket

import pytest

from scoped_mcp.identity import AgentContext


@pytest.fixture(autouse=True)
def _no_value_redaction_leak():
    """Reset the process-wide by-value redaction set after every test.

    configure_logging() builds it from the real environment, and a set left behind by one
    test would silently redact strings in the next.
    """
    yield
    from scoped_mcp.audit import configure_value_redaction

    configure_value_redaction(environ={})


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


def _dragonfly_reachable() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 6379), timeout=1):
            return True
    except OSError:
        return False


@pytest.fixture
def dragonfly_backend():
    """DragonflyBackend connected to DB 15 on localhost:6379."""
    if not _dragonfly_reachable():
        pytest.skip("Dragonfly not available on localhost:6379")
    try:
        from scoped_mcp.state_dragonfly import DragonflyBackend
    except ImportError:
        pytest.skip("redis-py not installed — install scoped-mcp[dragonfly]")
    return DragonflyBackend(url="redis://localhost:6379/15", agent_id="test-agent")


@pytest.fixture
async def redis_client():
    """Raw aioredis client for DB 15 — for hitl_cli injection tests."""
    if not _dragonfly_reachable():
        pytest.skip("Dragonfly not available on localhost:6379")
    try:
        import redis.asyncio as aioredis
    except ImportError:
        pytest.skip("redis-py not installed — install scoped-mcp[dragonfly]")
    client = aioredis.from_url("redis://localhost:6379/15", decode_responses=True)
    yield client
    await client.aclose()
