"""Tests for modules/_base.py — ToolModule lifecycle hooks."""

from __future__ import annotations

from typing import ClassVar

import pytest

from scoped_mcp.identity import AgentContext
from scoped_mcp.modules._base import ToolModule


class _ConcreteModule(ToolModule):
    """Minimal concrete subclass for testing the base class interface."""

    name = "test_module"
    required_credentials: ClassVar[list[str]] = []

    def get_tool_methods(self, mode):
        return []


@pytest.fixture
def concrete_module():
    ctx = AgentContext(agent_id="test-agent", agent_type="test")
    return _ConcreteModule(agent_ctx=ctx, credentials={}, config={})


@pytest.mark.asyncio
async def test_base_startup_is_noop(concrete_module):
    """startup() default implementation does nothing and returns None."""
    result = await concrete_module.startup()
    assert result is None


@pytest.mark.asyncio
async def test_base_shutdown_is_noop(concrete_module):
    """shutdown() default implementation does nothing and returns None."""
    result = await concrete_module.shutdown()
    assert result is None
