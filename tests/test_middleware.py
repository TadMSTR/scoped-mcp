"""Tests for ToolCallMiddleware protocol and MiddlewareChain composition."""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from scoped_mcp.identity import AgentContext
from scoped_mcp.middleware import MiddlewareChain, ToolCallMiddleware


@pytest.fixture
def agent_ctx():
    return AgentContext(agent_id="test-agent", agent_type="test")


@pytest.mark.asyncio
async def test_middleware_chain_empty_calls_handler_directly(agent_ctx):
    """Empty middleware list passes through to the handler unchanged."""
    chain = MiddlewareChain([])
    handler = AsyncMock(return_value="direct_result")
    wrapped = chain.wrap("test_tool", handler, agent_ctx)

    result = await wrapped(foo="bar")

    handler.assert_awaited_once_with(foo="bar")
    assert result == "direct_result"


@pytest.mark.asyncio
async def test_middleware_chain_calls_middleware_in_order(agent_ctx):
    """Middleware is called in list order (first in, first wrapped)."""
    call_order = []

    class RecordingMiddleware:
        def __init__(self, name):
            self.name = name

        async def __call__(self, agent_ctx, tool_name, kwargs, call_next):
            call_order.append(f"before:{self.name}")
            result = await call_next()
            call_order.append(f"after:{self.name}")
            return result

    chain = MiddlewareChain([RecordingMiddleware("a"), RecordingMiddleware("b")])
    handler = AsyncMock(return_value="result")
    wrapped = chain.wrap("test_tool", handler, agent_ctx)

    result = await wrapped()

    assert result == "result"
    assert call_order == ["before:a", "before:b", "after:b", "after:a"]


@pytest.mark.asyncio
async def test_middleware_chain_propagates_exception(agent_ctx):
    """Exceptions from the handler propagate through the middleware chain."""

    class PassthroughMiddleware:
        async def __call__(self, agent_ctx, tool_name, kwargs, call_next):
            return await call_next()

    chain = MiddlewareChain([PassthroughMiddleware()])
    handler = AsyncMock(side_effect=ValueError("upstream error"))
    wrapped = chain.wrap("test_tool", handler, agent_ctx)

    with pytest.raises(ValueError, match="upstream error"):
        await wrapped()


@pytest.mark.asyncio
async def test_middleware_receives_correct_tool_name_and_kwargs(agent_ctx):
    """Middleware sees the namespaced tool name and the actual kwargs."""
    received = {}

    class InspectingMiddleware:
        async def __call__(self, agent_ctx, tool_name, kwargs, call_next):
            received["tool_name"] = tool_name
            received["kwargs"] = dict(kwargs)
            return await call_next()

    chain = MiddlewareChain([InspectingMiddleware()])
    handler = AsyncMock(return_value=None)
    wrapped = chain.wrap("matrix_send_message", handler, agent_ctx)
    await wrapped(room_id="!abc:test", content="hello")

    assert received["tool_name"] == "matrix_send_message"
    assert received["kwargs"] == {"room_id": "!abc:test", "content": "hello"}


def test_middleware_protocol_is_runtime_checkable(agent_ctx):
    """ToolCallMiddleware is @runtime_checkable — isinstance() works on callables."""

    class ValidMiddleware:
        async def __call__(self, agent_ctx, tool_name, kwargs, call_next):
            return await call_next()

    assert isinstance(ValidMiddleware(), ToolCallMiddleware)


@pytest.mark.asyncio
async def test_wrapped_callable_preserves_handler_name(agent_ctx):
    """chain.wrap() preserves the handler's __name__ on the returned callable."""

    async def my_tool_handler(**kwargs):
        return "result"

    chain = MiddlewareChain([])
    wrapped = chain.wrap("ns_my_tool_handler", my_tool_handler, agent_ctx)
    assert wrapped.__name__ == "my_tool_handler"
