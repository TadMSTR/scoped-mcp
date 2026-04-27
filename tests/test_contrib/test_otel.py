"""Tests for OtelMiddleware — verifies span creation and attribute population."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from scoped_mcp.contrib.otel import OtelMiddleware
from scoped_mcp.identity import AgentContext


@pytest.fixture
def agent_ctx():
    return AgentContext(agent_id="test-agent", agent_type="test")


@pytest.fixture
def mock_tracer():
    """Provide a mock OTel tracer that captures span interactions."""
    tracer = MagicMock()
    span = MagicMock()
    span.__enter__ = MagicMock(return_value=span)
    span.__exit__ = MagicMock(return_value=False)
    tracer.start_as_current_span.return_value = span
    return tracer, span


@pytest.mark.asyncio
async def test_otel_opens_span_per_call(agent_ctx, mock_tracer):
    """OtelMiddleware opens one span per tool call."""
    tracer, _span = mock_tracer
    with patch("scoped_mcp.contrib.otel.trace.get_tracer", return_value=tracer):
        mw = OtelMiddleware()
    handler = AsyncMock(return_value="ok")
    await mw(agent_ctx, "matrix_send_message", {}, handler)
    tracer.start_as_current_span.assert_called_once_with("matrix_send_message")


@pytest.mark.asyncio
async def test_otel_sets_standard_attributes(agent_ctx, mock_tracer):
    """OtelMiddleware sets agent.id, agent.type, and tool.name on the span."""
    tracer, span = mock_tracer
    with patch("scoped_mcp.contrib.otel.trace.get_tracer", return_value=tracer):
        mw = OtelMiddleware()
    await mw(agent_ctx, "matrix_send_message", {}, AsyncMock(return_value=None))
    attrs = {call.args[0]: call.args[1] for call in span.set_attribute.call_args_list}
    assert attrs["scoped_mcp.agent.id"] == "test-agent"
    assert attrs["scoped_mcp.agent.type"] == "test"
    assert attrs["scoped_mcp.tool.name"] == "matrix_send_message"


@pytest.mark.asyncio
async def test_otel_records_exception_on_error(agent_ctx, mock_tracer):
    """OtelMiddleware records exceptions and sets ERROR status."""
    tracer, span = mock_tracer
    with patch("scoped_mcp.contrib.otel.trace.get_tracer", return_value=tracer):
        mw = OtelMiddleware()
    err = RuntimeError("tool failed")
    with pytest.raises(RuntimeError):
        await mw(agent_ctx, "failing_tool", {}, AsyncMock(side_effect=err))
    span.record_exception.assert_called_once_with(err)


@pytest.mark.asyncio
async def test_otel_sets_ok_status_on_success(agent_ctx, mock_tracer):
    """OtelMiddleware sets OK status and call.status=ok on success."""

    tracer, span = mock_tracer
    with patch("scoped_mcp.contrib.otel.trace.get_tracer", return_value=tracer):
        mw = OtelMiddleware()
    await mw(agent_ctx, "some_tool", {}, AsyncMock(return_value="result"))

    attrs = {call.args[0]: call.args[1] for call in span.set_attribute.call_args_list}
    assert attrs["scoped_mcp.call.status"] == "ok"
    # Status was set (just verify set_status was called)
    span.set_status.assert_called_once()


@pytest.mark.asyncio
async def test_otel_returns_handler_result(agent_ctx, mock_tracer):
    """OtelMiddleware transparently returns the handler result."""
    tracer, _span = mock_tracer
    with patch("scoped_mcp.contrib.otel.trace.get_tracer", return_value=tracer):
        mw = OtelMiddleware()
    result = await mw(agent_ctx, "tool", {}, AsyncMock(return_value={"data": 42}))
    assert result == {"data": 42}


@pytest.mark.asyncio
async def test_otel_does_not_include_kwargs_in_span(agent_ctx, mock_tracer):
    """OtelMiddleware does not log kwargs (may contain credentials) as span attributes."""
    tracer, span = mock_tracer
    with patch("scoped_mcp.contrib.otel.trace.get_tracer", return_value=tracer):
        mw = OtelMiddleware()
    await mw(
        agent_ctx,
        "some_tool",
        {"secret_key": "s3cr3t", "content": "hello"},
        AsyncMock(return_value=None),
    )
    attr_keys = [call.args[0] for call in span.set_attribute.call_args_list]
    assert "secret_key" not in attr_keys
    assert "content" not in attr_keys
