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
    """OtelMiddleware emits an exception event via add_event (not record_exception)."""
    tracer, span = mock_tracer
    with patch("scoped_mcp.contrib.otel.trace.get_tracer", return_value=tracer):
        mw = OtelMiddleware()
    err = RuntimeError("tool failed")
    with pytest.raises(RuntimeError):
        await mw(agent_ctx, "failing_tool", {}, AsyncMock(side_effect=err))
    span.add_event.assert_called_once()
    event_name, event_kwargs = span.add_event.call_args[0][0], span.add_event.call_args[1]
    assert event_name == "exception"
    attrs = event_kwargs["attributes"]
    assert attrs["exception.type"] == "RuntimeError"
    assert "tool failed" in attrs["exception.message"]
    assert "exception.stacktrace" in attrs
    # record_exception must NOT be called (it emits raw unredacted exception.message)
    span.record_exception.assert_not_called()


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


@pytest.mark.asyncio
async def test_otel_redacts_exception_message_in_status(agent_ctx, mock_tracer):
    """Error span status description has sensitive patterns redacted."""
    tracer, span = mock_tracer
    with patch("scoped_mcp.contrib.otel.trace.get_tracer", return_value=tracer):
        mw = OtelMiddleware()
    # A bearer token in the exception message should be redacted from the span status
    err = RuntimeError("upstream rejected: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.x.y")
    with pytest.raises(RuntimeError):
        await mw(agent_ctx, "failing_tool", {}, AsyncMock(side_effect=err))
    # set_status was called; its description should not contain the raw bearer token
    call_args = span.set_status.call_args[0][0]  # the Status object
    status_desc = call_args.description or ""
    assert "Bearer eyJ" not in status_desc


# ── L4: credential-health metrics (SMCP-26) ───────────────────────────────────


def test_credential_gauge_values_healthy() -> None:
    from scoped_mcp.contrib.otel import _credential_gauge_values

    healthy, failures = _credential_gauge_values({"token_healthy": True, "consecutive_failures": 0})
    assert healthy == 1.0
    assert failures == 0.0


def test_credential_gauge_values_degraded() -> None:
    from scoped_mcp.contrib.otel import _credential_gauge_values

    healthy, failures = _credential_gauge_values(
        {"token_healthy": False, "consecutive_failures": 5}
    )
    assert healthy == 0.0
    assert failures == 5.0


def test_credential_gauge_values_missing_keys_default_healthy() -> None:
    from scoped_mcp.contrib.otel import _credential_gauge_values

    # A partial snapshot must not raise; absent token_healthy defaults to healthy.
    healthy, failures = _credential_gauge_values({})
    assert healthy == 1.0
    assert failures == 0.0


def test_init_credential_metrics_registers_and_observes() -> None:
    """With an in-memory reader, both gauges register and observe live values."""
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader

    from scoped_mcp.contrib.otel import init_credential_metrics

    # Inject an explicit provider — set_meter_provider is process-global and one-shot,
    # so tests must not mutate it.
    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])

    state = {"token_healthy": False, "consecutive_failures": 3}
    ok = init_credential_metrics(lambda: dict(state), "agent-x", "dev", meter_provider=provider)
    assert ok is True

    data = reader.get_metrics_data()
    seen: dict[str, float] = {}
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                for point in metric.data.data_points:
                    seen[metric.name] = point.value

    assert seen["scoped_mcp.credentials.healthy"] == 0.0
    assert seen["scoped_mcp.vault.consecutive_renewal_failures"] == 3.0


def test_init_credential_metrics_callback_survives_bad_health_fn() -> None:
    """A raising health function must not break metric collection."""
    from opentelemetry.sdk.metrics import MeterProvider
    from opentelemetry.sdk.metrics.export import InMemoryMetricReader

    from scoped_mcp.contrib.otel import init_credential_metrics

    reader = InMemoryMetricReader()
    provider = MeterProvider(metric_readers=[reader])

    def _boom() -> dict:
        raise RuntimeError("vault source exploded")

    assert init_credential_metrics(_boom, "agent-x", "dev", meter_provider=provider) is True
    # Collection must not raise even though the health fn does; the gauge falls back
    # to a degraded reading rather than propagating the exception.
    data = reader.get_metrics_data()
    seen: dict[str, float] = {}
    for rm in data.resource_metrics:
        for sm in rm.scope_metrics:
            for metric in sm.metrics:
                for point in metric.data.data_points:
                    seen[metric.name] = point.value
    assert seen["scoped_mcp.credentials.healthy"] == 0.0
