"""OpenTelemetry middleware for scoped-mcp tool call tracing.

Emits one span per tool invocation. Span attributes:
    scoped_mcp.agent.id       — agent identifier
    scoped_mcp.agent.type     — agent type
    scoped_mcp.tool.name      — full namespaced tool name
    scoped_mcp.call.status    — "ok" | "error"

Tool arguments (kwargs) are intentionally excluded from span attributes to
prevent credential or sensitive data leakage to the OTLP collector endpoint.

Install the [otel] extra to use this:
    pip install scoped-mcp[otel]

The OtelMiddleware is auto-enabled when OTEL_EXPORTER_OTLP_ENDPOINT is set.
Configure the OTLP exporter via standard OTel SDK environment variables:
    OTEL_EXPORTER_OTLP_ENDPOINT=http://signoz-host:4317
    OTEL_EXPORTER_OTLP_ENDPOINT=https://otlp.langfuse.com  # Langfuse OTLP

For Langfuse, also set:
    OTEL_EXPORTER_OTLP_HEADERS=Authorization=Basic <base64-encoded key>

Note: when OTEL_EXPORTER_OTLP_ENDPOINT points to a cloud endpoint (e.g.
otlp.langfuse.com), span data including agent_id, agent_type, and tool names
is sent to that service. This is operational metadata, not PII. Tool arguments
are never included in spans.

Tool arguments are forwarded to the upstream server without validation —
upstream servers are responsible for their own input validation.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

_TRACER_NAME = "scoped_mcp"


class OtelMiddleware:
    """Emits an OTel span for every tool call passing through scoped-mcp."""

    def __init__(self, tracer_provider: Any = None) -> None:
        self._tracer = trace.get_tracer(
            _TRACER_NAME,
            tracer_provider=tracer_provider,
        )

    async def __call__(
        self,
        agent_ctx: Any,
        tool_name: str,
        kwargs: dict[str, Any],
        call_next: Callable,
    ) -> Any:
        with self._tracer.start_as_current_span(tool_name) as span:
            span.set_attribute("scoped_mcp.agent.id", agent_ctx.agent_id)
            span.set_attribute("scoped_mcp.agent.type", agent_ctx.agent_type)
            span.set_attribute("scoped_mcp.tool.name", tool_name)
            try:
                result = await call_next()
                span.set_status(Status(StatusCode.OK))
                span.set_attribute("scoped_mcp.call.status", "ok")
                return result
            except Exception as exc:
                span.record_exception(exc)
                span.set_status(Status(StatusCode.ERROR, str(exc)))
                span.set_attribute("scoped_mcp.call.status", "error")
                raise
