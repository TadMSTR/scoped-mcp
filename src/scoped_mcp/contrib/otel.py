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

import os
from collections.abc import Callable
from typing import Any

import structlog
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode

from ..audit import _redact_string

_TRACER_NAME = "scoped_mcp"
_log = structlog.get_logger("ops")


def _credential_gauge_values(health: dict) -> tuple[float, float]:
    """Map a credential_health() snapshot to (healthy_gauge, failures_gauge).

    Pure so the observable-gauge translation is unit-testable without an OTel SDK:
      * scoped_mcp.credentials.healthy  → 1.0 healthy / 0.0 degraded
      * scoped_mcp.vault.consecutive_renewal_failures → current failure streak
    """
    healthy = 1.0 if health.get("token_healthy", True) else 0.0
    failures = float(health.get("consecutive_failures", 0) or 0)
    return healthy, failures


def init_credential_metrics(
    credential_health_fn: Callable[[], dict],
    agent_id: str,
    agent_type: str,
    meter_provider: Any = None,
) -> bool:
    """Register OTel observable gauges for Vault credential health (L4 / SMCP-26).

    Two pull-based gauges observe ``credential_health_fn()`` on the SDK's collection
    schedule, so no per-event plumbing is needed and a SigNoz alert rule can fire on
    ``scoped_mcp.credentials.healthy == 0`` or a rising failure count. This is the
    durable, queryable second alert path that complements the Matrix ops-alert.

    Opt-in and degradeable exactly like the tracing path: returns False (no-op) if the
    OpenTelemetry metrics SDK or an OTLP metric exporter is unavailable, and never
    raises. Reuses an already-installed SDK MeterProvider; otherwise installs one wired
    to the standard ``OTEL_EXPORTER_OTLP_*`` environment. ``meter_provider`` may be passed
    to use an explicit provider instead of the process-global one (used by tests and any
    caller that manages its own provider).
    """
    try:
        from opentelemetry import metrics
        from opentelemetry.metrics import Observation
    except ImportError:
        return False

    provider = meter_provider
    if provider is None:
        try:
            provider = metrics.get_meter_provider()
            if "sdk" not in type(provider).__module__:
                from opentelemetry.sdk.metrics import MeterProvider
                from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader
                from opentelemetry.sdk.resources import Resource

                if os.environ.get("OTEL_EXPORTER_OTLP_PROTOCOL", "").startswith("http"):
                    from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
                        OTLPMetricExporter,
                    )
                else:
                    from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
                        OTLPMetricExporter,
                    )

                reader = PeriodicExportingMetricReader(OTLPMetricExporter())
                provider = MeterProvider(resource=Resource.create(), metric_readers=[reader])
                metrics.set_meter_provider(provider)
        except ImportError:
            return False

    meter = provider.get_meter(_TRACER_NAME)
    attributes = {"scoped_mcp.agent.id": agent_id, "scoped_mcp.agent.type": agent_type}

    def _safe_health() -> dict:
        try:
            return credential_health_fn()
        except Exception:
            # Never let a gauge callback raise into the SDK collector.
            return {"token_healthy": False, "consecutive_failures": 0}

    def _observe_healthy(_options: Any) -> list:
        healthy, _ = _credential_gauge_values(_safe_health())
        return [Observation(healthy, attributes)]

    def _observe_failures(_options: Any) -> list:
        _, failures = _credential_gauge_values(_safe_health())
        return [Observation(failures, attributes)]

    meter.create_observable_gauge(
        "scoped_mcp.credentials.healthy",
        callbacks=[_observe_healthy],
        description="1 when the Vault token is healthy, 0 when degraded",
    )
    meter.create_observable_gauge(
        "scoped_mcp.vault.consecutive_renewal_failures",
        callbacks=[_observe_failures],
        description="Consecutive Vault token renewal failures (0 when healthy)",
    )
    _log.info("credential_metrics_registered", agent_id=agent_id)
    return True


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
                span.add_event(
                    "exception",
                    attributes={
                        "exception.type": type(exc).__name__,
                        "exception.message": _redact_string(str(exc)),
                        "exception.stacktrace": "",
                    },
                )
                span.set_status(Status(StatusCode.ERROR, _redact_string(str(exc))))
                span.set_attribute("scoped_mcp.call.status", "error")
                raise
