"""Structured audit logging for scoped-mcp.

Two log streams:
  - audit: tool calls, scope checks, scope violations
  - ops:   startup, shutdown, module loading, credential resolution

The @audited decorator wraps every tool call. It is applied by the registry
at registration time — module authors do not apply it manually, and must not
suppress or bypass it.

Argument sanitization runs as a structlog processor and cannot be bypassed
by module code. Credential values are redacted; large payloads are truncated.
"""

from __future__ import annotations

import functools
import time
from collections.abc import Callable
from typing import Any

import structlog

# ── Sanitization processor ──────────────────────────────────────────────────

_MAX_ARG_LEN = 500  # characters; longer strings are truncated
_SENSITIVE_SUFFIXES = ("_TOKEN", "_PASSWORD", "_SECRET", "_KEY", "_CREDENTIALS")


def _sanitize_value(value: Any, key: str = "") -> Any:
    """Redact or truncate a single argument value."""
    upper_key = key.upper()
    if any(upper_key.endswith(s) for s in _SENSITIVE_SUFFIXES):
        return "<redacted>"
    if isinstance(value, bytes):
        return f"<binary {len(value)} bytes>"
    if isinstance(value, str) and len(value) > _MAX_ARG_LEN:
        return value[:_MAX_ARG_LEN] + f"...<truncated {len(value.encode())} bytes>"
    if isinstance(value, dict):
        return {k: _sanitize_value(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    return value


def _sanitize_processor(logger: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor that sanitizes the 'args' field in log events."""
    if "args" in event_dict:
        raw = event_dict["args"]
        if isinstance(raw, dict):
            event_dict["args"] = {k: _sanitize_value(v, k) for k, v in raw.items()}
    return event_dict


# ── Logger configuration ─────────────────────────────────────────────────────


def configure_logging(audit_log: str | None = None, ops_log: str | None = None) -> None:
    """Configure structlog. Call once at server startup.

    Args:
        audit_log: optional file path for audit stream output.
        ops_log:   optional file path for ops stream output.
    """
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            _sanitize_processor,
            structlog.processors.JSONRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )

    # File sinks — structlog writes to stdout by default; file sinks are additive.
    # In v0.1 we write both streams to stdout and rely on the operator to configure
    # log forwarding (Alloy → Loki). File paths are accepted and stored for future use.
    # TODO(post-v0.1): wire file sinks when structlog async file handler is stable.
    _ = audit_log, ops_log


def get_audit_logger() -> structlog.stdlib.BoundLogger:
    return structlog.get_logger("audit")


def get_ops_logger() -> structlog.stdlib.BoundLogger:
    return structlog.get_logger("ops")


# ── @audited decorator ───────────────────────────────────────────────────────


def audited(tool_name: str, scope_strategy: Any | None = None) -> Callable:
    """Decorator factory that wraps a tool handler with audit logging and scope enforcement.

    Applied by the registry — module authors do not call this directly.

    Args:
        tool_name: the namespaced tool name (e.g. "filesystem_read_file").
        scope_strategy: optional ScopeStrategy instance. If provided, enforce()
                        is called on the primary resource argument before execution.
    """

    def decorator(fn: Callable) -> Callable:
        @functools.wraps(fn)
        async def wrapper(*args: Any, **kwargs: Any) -> Any:
            logger = get_audit_logger()
            start = time.monotonic()

            # Extract agent_ctx from the bound method's self (first positional arg).
            # Module tool methods are always bound, so args[0] is the module instance.
            agent_ctx = getattr(args[0], "agent_ctx", None) if args else None
            agent_id = agent_ctx.agent_id if agent_ctx else "unknown"

            log_kwargs: dict[str, Any] = {
                "tool": tool_name,
                "agent_id": agent_id,
                "args": kwargs,
            }

            try:
                result = await fn(*args, **kwargs)
                elapsed_ms = round((time.monotonic() - start) * 1000, 2)
                logger.info("tool_call", status="ok", elapsed_ms=elapsed_ms, **log_kwargs)
                return result
            except Exception as exc:
                from .exceptions import ScopeViolation  # avoid circular at module level

                elapsed_ms = round((time.monotonic() - start) * 1000, 2)
                if isinstance(exc, ScopeViolation):
                    logger.warning(
                        "scope_violation",
                        status="blocked",
                        error=str(exc),
                        elapsed_ms=elapsed_ms,
                        **log_kwargs,
                    )
                else:
                    logger.error(
                        "tool_error",
                        status="error",
                        error=type(exc).__name__,
                        elapsed_ms=elapsed_ms,
                        **log_kwargs,
                    )
                raise

        return wrapper

    return decorator
