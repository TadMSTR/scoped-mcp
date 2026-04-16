"""Structured audit logging for scoped-mcp.

Two log streams:
  - audit: tool calls, scope checks, scope violations
  - ops:   startup, shutdown, module loading, credential resolution

The @audited decorator wraps every tool call for logging. It is applied by
the registry at registration time — module authors do not apply it manually,
and must not suppress or bypass it. @audited does NOT enforce scope; each
module is responsible for calling its own ``scoping.enforce()`` (or an
equivalent allowlist / validation check) inside every tool method. See
``AGENTS.md`` for the module-author enforcement checklist.

Argument sanitization runs as a structlog processor and cannot be bypassed
by module code. Credential values are redacted; large payloads are truncated.
"""

from __future__ import annotations

import functools
import re
import time
from collections.abc import Callable
from typing import Any

import structlog

# ── Sanitization processor ──────────────────────────────────────────────────

_MAX_ARG_LEN = 500  # characters; longer strings are truncated
_SENSITIVE_SUFFIXES = (
    "_TOKEN",
    "_PASSWORD",
    "_SECRET",
    "_KEY",
    "_CREDENTIALS",
    "_PWD",
    "_PASS",
    "_AUTH",
)
_SENSITIVE_KEYS = frozenset(
    {
        "authorization",
        "cookie",
        "session",
        "bearer",
        "password",
        "passwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "access_token",
        "refresh_token",
    }
)
# Log-event top-level keys whose value is operational metadata, not user-supplied
# data, and must never be redacted by the key-match pass (e.g. a log record whose
# ``event`` field is literally ``"scope_violation"`` or an arg named ``token``
# labelled via ``key``).
_PRESERVE_KEYS = frozenset({"event", "logger", "level", "timestamp", "status"})

# Pattern-based redaction — applied to every string value regardless of key name.
# Keeps tokens out of logs when they appear embedded in error strings,
# user-supplied URLs, free-form messages, etc.
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}")
_LONG_HEX_RE = re.compile(r"\b[A-Fa-f0-9]{32,}\b")
_GH_PAT_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b")


def _redact_string(s: str) -> str:
    """Apply pattern-based redaction to a single string."""
    s = _JWT_RE.sub("<redacted-jwt>", s)
    s = _BEARER_RE.sub("<redacted-bearer>", s)
    s = _GH_PAT_RE.sub("<redacted-gh-token>", s)
    s = _LONG_HEX_RE.sub("<redacted-hex>", s)
    return s


def _key_looks_sensitive(key: str) -> bool:
    lower = key.lower()
    upper = key.upper()
    if lower in _SENSITIVE_KEYS:
        return True
    return any(upper.endswith(s) for s in _SENSITIVE_SUFFIXES)


def _sanitize_value(value: Any, key: str = "") -> Any:
    """Redact or truncate a single argument value."""
    if key and _key_looks_sensitive(key):
        return "<redacted>"
    if isinstance(value, bytes):
        return f"<binary {len(value)} bytes>"
    if isinstance(value, str):
        redacted = _redact_string(value)
        if len(redacted) > _MAX_ARG_LEN:
            return redacted[:_MAX_ARG_LEN] + f"...<truncated {len(redacted.encode())} bytes>"
        return redacted
    if isinstance(value, dict):
        return {k: _sanitize_value(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize_value(v) for v in value]
    return value


def _sanitize_processor(logger: Any, method: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """structlog processor that sanitizes every field in log events.

    Applied to the whole event_dict, not just the ``args`` sub-mapping, so
    credential values leaking into ``error``, ``detail``, or any other key
    are still caught. ``event``/``level``/``logger``/``timestamp``/``status``
    are preserved so they cannot be silently clobbered.
    """
    for k, v in list(event_dict.items()):
        if k in _PRESERVE_KEYS:
            continue
        event_dict[k] = _sanitize_value(v, k)
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


def audited(tool_name: str) -> Callable:
    """Decorator factory that wraps a tool handler with audit logging.

    Applied by the registry — module authors do not call this directly.
    Scope enforcement is the module's responsibility (see ``AGENTS.md``);
    ``@audited`` does not call ``scope_strategy.enforce()``.

    Args:
        tool_name: the namespaced tool name (e.g. "filesystem_read_file").
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
