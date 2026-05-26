"""Pre-call hook registry for scoped-mcp.

Hooks fire before forwarding specific tool calls through mcp_proxy, allowing
infrastructure-level interception without changes to agent code.

Current use: agent-bus signing hook (Phase 2b) — signs log_event payloads
with the agent's ed25519 private key before the call reaches agent-bus.

Future use: Langfuse trace ID injection, per-call rate telemetry, etc.

API::

    from scoped_mcp.hooks import register_before, run_before_hooks

    # Register a hook at startup (e.g. in server.py):
    register_before("agent-bus", "log_event", sign_event_hook)

    # Fire hooks before forwarding (called by mcp_proxy._make_proxy_method):
    kwargs = await run_before_hooks("agent-bus", "log_event", kwargs)

Hook handler signature::

    async def handler(kwargs: dict) -> dict:
        # Inspect or modify kwargs; return the (possibly modified) dict.
        ...

Handlers are called in registration order. Each receives the output of the
previous handler. An exception in a handler propagates to the caller — hooks
are not fire-and-forget.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

# Maps (server_name, tool_name) → ordered list of async callables.
_registry: dict[tuple[str, str], list[Callable[..., Any]]] = {}


def register_before(server: str, tool: str, handler: Callable[..., Any]) -> None:
    """Register an async pre-call hook for a specific server+tool combination.

    Args:
        server: manifest key of the target mcp_proxy module (e.g. "agent-bus").
        tool:   upstream tool name (e.g. "log_event").
        handler: ``async def handler(kwargs: dict) -> dict`` callable.
    """
    key = (server, tool)
    _registry.setdefault(key, []).append(handler)


async def run_before_hooks(server: str, tool: str, kwargs: dict[str, Any]) -> dict[str, Any]:
    """Run all registered pre-call hooks for server+tool in order.

    Returns the final kwargs dict (possibly modified by hooks). If no hooks
    are registered for this combination, returns kwargs unchanged.

    Args:
        server: manifest key of the mcp_proxy module.
        tool:   upstream tool name being called.
        kwargs: current call kwargs.

    Returns:
        kwargs after all hooks have run.
    """
    handlers = _registry.get((server, tool), [])
    for handler in handlers:
        kwargs = await handler(kwargs)
    return kwargs


def clear_hooks() -> None:
    """Remove all registered hooks. Intended for use in tests only."""
    _registry.clear()
