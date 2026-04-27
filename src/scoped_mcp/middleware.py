"""Tool call middleware protocol and chain composition for scoped-mcp.

Middleware intercepts every tool invocation at the registry level, after
scoping is applied and before the actual tool function executes.

Usage:
    from scoped_mcp.middleware import MiddlewareChain
    from scoped_mcp.contrib.otel import OtelMiddleware

    server = build_server(
        agent_ctx, manifest,
        middleware=[OtelMiddleware()],
    )

Protocol:
    Each middleware is an async callable:
        async def __call__(agent_ctx, tool_name, kwargs, call_next) -> Any

    It must call ``await call_next()`` exactly once to continue the chain.
    Omitting the call silently short-circuits the chain — subsequent middleware
    and the tool handler will not run.
    The return value of ``call_next()`` is the tool's result.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any, Protocol, runtime_checkable


@runtime_checkable
class ToolCallMiddleware(Protocol):
    """Intercept a tool call. Call ``await call_next()`` to continue the chain."""

    async def __call__(
        self,
        agent_ctx: Any,
        tool_name: str,
        kwargs: dict[str, Any],
        call_next: Callable[[], Any],
    ) -> Any: ...


class MiddlewareChain:
    """Composes a list of ToolCallMiddleware into a single callable chain."""

    def __init__(self, middleware: list[ToolCallMiddleware]) -> None:
        self._middleware = middleware

    def wrap(self, tool_name: str, handler: Callable, agent_ctx: Any) -> Callable:
        """Return a new async callable that runs handler through all middleware."""

        async def call_with_middleware(**kwargs: Any) -> Any:
            # List order: index 0 is the outermost wrapper (first in, first wrapped).
            # Do NOT reverse — reversed() here would invert the documented execution order.
            chain = self._middleware

            async def _run(idx: int) -> Any:
                if idx >= len(chain):
                    return await handler(**kwargs)
                mw = chain[idx]
                # Pass a copy so middleware mutations don't propagate through the chain.
                # The handler always uses the original kwargs from the outer closure.
                return await mw(
                    agent_ctx=agent_ctx,
                    tool_name=tool_name,
                    kwargs=dict(kwargs),
                    call_next=lambda: _run(idx + 1),
                )

            return await _run(0)

        call_with_middleware.__name__ = handler.__name__
        return call_with_middleware
