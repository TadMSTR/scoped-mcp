"""Rate limiting middleware for scoped-mcp.

Enforces per-agent, per-tool sliding window rate limits configured in the manifest.
Limits are evaluated against a StateBackend (InProcessBackend by default, DragonflyBackend
when state_backend.type is 'dragonfly').

Manifest config:
    rate_limits:
      global: 200/minute          # all tools combined for this agent
      per_tool:
        filesystem.write_file: 20/minute
        http_proxy.request: 50/minute
        mcp_proxy.*: 100/minute   # glob patterns supported

Auto-registered when rate_limits is present in the manifest (no manual wiring needed).
"""

from __future__ import annotations

import fnmatch
from collections.abc import Callable
from typing import Any

import structlog

from ..state import StateBackend, _sanitize_key_component

logger = structlog.get_logger("audit")

_UNIT_SECONDS = {
    "second": 1,
    "minute": 60,
    "hour": 3600,
}


def _parse_rate(spec: str) -> tuple[int, int]:
    """Parse '<N>/<unit>' → (limit, window_seconds). Raises ValueError on bad format."""
    try:
        n_str, unit = spec.split("/", 1)
        limit = int(n_str)
        window = _UNIT_SECONDS[unit]
        return limit, window
    except (ValueError, KeyError) as e:
        raise ValueError(
            f"Invalid rate limit spec {spec!r}: expected '<N>/second|minute|hour'"
        ) from e


class RateLimitMiddleware:
    """ToolCallMiddleware that enforces sliding window rate limits.

    Evaluates global limit first, then the most specific per_tool match.
    On limit exceeded: rejects the call and writes a warning to the audit log.
    """

    def __init__(
        self,
        state: StateBackend,
        agent_id: str,
        global_limit: str | None = None,
        per_tool: dict[str, str] | None = None,
    ) -> None:
        self._state = state
        self._agent_id = agent_id
        self._global_limit = _parse_rate(global_limit) if global_limit else None
        # Preserve insertion order — first match wins for glob patterns
        self._per_tool: list[tuple[str, int, int]] = []
        for pattern, spec in (per_tool or {}).items():
            lim, win = _parse_rate(spec)
            self._per_tool.append((pattern, lim, win))

    def _global_key(self) -> str:
        return "rate:global"

    def _match_per_tool(self, tool_name: str) -> tuple[str, int, int] | None:
        """Return (counter_key, limit, window_seconds) for the first matching per_tool pattern.

        The counter key is derived from the PATTERN, not the individual tool name, so that
        glob patterns like 'mcp_proxy.*' share a single sliding window across all matching tools.
        """
        for pattern, lim, win in self._per_tool:
            if fnmatch.fnmatch(tool_name, pattern):
                # Use sanitized pattern as key so all tools matching the pattern share a counter
                return f"rate:{_sanitize_key_component(pattern)}", lim, win
        return None

    async def __call__(
        self,
        agent_ctx: Any,
        tool_name: str,
        kwargs: dict[str, Any],
        call_next: Callable[[], Any],
    ) -> Any:
        # Check global limit first
        if self._global_limit is not None:
            lim, win = self._global_limit
            allowed, count = await self._state.increment(self._global_key(), win, lim)
            if not allowed:
                logger.warning(
                    "rate_limit_exceeded",
                    agent_id=self._agent_id,
                    tool_name=tool_name,
                    limit_type="global",
                    current_count=count,
                    limit=lim,
                    window_seconds=win,
                )
                from ..exceptions import ConfigError

                raise ConfigError(
                    f"Rate limit exceeded for agent '{self._agent_id}': "
                    f"global limit {lim}/{win}s, current={count}"
                )

        # Check per-tool limit
        per_tool_match = self._match_per_tool(tool_name)
        if per_tool_match is not None:
            counter_key, lim, win = per_tool_match
            allowed, count = await self._state.increment(counter_key, win, lim)
            if not allowed:
                logger.warning(
                    "rate_limit_exceeded",
                    agent_id=self._agent_id,
                    tool_name=tool_name,
                    limit_type="per_tool",
                    current_count=count,
                    limit=lim,
                    window_seconds=win,
                )
                from ..exceptions import ConfigError

                raise ConfigError(
                    f"Rate limit exceeded for tool '{tool_name}' on agent '{self._agent_id}': "
                    f"limit {lim}/{win}s, current={count}"
                )

        return await call_next()
