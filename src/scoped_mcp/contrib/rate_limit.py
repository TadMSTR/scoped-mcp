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

from ..state import IncrementResult, StateBackend, _sanitize_key_component

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
        # The spec as written in the manifest, quoted back in a refusal.
        self._global_spec = global_limit
        # Preserve insertion order — first match wins for glob patterns
        self._per_tool: list[tuple[str, int, int, str]] = []
        for pattern, spec in (per_tool or {}).items():
            lim, win = _parse_rate(spec)
            self._per_tool.append((pattern, lim, win, spec))

    def _global_key(self) -> str:
        return "rate:global"

    def _match_per_tool(self, tool_name: str) -> tuple[str, int, int, str] | None:
        """Return (counter_key, limit, window_seconds, spec) for the first matching pattern.

        The counter key is derived from the PATTERN, not the individual tool name, so that
        glob patterns like 'mcp_proxy.*' share a single sliding window across all matching tools.
        """
        for pattern, lim, win, spec in self._per_tool:
            if fnmatch.fnmatch(tool_name, pattern):
                # Use sanitized pattern as key so all tools matching the pattern share a counter
                return f"rate:{_sanitize_key_component(pattern)}", lim, win, spec
        return None

    async def _increment(self, key: str, window: int, limit: int) -> IncrementResult:
        """increment_detailed() when the backend has it, else the 1.19 two-tuple form."""
        detailed = getattr(self._state, "increment_detailed", None)
        if detailed is not None:
            return await detailed(key, window, limit)
        allowed, count = await self._state.increment(key, window, limit)
        return IncrementResult(allowed, count)

    async def _check(
        self, tool_name: str, key: str, limit_type: str, spec: str, lim: int, win: int
    ) -> None:
        try:
            result = await self._increment(key, win, lim)
        except Exception:
            # fail-closed: backend errors block the call rather than silently bypassing limits
            logger.warning(
                "rate_limit_backend_error",
                agent_id=self._agent_id,
                tool_name=tool_name,
                limit_type=limit_type,
            )
            raise
        if result.allowed:
            return
        logger.warning(
            "rate_limit_exceeded",
            agent_id=self._agent_id,
            tool_name=tool_name,
            limit_type=limit_type,
            limit_spec=spec,
            current_count=result.count,
            limit=lim,
            window_seconds=win,
            retry_after_seconds=result.retry_after_seconds,
        )
        from ..exceptions import ConfigError

        # retry_after_seconds tells the caller when the window frees, instead of leaving
        # it to guess and retry into the same refusal (#1288 (id 1371)). The window is
        # per agent identity: every subagent and concurrent session of this agent shares
        # it, so the count includes calls this caller did not make.
        retry = (
            f", retry_after_seconds={result.retry_after_seconds}"
            if result.retry_after_seconds is not None
            else ""
        )
        if limit_type == "global":
            subject = f"agent '{self._agent_id}': global limit {spec}"
        else:
            subject = f"tool '{tool_name}' on agent '{self._agent_id}': limit {spec}"
        raise ConfigError(
            f"Rate limit exceeded for {subject} ({lim}/{win}s), current={result.count}, "
            f"limit_type={limit_type}{retry}"
        )

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
            await self._check(
                tool_name, self._global_key(), "global", self._global_spec or "", lim, win
            )

        # Check per-tool limit
        per_tool_match = self._match_per_tool(tool_name)
        if per_tool_match is not None:
            counter_key, lim, win, spec = per_tool_match
            await self._check(tool_name, counter_key, "per_tool", spec, lim, win)

        return await call_next()
