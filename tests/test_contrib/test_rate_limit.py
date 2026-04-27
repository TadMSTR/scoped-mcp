"""Tests for RateLimitMiddleware."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import pytest

from scoped_mcp.contrib.rate_limit import RateLimitMiddleware
from scoped_mcp.exceptions import ConfigError
from scoped_mcp.state import InProcessBackend


def _make_middleware(
    global_limit: str | None = None,
    per_tool: dict[str, str] | None = None,
    agent_id: str = "test-agent",
) -> RateLimitMiddleware:
    return RateLimitMiddleware(
        state=InProcessBackend(),
        agent_id=agent_id,
        global_limit=global_limit,
        per_tool=per_tool,
    )


async def _call(mw: RateLimitMiddleware, tool_name: str = "fs.read") -> Any:
    call_next = AsyncMock(return_value="result")
    result = await mw(
        agent_ctx=object(),
        tool_name=tool_name,
        kwargs={},
        call_next=call_next,
    )
    return result, call_next


# ---------------------------------------------------------------------------
# Global limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_global_limit_allows_under_limit() -> None:
    mw = _make_middleware(global_limit="3/minute")
    for _ in range(3):
        result, call_next = await _call(mw)
        assert result == "result"
        call_next.assert_called_once()


@pytest.mark.asyncio
async def test_global_limit_rejects_over_limit() -> None:
    mw = _make_middleware(global_limit="2/minute")
    await _call(mw)
    await _call(mw)
    with pytest.raises(ConfigError, match="Rate limit exceeded"):
        await _call(mw)


@pytest.mark.asyncio
async def test_global_limit_applies_across_different_tools() -> None:
    mw = _make_middleware(global_limit="2/minute")
    await _call(mw, tool_name="tool_a")
    await _call(mw, tool_name="tool_b")
    with pytest.raises(ConfigError, match="global"):
        await _call(mw, tool_name="tool_c")


# ---------------------------------------------------------------------------
# Per-tool limit
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_per_tool_limit_enforced() -> None:
    mw = _make_middleware(per_tool={"fs.write": "2/minute"})
    await _call(mw, "fs.write")
    await _call(mw, "fs.write")
    with pytest.raises(ConfigError, match="Rate limit exceeded"):
        await _call(mw, "fs.write")


@pytest.mark.asyncio
async def test_per_tool_limit_does_not_bleed_to_other_tools() -> None:
    mw = _make_middleware(per_tool={"fs.write": "1/minute"})
    await _call(mw, "fs.write")
    with pytest.raises(ConfigError):
        await _call(mw, "fs.write")

    # fs.read is unaffected
    result, _ = await _call(mw, "fs.read")
    assert result == "result"


@pytest.mark.asyncio
async def test_per_tool_glob_match() -> None:
    mw = _make_middleware(per_tool={"mcp_proxy.*": "2/minute"})
    await _call(mw, "mcp_proxy.read_file")
    await _call(mw, "mcp_proxy.write_file")
    with pytest.raises(ConfigError, match="Rate limit exceeded"):
        await _call(mw, "mcp_proxy.list_dir")


@pytest.mark.asyncio
async def test_per_tool_glob_does_not_match_other_modules() -> None:
    mw = _make_middleware(per_tool={"mcp_proxy.*": "1/minute"})
    await _call(mw, "mcp_proxy.read")
    with pytest.raises(ConfigError):
        await _call(mw, "mcp_proxy.read")

    # filesystem tools are unaffected
    result, _ = await _call(mw, "filesystem.read_file")
    assert result == "result"


# ---------------------------------------------------------------------------
# Global + per-tool combined
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_global_checked_before_per_tool() -> None:
    """Global limit fires first even when per_tool would have allowed the call."""
    mw = _make_middleware(global_limit="1/minute", per_tool={"tool": "100/minute"})
    await _call(mw, "tool")
    with pytest.raises(ConfigError, match="global"):
        await _call(mw, "tool")


# ---------------------------------------------------------------------------
# Audit log — rejection must not call call_next
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rejection_does_not_call_call_next() -> None:
    mw = _make_middleware(global_limit="1/minute")
    await _call(mw)  # allowed
    call_next = AsyncMock()
    with pytest.raises(ConfigError):
        await mw(
            agent_ctx=object(),
            tool_name="any",
            kwargs={},
            call_next=call_next,
        )
    call_next.assert_not_called()


# ---------------------------------------------------------------------------
# Audit log — audit logger receives rejection event (via structlog caplog)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_audit_log_on_rejection() -> None:
    """Verify the audit logger is called with rate_limit_exceeded on rejection."""
    from unittest.mock import patch

    mw = _make_middleware(global_limit="1/minute")
    await _call(mw)

    with patch("scoped_mcp.contrib.rate_limit.logger") as mock_log:
        with pytest.raises(ConfigError):
            await _call(mw)
        mock_log.warning.assert_called_once()
        call_kwargs = mock_log.warning.call_args
        assert call_kwargs[0][0] == "rate_limit_exceeded"


# ---------------------------------------------------------------------------
# Fail-closed: backend errors must propagate, not silently bypass limits
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_global_backend_error_is_fail_closed() -> None:
    """A broken backend must block the call (fail-closed), not silently allow it."""
    from unittest.mock import AsyncMock, patch

    mw = _make_middleware(global_limit="10/minute")
    with patch.object(mw._state, "increment", AsyncMock(side_effect=RuntimeError("conn error"))):
        with pytest.raises(RuntimeError, match="conn error"):
            await _call(mw)


@pytest.mark.asyncio
async def test_per_tool_backend_error_is_fail_closed() -> None:
    """A broken backend on the per-tool check must block the call."""
    from unittest.mock import AsyncMock, patch

    mw = _make_middleware(per_tool={"fs.read": "10/minute"})
    with patch.object(mw._state, "increment", AsyncMock(side_effect=RuntimeError("conn error"))):
        with pytest.raises(RuntimeError, match="conn error"):
            await _call(mw, tool_name="fs.read")


# ---------------------------------------------------------------------------
# Edge: invalid rate spec raises at construction
# ---------------------------------------------------------------------------


def test_invalid_rate_spec_raises() -> None:
    with pytest.raises(ValueError, match="Invalid rate limit spec"):
        _make_middleware(global_limit="100/fortnight")
