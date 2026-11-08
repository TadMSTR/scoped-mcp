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
    with patch.object(
        mw._state, "increment_detailed", AsyncMock(side_effect=RuntimeError("conn error"))
    ):
        with pytest.raises(RuntimeError, match="conn error"):
            await _call(mw)


@pytest.mark.asyncio
async def test_per_tool_backend_error_is_fail_closed() -> None:
    """A broken backend on the per-tool check must block the call."""
    from unittest.mock import AsyncMock, patch

    mw = _make_middleware(per_tool={"fs.read": "10/minute"})
    with patch.object(
        mw._state, "increment_detailed", AsyncMock(side_effect=RuntimeError("conn error"))
    ):
        with pytest.raises(RuntimeError, match="conn error"):
            await _call(mw, tool_name="fs.read")


# ---------------------------------------------------------------------------
# Edge: invalid rate spec raises at construction
# ---------------------------------------------------------------------------


def test_invalid_rate_spec_raises() -> None:
    with pytest.raises(ValueError, match="Invalid rate limit spec"):
        _make_middleware(global_limit="100/fortnight")


# ---------------------------------------------------------------------------
# retry_after_seconds on a refusal (#1288 (id 1371))
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now


@pytest.fixture()
def clock(monkeypatch: pytest.MonkeyPatch) -> _Clock:
    c = _Clock()
    monkeypatch.setattr("scoped_mcp.state.time.monotonic", c)
    return c


def _refusal(exc: pytest.ExceptionInfo) -> dict[str, str]:
    """Parse `key=value` pairs out of the refusal message."""
    import re

    return dict(re.findall(r"(\w+)=([\w./]+)", str(exc.value)))


@pytest.mark.asyncio
async def test_global_refusal_says_when_the_window_frees(clock: _Clock) -> None:
    mw = _make_middleware(global_limit="2/minute")
    await _call(mw)  # t=1000, the oldest entry
    clock.now = 1010.0
    await _call(mw)
    clock.now = 1020.4
    with pytest.raises(ConfigError) as exc:
        await _call(mw)
    detail = _refusal(exc)
    # oldest (1000) + window (60) - now (1020.4) = 39.6 -> 40
    assert detail["retry_after_seconds"] == "40"
    assert detail["limit_type"] == "global"
    assert "2/minute" in str(exc.value)


@pytest.mark.asyncio
async def test_per_tool_refusal_quotes_the_manifest_spec(clock: _Clock) -> None:
    mw = _make_middleware(per_tool={"vikunja-mcp_*": "1/minute"})
    await _call(mw, tool_name="vikunja-mcp_task_get")
    clock.now = 1059.5
    with pytest.raises(ConfigError) as exc:
        await _call(mw, tool_name="vikunja-mcp_task_list")
    detail = _refusal(exc)
    assert detail["retry_after_seconds"] == "1"  # 0.5 s left rounds up to 1
    assert detail["limit_type"] == "per_tool"
    assert "1/minute" in str(exc.value)


@pytest.mark.asyncio
async def test_retry_after_moves_with_the_clock_and_is_never_below_one(clock: _Clock) -> None:
    mw = _make_middleware(global_limit="1/minute")
    await _call(mw)
    seen = []
    for now in (1000.0, 1001.0, 1030.0, 1059.0, 1059.999):
        clock.now = now
        with pytest.raises(ConfigError) as exc:
            await _call(mw)
        seen.append(int(_refusal(exc)["retry_after_seconds"]))
    assert seen == [60, 59, 30, 1, 1]
    assert all(v >= 1 for v in seen)
    clock.now = 1060.0  # the oldest entry has aged out
    result, _ = await _call(mw)
    assert result == "result"


@pytest.mark.asyncio
async def test_refusal_log_line_carries_retry_after(clock: _Clock) -> None:
    from structlog.testing import capture_logs

    mw = _make_middleware(global_limit="1/minute")
    await _call(mw)
    with capture_logs() as logs, pytest.raises(ConfigError):
        await _call(mw)
    (line,) = [entry for entry in logs if entry["event"] == "rate_limit_exceeded"]
    assert line["retry_after_seconds"] == 60
    assert line["limit_type"] == "global"
    assert line["limit_spec"] == "1/minute"


@pytest.mark.asyncio
async def test_a_backend_without_increment_detailed_still_limits() -> None:
    """A third-party StateBackend written against 1.19 has only increment()."""

    class OldBackend:
        def __init__(self) -> None:
            self.calls = 0

        async def increment(self, key: str, window_seconds: int, limit: int) -> tuple[bool, int]:
            self.calls += 1
            return self.calls <= limit, self.calls

    mw = RateLimitMiddleware(state=OldBackend(), agent_id="a", global_limit="1/minute")
    await _call(mw)
    with pytest.raises(ConfigError) as exc:
        await _call(mw)
    assert "retry_after_seconds" not in str(exc.value)
    assert "limit_type=global" in str(exc.value)


def test_retry_after_seconds_helper_bounds() -> None:
    from scoped_mcp.state import retry_after_seconds

    assert retry_after_seconds(100.0, 60, 100.0) == 60
    assert retry_after_seconds(100.0, 60, 159.01) == 1
    assert retry_after_seconds(100.0, 60, 200.0) == 1  # clock skew past the window: still >= 1
    assert retry_after_seconds(100.0, 60, 130.5) == 30
