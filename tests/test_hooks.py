"""Tests for hooks.py — pre-call hook registry."""

from __future__ import annotations

import pytest

from scoped_mcp.hooks import clear_hooks, register_before, run_before_hooks


@pytest.fixture(autouse=True)
def _reset_hooks():
    clear_hooks()
    yield
    clear_hooks()


@pytest.mark.asyncio
async def test_no_hooks_returns_kwargs_unchanged() -> None:
    kwargs = {"a": 1, "b": "hello"}
    result = await run_before_hooks("some-server", "some_tool", kwargs)
    assert result == {"a": 1, "b": "hello"}


@pytest.mark.asyncio
async def test_hook_can_modify_kwargs() -> None:
    async def add_field(kwargs: dict) -> dict:
        return {**kwargs, "injected": True}

    register_before("agent-bus", "log_event", add_field)
    result = await run_before_hooks("agent-bus", "log_event", {"x": 1})
    assert result["injected"] is True
    assert result["x"] == 1


@pytest.mark.asyncio
async def test_hook_only_fires_for_matching_server_tool() -> None:
    called = []

    async def hook(kwargs: dict) -> dict:
        called.append(True)
        return kwargs

    register_before("agent-bus", "log_event", hook)
    await run_before_hooks("agent-bus", "query_events", {"x": 1})  # different tool
    await run_before_hooks("other-server", "log_event", {"x": 1})  # different server
    assert not called


@pytest.mark.asyncio
async def test_multiple_hooks_chain_in_order() -> None:
    async def hook1(kwargs: dict) -> dict:
        return {**kwargs, "step": [*kwargs.get("step", []), 1]}

    async def hook2(kwargs: dict) -> dict:
        return {**kwargs, "step": [*kwargs.get("step", []), 2]}

    register_before("bus", "tool", hook1)
    register_before("bus", "tool", hook2)
    result = await run_before_hooks("bus", "tool", {})
    assert result["step"] == [1, 2]


@pytest.mark.asyncio
async def test_hook_exception_propagates() -> None:
    async def bad_hook(kwargs: dict) -> dict:
        raise ValueError("hook failure")

    register_before("bus", "tool", bad_hook)
    with pytest.raises(ValueError, match="hook failure"):
        await run_before_hooks("bus", "tool", {})
