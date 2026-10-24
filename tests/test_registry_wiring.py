"""The registry applies the security wiring to every tool it registers (vikunja#1219).

Middleware (HITL, rate limits, argument filters) and the manifest's read/write mode are
applied in ``_register_module_tools``, which runs twice in a module's life: at startup,
and again from the self-heal retry when a module that failed to initialise recovers.
Each test here calls a tool through the server, not on the module instance.
"""

from __future__ import annotations

import asyncio
import time
from typing import Any, ClassVar
from unittest.mock import patch

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from scoped_mcp import module_selfheal, ops_alert, registry
from scoped_mcp.contrib.arg_filter import ArgumentFilterMiddleware
from scoped_mcp.identity import AgentContext
from scoped_mcp.manifest import Manifest
from scoped_mcp.modules._base import ToolModule, tool
from scoped_mcp.registry import build_server


class _WiringModule(ToolModule):
    name = "wiring"
    scoping = None
    required_credentials: ClassVar[list[str]] = []
    optional_credentials: ClassVar[list[str]] = []

    @tool(mode="read")
    async def ping(self, body: str = "") -> str:
        return "pong"

    @tool(mode="write")
    async def poke(self, body: str = "") -> str:
        return "poked"


class _RecordingMiddleware:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    async def __call__(self, agent_ctx: Any, tool_name: str, kwargs: dict, call_next: Any) -> Any:
        self.calls.append((agent_ctx.agent_id, tool_name))
        return await call_next()


def _text(result: Any) -> str:
    return result.content[0].text


def _manifest(mode: str, **module: Any) -> Manifest:
    return Manifest.model_validate(
        {
            "agent_type": "research",
            "modules": {"mod": {"type": "wiring", "mode": mode, "config": {}, **module}},
        }
    )


def _build(agent_ctx: AgentContext, manifest: Manifest, **kwargs: Any) -> Any:
    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"wiring": _WiringModule, "flaky": _FlakyModule}, {}),
    ):
        return build_server(agent_ctx, manifest, **kwargs)


def _block_filter(agent_ctx: AgentContext) -> ArgumentFilterMiddleware:
    return ArgumentFilterMiddleware(
        rules=[{"name": "no-drop", "pattern": "DROP", "fields": ["body"], "action": "block"}],
        agent_id=agent_ctx.agent_id,
    )


# ── Middleware applied at startup registration ───────────────────────────────


async def test_middleware_runs_on_every_tool_call(agent_ctx: AgentContext) -> None:
    recorder = _RecordingMiddleware()
    server = _build(agent_ctx, _manifest("write"), middleware=[recorder])

    async with Client(server) as client:
        await client.call_tool("mod_ping", {})
        await client.call_tool("mod_poke", {})

    assert recorder.calls == [("test-agent-1", "mod_ping"), ("test-agent-1", "mod_poke")]


async def test_argument_filter_blocks_through_the_server(agent_ctx: AgentContext) -> None:
    server = _build(agent_ctx, _manifest("write"), middleware=[_block_filter(agent_ctx)])

    async with Client(server) as client:
        assert _text(await client.call_tool("mod_poke", {"body": "fine"})) == "poked"
        with pytest.raises(ToolError, match="argument filter policy"):
            await client.call_tool("mod_poke", {"body": "DROP everything"})


async def test_no_middleware_leaves_tools_unwrapped(agent_ctx: AgentContext) -> None:
    recorder = _RecordingMiddleware()
    server = _build(agent_ctx, _manifest("write"), middleware=None)

    async with Client(server) as client:
        assert _text(await client.call_tool("mod_poke", {"body": "DROP"})) == "poked"

    assert recorder.calls == []


# ── Mode honoured ─────────────────────────────────────────────────────────────


async def test_read_mode_module_does_not_register_write_tools(agent_ctx: AgentContext) -> None:
    server = _build(agent_ctx, _manifest("read"))

    names = {t.name for t in await server.list_tools()}
    assert "mod_ping" in names
    assert "mod_poke" not in names

    async with Client(server) as client:
        with pytest.raises(ToolError):
            await client.call_tool("mod_poke", {})


async def test_write_mode_module_registers_both(agent_ctx: AgentContext) -> None:
    server = _build(agent_ctx, _manifest("write"))

    names = {t.name for t in await server.list_tools()}
    assert {"mod_ping", "mod_poke"} <= names


# ── Middleware and mode applied on the self-heal registration path ───────────


class _FlakyModule(_WiringModule):
    """Fails to initialise until ``healthy`` is set, then recovers via self-heal."""

    name = "flaky"
    healthy: ClassVar[bool] = False

    def __init__(self, agent_ctx: Any, credentials: dict, config: dict) -> None:
        super().__init__(agent_ctx, credentials, config)
        if not type(self).healthy:
            raise ConnectionRefusedError("dependency not up yet")


@pytest.fixture
def fast_selfheal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Test-speed backoff, alerts recorded instead of sent, and a fresh flaky flag."""
    real_cls = module_selfheal.ModuleSelfHealer

    def _fast(*args: Any, **kwargs: Any) -> Any:
        kwargs.setdefault("base_delay", 0.05)
        kwargs.setdefault("max_delay", 0.2)
        return real_cls(*args, **kwargs)

    async def _no_alert(event: str, detail: dict) -> bool:
        return True

    monkeypatch.setattr(registry, "ModuleSelfHealer", _fast)
    monkeypatch.setattr(ops_alert, "send_ops_alert", _no_alert)
    monkeypatch.setattr(_FlakyModule, "healthy", False)


def _recover(client: Any) -> None:
    _FlakyModule.healthy = True
    deadline = time.monotonic() + 15.0
    while time.monotonic() < deadline:
        if client.get("/health").status_code == 200:
            return
        time.sleep(0.05)
    pytest.fail("flaky module never recovered")


def test_selfheal_registration_applies_middleware(
    agent_ctx: AgentContext, fast_selfheal: None
) -> None:
    from starlette.testclient import TestClient

    recorder = _RecordingMiddleware()
    manifest = Manifest.model_validate(
        {
            "agent_type": "research",
            "modules": {"heal": {"type": "flaky", "mode": "write", "config": {}}},
        }
    )
    server = _build(
        agent_ctx,
        manifest,
        middleware=[recorder, _block_filter(agent_ctx)],
        transport="http",
    )

    with TestClient(server.http_app()) as client:
        _recover(client)
        result = client.portal.call(server.call_tool, "heal_poke", {"body": "fine"})
        assert _text(result) == "poked"
        with pytest.raises(Exception, match="argument filter policy"):
            client.portal.call(server.call_tool, "heal_poke", {"body": "DROP it"})

    assert recorder.calls == [("test-agent-1", "heal_poke"), ("test-agent-1", "heal_poke")]


def test_selfheal_registration_honours_read_mode(
    agent_ctx: AgentContext, fast_selfheal: None
) -> None:
    from starlette.testclient import TestClient

    manifest = Manifest.model_validate(
        {
            "agent_type": "research",
            "modules": {"heal": {"type": "flaky", "mode": "read", "config": {}}},
        }
    )
    server = _build(agent_ctx, manifest, transport="http")

    with TestClient(server.http_app()) as client:
        _recover(client)
        names = {t.name for t in client.portal.call(server.list_tools)}

    assert "heal_ping" in names
    assert "heal_poke" not in names


def test_flaky_module_really_failed_at_startup(
    agent_ctx: AgentContext, fast_selfheal: None
) -> None:
    """Guard: the self-heal tests above only prove something if the first build failed."""
    manifest = Manifest.model_validate(
        {
            "agent_type": "research",
            "modules": {"heal": {"type": "flaky", "mode": "write", "config": {}}},
        }
    )
    server = _build(agent_ctx, manifest, transport="http")

    assert not any(t.name.startswith("heal_") for t in asyncio.run(server.list_tools()))
