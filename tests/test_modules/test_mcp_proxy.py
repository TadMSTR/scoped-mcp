"""Tests for modules/mcp_proxy.py — discovery, allowlist, denylist, forwarding."""

from __future__ import annotations

from dataclasses import dataclass
from unittest.mock import AsyncMock, patch

import pytest
from mcp.types import Tool

from scoped_mcp.identity import AgentContext
from scoped_mcp.modules.mcp_proxy import McpProxyModule


def _make_tool(name: str) -> Tool:
    """Build a real mcp.types.Tool — MagicMock(name=t) does NOT set .name."""
    return Tool(name=name, description="", inputSchema={})


@dataclass
class FakeCallToolResult:
    """Minimal stand-in for fastmcp CallToolResult."""

    data: object
    content: list
    structured_content: object = None
    meta: object = None
    is_error: bool = False


@pytest.fixture
def agent_ctx() -> AgentContext:
    return AgentContext(agent_id="test-agent", agent_type="test")


@pytest.fixture
def http_module(agent_ctx):
    """McpProxyModule (HTTP transport) created in sync context.

    McpProxyModule.__init__ calls asyncio.run() for tool discovery.
    That must happen outside a running event loop — i.e. in a sync
    fixture, not inside an async test body.
    """
    fake_result = FakeCallToolResult(data={"task_id": "abc"}, content=[])
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool("submit_task")])
        mock_cm.call_tool = AsyncMock(return_value=fake_result)
        MockClient.return_value = mock_cm
        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp"},
        )
        yield mod, mock_cm


def test_requires_url_or_command(agent_ctx):
    with pytest.raises(ValueError, match="requires either"):
        McpProxyModule(agent_ctx=agent_ctx, credentials={}, config={})


def test_rejects_both_url_and_command(agent_ctx):
    with pytest.raises(ValueError, match="not both"):
        McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://localhost:8485/mcp", "command": "python3"},
        )


def test_discovers_tools_from_upstream(agent_ctx):
    """All tools discovered from upstream are registered when no filters set."""
    tool_names = ["submit_task", "get_task", "list_tasks"]
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool(t) for t in tool_names])
        MockClient.return_value = mock_cm

        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp"},
        )

    methods = mod.get_tool_methods(mode=None)
    assert len(methods) == 3
    assert {m.__name__ for m in methods} == set(tool_names)


def test_tool_allowlist_filters_upstream(agent_ctx):
    """Only allowlisted tools are exposed."""
    tool_names = ["submit_task", "get_task", "list_tasks", "update_task"]
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool(t) for t in tool_names])
        MockClient.return_value = mock_cm

        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={
                "url": "http://127.0.0.1:8485/mcp",
                "tool_allowlist": ["submit_task", "get_task"],
            },
        )

    methods = mod.get_tool_methods(mode=None)
    assert len(methods) == 2
    assert {m.__name__ for m in methods} == {"submit_task", "get_task"}


def test_tool_denylist_filters_upstream(agent_ctx):
    """Denylisted tools are not exposed."""
    tool_names = ["submit_task", "get_task", "delete_task"]
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool(t) for t in tool_names])
        MockClient.return_value = mock_cm

        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={
                "url": "http://127.0.0.1:8485/mcp",
                "tool_denylist": ["delete_task"],
            },
        )

    methods = mod.get_tool_methods(mode=None)
    assert len(methods) == 2
    assert "delete_task" not in {m.__name__ for m in methods}


@pytest.mark.asyncio
async def test_proxy_method_forwards_to_upstream(http_module):
    """proxy_call invokes client.call_tool with correct name and args; returns .data."""
    mod, mock_cm = http_module
    methods = mod.get_tool_methods(mode=None)
    result = await methods[0](description="do a thing")

    mock_cm.call_tool.assert_called_once_with(
        "submit_task", arguments={"description": "do a thing"}
    )
    assert result == {"task_id": "abc"}


def test_proxy_callable_has_agent_ctx_self(agent_ctx):
    """proxy_call.__self__ is set so @audited can find agent_ctx."""
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool("get_task")])
        MockClient.return_value = mock_cm

        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp"},
        )

    methods = mod.get_tool_methods(mode=None)
    assert getattr(methods[0], "__self__", None) is mod
    assert mod.agent_ctx is agent_ctx


def test_get_tool_methods_ignores_mode(agent_ctx):
    """mode parameter is ignored — all discovered tools returned regardless."""
    tool_names = ["read_thing", "write_thing"]
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool(t) for t in tool_names])
        MockClient.return_value = mock_cm

        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp"},
        )

    assert len(mod.get_tool_methods(mode="read")) == 2
    assert len(mod.get_tool_methods(mode="write")) == 2
    assert len(mod.get_tool_methods(mode=None)) == 2


def test_tool_name_sanitization(agent_ctx):
    """Upstream names with hyphens, dots, or leading digits produce valid identifiers."""
    tool_names = ["log-event", "get.task", "2bad-name"]
    expected = {"log_event", "get_task", "tool_2bad_name"}
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool(t) for t in tool_names])
        MockClient.return_value = mock_cm

        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp"},
        )

    assert {m.__name__ for m in mod.get_tool_methods(mode=None)} == expected


def test_colliding_sanitized_names_raises(agent_ctx):
    """Two upstream tool names that normalize to the same identifier raise ValueError."""
    # "log-event" and "log_event" both normalize to "log_event"
    tool_names = ["log-event", "log_event"]
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool(t) for t in tool_names])
        MockClient.return_value = mock_cm

        with pytest.raises(ValueError, match="collides with an earlier tool"):
            McpProxyModule(
                agent_ctx=agent_ctx,
                credentials={},
                config={"url": "http://127.0.0.1:8485/mcp"},
            )


def test_discovery_timeout_config(agent_ctx):
    """discovery_timeout_seconds is read from config and stored."""
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[])
        MockClient.return_value = mock_cm

        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp", "discovery_timeout_seconds": 30.0},
        )

    assert mod._discovery_timeout == 30.0


def test_discovery_timeout_default(agent_ctx):
    """discovery_timeout_seconds defaults to 10.0 when not set."""
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[])
        MockClient.return_value = mock_cm

        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp"},
        )

    assert mod._discovery_timeout == 10.0


# ── Persistent stdio tests ────────────────────────────────────────────────────


@pytest.fixture
def stdio_module(agent_ctx):
    """McpProxyModule (stdio transport) created in sync context.

    Module is created with Client patched for discovery. startup() is NOT
    called here — tests call it explicitly with their own mock setup.
    """
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool("log_event")])
        MockClient.return_value = mock_cm
        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"command": "/path/to/python3", "args": ["/path/to/server.py"]},
        )
        yield mod


@pytest.mark.asyncio
async def test_stdio_startup_opens_persistent_client(stdio_module):
    """startup() opens a persistent Client for stdio transport."""
    mock_persistent = AsyncMock()
    mock_persistent.__aenter__ = AsyncMock(return_value=mock_persistent)
    mock_persistent.__aexit__ = AsyncMock(return_value=None)

    with patch("scoped_mcp.modules.mcp_proxy.Client", return_value=mock_persistent):
        await stdio_module.startup()

    assert stdio_module._persistent_client is mock_persistent
    mock_persistent.__aenter__.assert_called_once()


@pytest.mark.asyncio
async def test_http_startup_does_not_open_persistent_client(http_module):
    """startup() is a no-op for HTTP transport — HTTP reconnects per-call."""
    mod, _ = http_module
    await mod.startup()
    assert mod._persistent_client is None


@pytest.mark.asyncio
async def test_stdio_proxy_call_uses_persistent_client(stdio_module):
    """Tool calls on stdio module use _persistent_client; no new subprocess spawned."""
    fake_result = FakeCallToolResult(data={"ok": True}, content=[])
    mock_persistent = AsyncMock()
    mock_persistent.__aenter__ = AsyncMock(return_value=mock_persistent)
    mock_persistent.__aexit__ = AsyncMock(return_value=None)
    mock_persistent.call_tool = AsyncMock(return_value=fake_result)

    with patch("scoped_mcp.modules.mcp_proxy.Client", return_value=mock_persistent) as MockClient:
        await stdio_module.startup()
        MockClient.reset_mock()
        methods = stdio_module.get_tool_methods(mode=None)
        result = await methods[0]()

    MockClient.assert_not_called()
    mock_persistent.call_tool.assert_called_once_with("log_event", arguments={})
    assert result == {"ok": True}


@pytest.mark.asyncio
async def test_shutdown_closes_persistent_client(stdio_module):
    """shutdown() calls __aexit__ on the persistent client and clears the reference."""
    mock_persistent = AsyncMock()
    mock_persistent.__aenter__ = AsyncMock(return_value=mock_persistent)
    mock_persistent.__aexit__ = AsyncMock(return_value=None)

    with patch("scoped_mcp.modules.mcp_proxy.Client", return_value=mock_persistent):
        await stdio_module.startup()
        await stdio_module.shutdown()

    mock_persistent.__aexit__.assert_called_once_with(None, None, None)
    assert stdio_module._persistent_client is None
    assert stdio_module._client_handle is None
