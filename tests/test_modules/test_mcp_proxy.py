"""Tests for modules/mcp_proxy.py — discovery, allowlist, denylist, forwarding."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastmcp.client.transports import StreamableHttpTransport
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


# ── fastmcp 3.x compatibility regression tests ───────────────────────────────


def test_stdio_transport_wraps_in_mcp_servers(agent_ctx):
    """P2: _transport() for stdio wraps command/args in mcpServers for fastmcp 3.x."""
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool("run_cmd")])
        MockClient.return_value = mock_cm

        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"command": "python3", "args": ["-m", "my_server"]},
        )

    assert mod._transport() == {
        "mcpServers": {"upstream": {"command": "python3", "args": ["-m", "my_server"]}}
    }


def test_proxy_call_has_synthesized_signature(agent_ctx):
    """P1: proxy_call gets an explicit inspect.Signature derived from inputSchema."""
    import inspect as _inspect

    schema = {
        "type": "object",
        "properties": {
            "path": {"type": "string"},
            "recursive": {"type": "boolean"},
        },
        "required": ["path"],
    }
    tool = Tool(name="list_files", description="", inputSchema=schema)

    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[tool])
        MockClient.return_value = mock_cm

        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp"},
        )

    method = mod.get_tool_methods(mode=None)[0]
    sig = method.__signature__
    assert isinstance(sig, _inspect.Signature)
    assert "path" in sig.parameters
    assert "recursive" in sig.parameters
    # required param has no default; optional has None default (not provided in schema)
    assert sig.parameters["path"].default is _inspect.Parameter.empty
    assert sig.parameters["recursive"].default is None


@pytest.fixture
def search_module(agent_ctx):
    """McpProxyModule with a schema-bearing 'search' tool — built in sync context."""
    fake_result = FakeCallToolResult(data="ok", content=[])
    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string"},
            "limit": {"type": "integer"},
        },
        "required": ["query"],
    }
    tool = Tool(name="search", description="", inputSchema=schema)
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[tool])
        mock_cm.call_tool = AsyncMock(return_value=fake_result)
        MockClient.return_value = mock_cm
        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8485/mcp"},
        )
        yield mod, mock_cm


@pytest.mark.asyncio
async def test_proxy_call_strips_none_kwargs(search_module):
    """P3: None-valued kwargs are stripped before forwarding so unprovided optional
    params are omitted rather than passed as None to the upstream tool."""
    mod, mock_cm = search_module
    method = mod.get_tool_methods(mode=None)[0]
    await method(query="hello", limit=None)

    # limit=None must be stripped; only query forwarded
    mock_cm.call_tool.assert_called_once_with("search", arguments={"query": "hello"})


# ---------------------------------------------------------------------------
# Header injection tests
# ---------------------------------------------------------------------------


def _make_http_module_with_headers(agent_ctx, headers: dict) -> McpProxyModule:
    """Helper: build McpProxyModule with headers config (sync, patched discovery)."""
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool("health_check")])
        MockClient.return_value = mock_cm
        return McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8493/mcp", "headers": headers},
        )


def test_headers_config_builds_streamable_http_transport(agent_ctx):
    """When headers are configured, _transport() returns StreamableHttpTransport."""
    mod = _make_http_module_with_headers(agent_ctx, {"Authorization": "Bearer test-token-abc"})
    transport = mod._transport()
    assert isinstance(transport, StreamableHttpTransport)
    assert transport.headers == {"Authorization": "Bearer test-token-abc"}


def test_no_headers_config_returns_url_string(agent_ctx):
    """Without headers config, _transport() returns the URL string unchanged."""
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool("health_check")])
        MockClient.return_value = mock_cm
        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"url": "http://127.0.0.1:8493/mcp"},
        )
    assert mod._transport() == "http://127.0.0.1:8493/mcp"


def test_headers_on_stdio_transport_logs_warning(agent_ctx, capsys):
    """Headers config on stdio transport emits a warning and is otherwise ignored.

    structlog emits to stdout (not stdlib logging), so we capture via capsys.
    """
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool("health_check")])
        MockClient.return_value = mock_cm
        McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={
                "command": "/usr/bin/python3",
                "headers": {"Authorization": "Bearer token"},
            },
        )
    out = capsys.readouterr().out
    assert "mcp_proxy_headers_ignored" in out


def test_multiple_headers_passed_to_transport(agent_ctx):
    """All configured headers are forwarded to StreamableHttpTransport."""
    headers = {
        "Authorization": "Bearer secret-token",
        "X-Agent-Id": "developer",
    }
    mod = _make_http_module_with_headers(agent_ctx, headers)
    transport = mod._transport()
    assert isinstance(transport, StreamableHttpTransport)


# ---------------------------------------------------------------------------
# Stdio env propagation tests (SMCP-9)
# ---------------------------------------------------------------------------


def _make_stdio_module_with_env(agent_ctx, env: dict) -> McpProxyModule:
    """Helper: build McpProxyModule with stdio transport and env config."""
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool("stack_action")])
        MockClient.return_value = mock_cm
        return McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"command": "/path/to/server", "env": env},
        )


def test_env_config_stored_on_module(agent_ctx):
    """env from config is stored in _env."""
    mod = _make_stdio_module_with_env(agent_ctx, {"DOCKHAND_ENDPOINT": "http://localhost:7777"})
    assert mod._env == {"DOCKHAND_ENDPOINT": "http://localhost:7777"}


def test_stdio_transport_includes_env_when_configured(agent_ctx):
    """_transport() includes env in the mcpServers spec when env is non-empty."""
    mod = _make_stdio_module_with_env(agent_ctx, {"DOCKHAND_ENDPOINT": "http://localhost:7777"})
    assert mod._transport() == {
        "mcpServers": {
            "upstream": {
                "command": "/path/to/server",
                "args": [],
                "env": {"DOCKHAND_ENDPOINT": "http://localhost:7777"},
            }
        }
    }


def test_stdio_transport_omits_env_when_empty(agent_ctx):
    """_transport() omits env key from mcpServers spec when env is empty."""
    mod = _make_stdio_module_with_env(agent_ctx, {})
    transport = mod._transport()
    assert "env" not in transport["mcpServers"]["upstream"]


def test_env_default_is_empty(agent_ctx):
    """McpProxyModule defaults _env to empty dict when env not in config."""
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool("run_cmd")])
        MockClient.return_value = mock_cm
        mod = McpProxyModule(
            agent_ctx=agent_ctx,
            credentials={},
            config={"command": "python3"},
        )
    assert mod._env == {}


# ---------------------------------------------------------------------------
# tool_inventory() — vikunja#517, per-module tool inventory for drift detection
# ---------------------------------------------------------------------------


def _make_module(agent_ctx, config: dict, tools: list[str]) -> McpProxyModule:
    """Helper: build an McpProxyModule with a patched upstream tool list."""
    with patch("scoped_mcp.modules.mcp_proxy.Client") as MockClient:
        mock_cm = AsyncMock()
        mock_cm.__aenter__ = AsyncMock(return_value=mock_cm)
        mock_cm.__aexit__ = AsyncMock(return_value=None)
        mock_cm.list_tools = AsyncMock(return_value=[_make_tool(t) for t in tools])
        MockClient.return_value = mock_cm
        return McpProxyModule(agent_ctx=agent_ctx, credentials={}, config=config)


def test_tool_inventory_counts_registered_tools(agent_ctx):
    """tool_count is the post-filter registered surface, not the upstream's total."""
    mod = _make_module(
        agent_ctx,
        {"url": "http://127.0.0.1:8485/mcp"},
        ["submit_task", "get_task", "list_tasks"],
    )
    inv = mod.tool_inventory()
    assert inv["tool_count"] == 3
    assert inv["transport"] == "http"
    assert inv["allowlisted"] is False
    assert inv["denylisted"] is False


def test_tool_inventory_count_reflects_allowlist(agent_ctx):
    """An allowlisted proxy reports the filtered count, and says it is filtered.

    Without the allowlisted flag a drift consumer comparing this agent against an
    unfiltered one would read the (correct) count difference as drift.
    """
    mod = _make_module(
        agent_ctx,
        {
            "url": "http://127.0.0.1:8485/mcp",
            "tool_allowlist": ["submit_task", "get_task"],
        },
        ["submit_task", "get_task", "list_tasks", "update_task"],
    )
    inv = mod.tool_inventory()
    assert inv["tool_count"] == 2
    assert inv["allowlisted"] is True
    assert inv["denylisted"] is False


def test_tool_inventory_count_reflects_denylist(agent_ctx):
    """A denylist changes the count too, so it is reported alongside the allowlist."""
    mod = _make_module(
        agent_ctx,
        {"url": "http://127.0.0.1:8485/mcp", "tool_denylist": ["delete_task"]},
        ["submit_task", "get_task", "delete_task"],
    )
    inv = mod.tool_inventory()
    assert inv["tool_count"] == 2
    assert inv["allowlisted"] is False
    assert inv["denylisted"] is True


def test_tool_inventory_reports_stdio_transport(agent_ctx):
    """stdio proxies are reported as such — their child is spawned by the parent,
    so they share its age and cannot drift. A consumer skips them on this field."""
    mod = _make_module(agent_ctx, {"command": "python3"}, ["run_cmd"])
    assert mod.tool_inventory()["transport"] == "stdio"


def test_tool_inventory_omits_names_by_default(agent_ctx):
    """The default must be name-free — /health is unauthenticated and calls it bare."""
    mod = _make_module(agent_ctx, {"url": "http://127.0.0.1:8485/mcp"}, ["submit_task", "get_task"])
    assert "tools" not in mod.tool_inventory()


def test_tool_inventory_include_names_lists_registered_tools(agent_ctx):
    """include_names lists exactly the post-filter names, sorted."""
    mod = _make_module(
        agent_ctx,
        {"url": "http://127.0.0.1:8485/mcp", "tool_denylist": ["delete_task"]},
        ["submit_task", "get_task", "delete_task"],
    )
    assert mod.tool_inventory(include_names=True)["tools"] == ["get_task", "submit_task"]


def test_tool_inventory_never_exposes_url_headers_or_schemas(agent_ctx):
    """The payload is counts, booleans, a timestamp and (opt-in) names — nothing else.

    A future field carrying the upstream URL or an Authorization header would reach
    the unauthenticated /health route; pin the key set so that is caught here.
    """
    mod = _make_module(
        agent_ctx,
        {
            "url": "http://127.0.0.1:8485/mcp",
            "headers": {"Authorization": "Bearer super-secret-token"},
        },
        ["submit_task"],
    )
    for inv in (mod.tool_inventory(), mod.tool_inventory(include_names=True)):
        assert set(inv) <= {
            "tool_count",
            "transport",
            "allowlisted",
            "denylisted",
            "discovered_at",
            "tools",
        }
        blob = json.dumps(inv)
        assert "super-secret-token" not in blob
        assert "127.0.0.1:8485" not in blob
        assert "inputSchema" not in blob


def test_tool_inventory_records_discovery_timestamp(agent_ctx):
    """discovered_at is set at discovery, not read from the clock on each call.

    It bounds how stale the exposed surface can be, and — unlike process start time —
    it moves when the self-healer re-instantiates a module.
    """
    mod = _make_module(agent_ctx, {"url": "http://127.0.0.1:8485/mcp"}, ["submit_task"])
    stamp = mod.tool_inventory()["discovered_at"]
    assert datetime.fromisoformat(stamp).tzinfo is not None
    assert mod.tool_inventory()["discovered_at"] == stamp


def test_tool_inventory_reports_normalized_names_not_raw_upstream_strings(agent_ctx):
    """A hostile upstream tool name must not reach the inventory verbatim.

    tool_inventory() lands in an agent's context via scoped_mcp_status, and that
    agent may go on to render it into Matrix or a tracker ticket — escaping belongs
    to those destinations and cannot be assumed here. The raw name is
    upstream-controlled; the registered name is [a-zA-Z0-9_]+ by construction, and
    is also the truthful answer to what this proxy registered.
    """
    hostile = "<img src=x onerror=alert(1)>\nrm -rf /"
    mod = _make_module(agent_ctx, {"url": "http://127.0.0.1:8485/mcp"}, [hostile, "submit_task"])
    names = mod.tool_inventory(include_names=True)["tools"]
    assert hostile not in names
    assert all(re.fullmatch(r"[a-zA-Z0-9_]+", n) for n in names), names
    assert "submit_task" in names


def test_tool_inventory_count_matches_the_reported_names(agent_ctx):
    """tool_count and the name list are derived from two different structures
    (_schemas, keyed by raw name; _registered_names, normalized). They are filled
    in the same loop iteration and must not drift apart."""
    mod = _make_module(
        agent_ctx,
        {"url": "http://127.0.0.1:8485/mcp", "tool_denylist": ["delete_task"]},
        ["submit_task", "get_task", "delete_task"],
    )
    inv = mod.tool_inventory(include_names=True)
    assert inv["tool_count"] == len(inv["tools"])
