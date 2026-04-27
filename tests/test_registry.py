"""Tests for registry.py — module discovery, mode filtering, manifest enforcement."""

from __future__ import annotations

from typing import ClassVar

import pytest

from scoped_mcp.exceptions import ManifestError
from scoped_mcp.identity import AgentContext
from scoped_mcp.manifest import Manifest, ModuleConfig
from scoped_mcp.modules._base import ToolModule, tool
from scoped_mcp.registry import _discover_module_classes, build_server

# ── Module discovery ──────────────────────────────────────────────────────────


def test_discover_finds_builtin_modules() -> None:
    """After Phase 2+ adds real modules, this number will grow."""
    discovered = _discover_module_classes()
    # In Phase 1, no tool modules exist yet — this verifies discovery runs without error.
    assert isinstance(discovered, dict)


# ── build_server rejects unknown modules ──────────────────────────────────────


def test_build_server_unknown_module_raises(agent_ctx: AgentContext) -> None:
    manifest = Manifest(
        agent_type="test",
        modules={"nonexistent_module": ModuleConfig(mode="read")},
    )
    with pytest.raises(ManifestError, match="nonexistent_module"):
        build_server(agent_ctx, manifest)


# ── ToolModule.get_tool_methods mode filtering ────────────────────────────────


class _MockModule(ToolModule):
    name = "_test_mock"
    scoping = None
    required_credentials: ClassVar[list[str]] = []

    @tool(mode="read")
    async def read_thing(self) -> str:
        return "read"

    @tool(mode="write")
    async def write_thing(self) -> str:
        return "write"


def _make_mock(agent_ctx: AgentContext) -> _MockModule:
    return _MockModule(agent_ctx=agent_ctx, credentials={}, config={})


def test_get_tool_methods_read_mode(agent_ctx: AgentContext) -> None:
    mod = _make_mock(agent_ctx)
    methods = mod.get_tool_methods("read")
    names = [m.__name__ for m in methods]
    assert "read_thing" in names
    assert "write_thing" not in names


def test_get_tool_methods_write_mode(agent_ctx: AgentContext) -> None:
    mod = _make_mock(agent_ctx)
    methods = mod.get_tool_methods("write")
    names = [m.__name__ for m in methods]
    assert "read_thing" in names
    assert "write_thing" in names


def test_get_tool_methods_none_mode(agent_ctx: AgentContext) -> None:
    mod = _make_mock(agent_ctx)
    methods = mod.get_tool_methods(None)
    names = [m.__name__ for m in methods]
    assert "read_thing" in names
    assert "write_thing" in names


# ── type: field dispatch tests ────────────────────────────────────────────────


from unittest.mock import MagicMock, patch  # noqa: E402


def _mock_module_cls():
    """Return a mock module class whose instances report no tools."""
    mock_cls = MagicMock()
    mock_cls.required_credentials = []
    mock_cls.optional_credentials = []
    mock_instance = mock_cls.return_value
    mock_instance.get_tool_methods.return_value = []
    return mock_cls


def test_type_field_dispatches_to_correct_class(agent_ctx: AgentContext) -> None:
    """Manifest key 'task-queue' with type: mcp_proxy instantiates the mcp_proxy class."""
    mock_cls = _mock_module_cls()

    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {
                "task-queue": {"type": "mcp_proxy", "config": {"url": "http://localhost/mcp"}}
            },
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes", return_value={"mcp_proxy": mock_cls}
    ):
        build_server(agent_ctx, manifest)

    mock_cls.assert_called_once()
    call_kwargs = mock_cls.call_args.kwargs
    assert call_kwargs["agent_ctx"] is agent_ctx


def test_unknown_type_raises_manifest_error(agent_ctx: AgentContext) -> None:
    """Registry raises ManifestError when type: references an unknown module class."""
    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {"thing": {"type": "nonexistent_module"}},
        }
    )

    with patch("scoped_mcp.registry._discover_module_classes", return_value={}):
        with pytest.raises(ManifestError, match="nonexistent_module"):
            build_server(agent_ctx, manifest)


def test_type_field_none_uses_key_name(agent_ctx: AgentContext) -> None:
    """When type is absent, the manifest key itself is used as the class name."""
    mock_matrix_cls = _mock_module_cls()

    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {"matrix": {"config": {"allowed_rooms": ["!abc:test"]}}},
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value={"matrix": mock_matrix_cls},
    ):
        build_server(agent_ctx, manifest)

    mock_matrix_cls.assert_called_once()


# ── Lifespan wiring tests ─────────────────────────────────────────────────────


from unittest.mock import AsyncMock  # noqa: E402

from scoped_mcp.registry import _make_module_lifespan  # noqa: E402


@pytest.mark.asyncio
async def test_registry_lifespan_calls_startup_on_all_modules(agent_ctx: AgentContext) -> None:
    """Registry lifespan calls startup() on each loaded module after server starts."""
    mock_instance = MagicMock()
    mock_instance.name = "matrix"
    mock_instance.startup = AsyncMock()
    mock_instance.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([mock_instance])
    async with lifespan(server=None):
        mock_instance.startup.assert_awaited_once()


@pytest.mark.asyncio
async def test_registry_lifespan_calls_shutdown_in_reverse(agent_ctx: AgentContext) -> None:
    """Registry lifespan calls shutdown() on modules in reverse manifest order."""
    call_order: list[str] = []

    mock_a = MagicMock()
    mock_a.name = "mod_a"
    mock_a.startup = AsyncMock()
    mock_a.shutdown = AsyncMock(side_effect=lambda: call_order.append("a"))

    mock_b = MagicMock()
    mock_b.name = "mod_b"
    mock_b.startup = AsyncMock()
    mock_b.shutdown = AsyncMock(side_effect=lambda: call_order.append("b"))

    lifespan = _make_module_lifespan([mock_a, mock_b])
    async with lifespan(server=None):
        pass  # triggers shutdown on exit

    assert call_order == ["b", "a"]
