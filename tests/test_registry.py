"""Tests for registry.py — module discovery, mode filtering, manifest enforcement."""

from __future__ import annotations

import asyncio
import json
from typing import ClassVar

import pytest

from scoped_mcp.exceptions import ManifestError
from scoped_mcp.identity import AgentContext
from scoped_mcp.manifest import Manifest, ModuleConfig
from scoped_mcp.modules._base import ToolModule, tool
from scoped_mcp.registry import (
    _discover_module_classes,
    _register_signing_hook_if_available,
    build_server,
)

# ── Module discovery ──────────────────────────────────────────────────────────


def test_discover_finds_builtin_modules() -> None:
    """Discovery returns (ok, failed) tuple; both dicts."""
    discovered, failed = _discover_module_classes()
    assert isinstance(discovered, dict)
    assert isinstance(failed, dict)


def test_discover_import_failure_is_isolated() -> None:
    """A module that raises on import is recorded in failed_imports; discovery continues."""
    import importlib
    import pkgutil
    from unittest.mock import MagicMock, patch

    # Simulate one module failing to import while others succeed.
    real_iter = pkgutil.iter_modules

    def patched_iter(path):
        # Yield a fake "broken_module" entry before the real ones.
        info = MagicMock()
        info.name = "broken_module"
        yield info
        yield from real_iter(path)

    with (
        patch("scoped_mcp.registry.pkgutil.iter_modules", side_effect=patched_iter),
        patch(
            "scoped_mcp.registry.importlib.import_module",
            side_effect=lambda name: (
                (_ for _ in ()).throw(ImportError("missing dep"))
                if name.endswith("broken_module")
                else importlib.import_module(name)
            ),
        ),
    ):
        discovered, failed = _discover_module_classes()

    assert "broken_module" in failed
    assert "ImportError" in failed["broken_module"]
    # Real modules still discovered despite the failure.
    assert isinstance(discovered, dict)


# ── build_server rejects unknown modules ──────────────────────────────────────


def test_build_server_unknown_module_raises(agent_ctx: AgentContext) -> None:
    manifest = Manifest(
        agent_type="test",
        modules={"nonexistent_module": ModuleConfig(mode="read")},
    )
    with pytest.raises(ManifestError, match="nonexistent_module"):
        build_server(agent_ctx, manifest)


def test_build_server_import_failed_module_is_excluded(agent_ctx: AgentContext) -> None:
    """A manifest module whose file failed to import is excluded, not a ManifestError.

    The server still builds with the remaining (successfully imported) modules.
    """
    from unittest.mock import patch

    good_cls = _mock_module_cls()

    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {
                "good-module": {"type": "good", "config": {}},
                "bad-module": {"type": "bad", "config": {}},
            },
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"good": good_cls}, {"bad": "ImportError: no module named 'bad_dep'"}),
    ):
        build_server(agent_ctx, manifest)  # must not raise

    good_cls.assert_called_once()


@pytest.mark.asyncio
async def test_build_server_import_failed_module_absent_from_tools(
    agent_ctx: AgentContext,
) -> None:
    """A module that failed to import has no tools registered; scoped_mcp_status is present."""
    from unittest.mock import patch

    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {
                "bad-module": {"type": "bad", "config": {}},
            },
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({}, {"bad": "ImportError: missing dep"}),
    ):
        server = build_server(agent_ctx, manifest)

    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    assert "scoped_mcp_status" in tool_names
    assert not any(n.startswith("bad-module_") for n in tool_names)


def test_build_server_init_failure_is_isolated(agent_ctx: AgentContext) -> None:
    """Module __init__ raising is caught; the server builds with remaining modules."""
    from unittest.mock import MagicMock, patch

    good_cls = _mock_module_cls()

    bad_cls = MagicMock()
    bad_cls.required_credentials = []
    bad_cls.optional_credentials = []
    bad_cls.side_effect = ValueError("missing required config field")

    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {
                "good-module": {"type": "good", "config": {}},
                "bad-module": {"type": "bad", "config": {}},
            },
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"good": good_cls, "bad": bad_cls}, {}),
    ):
        build_server(agent_ctx, manifest)  # must not raise

    good_cls.assert_called_once()
    bad_cls.assert_called_once()  # was called but raised


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


from unittest.mock import MagicMock, patch


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
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"mcp_proxy": mock_cls}, {}),
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

    with patch("scoped_mcp.registry._discover_module_classes", return_value=({}, {})):
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
        return_value=({"matrix": mock_matrix_cls}, {}),
    ):
        build_server(agent_ctx, manifest)

    mock_matrix_cls.assert_called_once()


# ── Lifespan wiring tests ─────────────────────────────────────────────────────


from unittest.mock import AsyncMock

from scoped_mcp.registry import _make_module_lifespan


@pytest.mark.asyncio
async def test_registry_lifespan_calls_startup_on_all_modules(agent_ctx: AgentContext) -> None:
    """Registry lifespan calls startup() on each loaded module after server starts."""
    mock_instance = MagicMock()
    mock_instance.name = "matrix"
    mock_instance.startup = AsyncMock()
    mock_instance.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([("matrix", mock_instance)])
    async with lifespan(server=None):
        mock_instance.startup.assert_awaited_once()


@pytest.mark.asyncio
async def test_registry_lifespan_calls_shutdown_in_reverse(agent_ctx: AgentContext) -> None:
    """Registry lifespan calls shutdown() on modules in reverse manifest order."""
    call_order: list[str] = []

    mock_a = MagicMock()
    mock_a.startup = AsyncMock()
    mock_a.shutdown = AsyncMock(side_effect=lambda: call_order.append("a"))

    mock_b = MagicMock()
    mock_b.startup = AsyncMock()
    mock_b.shutdown = AsyncMock(side_effect=lambda: call_order.append("b"))

    lifespan = _make_module_lifespan([("mod_a", mock_a), ("mod_b", mock_b)])
    async with lifespan(server=None):
        pass

    assert call_order == ["b", "a"]


@pytest.mark.asyncio
async def test_lifespan_startup_failure_is_isolated() -> None:
    """A module startup failure does not prevent the server from yielding.

    The failing module is marked failed_startup in module_health; the server yields
    normally so the working subset of tools remains available.
    """
    call_order: list[str] = []
    health = {"mod_a": {"status": "instantiated"}, "mod_b": {"status": "instantiated"}}

    mock_a = MagicMock()
    mock_a.startup = AsyncMock(side_effect=lambda: call_order.append("start_a"))
    mock_a.shutdown = AsyncMock(side_effect=lambda: call_order.append("shutdown_a"))

    mock_b = MagicMock()
    mock_b.startup = AsyncMock(side_effect=RuntimeError("startup failed"))
    mock_b.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([("mod_a", mock_a), ("mod_b", mock_b)], module_health=health)
    server_entered = False
    async with lifespan(server=None):
        server_entered = True

    assert server_entered, "server should yield even when a module fails to start"
    assert "start_a" in call_order
    assert "shutdown_a" in call_order
    assert health["mod_b"]["status"] == "failed_startup"
    assert "RuntimeError" in health["mod_b"]["error"]
    assert health["mod_a"]["status"] == "running"
    mock_b.shutdown.assert_awaited_once()


@pytest.mark.asyncio
async def test_lifespan_failed_startup_module_still_gets_shutdown() -> None:
    """A module that failed startup() still gets shutdown() called during teardown."""
    health = {"mod_a": {"status": "instantiated"}}

    mock_a = MagicMock()
    mock_a.startup = AsyncMock(side_effect=RuntimeError("startup failed"))
    mock_a.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([("mod_a", mock_a)], module_health=health)
    async with lifespan(server=None):
        pass

    assert health["mod_a"]["status"] == "failed_startup"
    mock_a.shutdown.assert_awaited_once()


@pytest.mark.asyncio
async def test_lifespan_shutdown_error_does_not_skip_remaining() -> None:
    """If mod.shutdown() raises, remaining modules still get shutdown()."""
    call_order: list[str] = []

    mock_a = MagicMock()
    mock_a.startup = AsyncMock()
    mock_a.shutdown = AsyncMock(side_effect=lambda: call_order.append("shutdown_a"))

    mock_b = MagicMock()
    mock_b.startup = AsyncMock()
    mock_b.shutdown = AsyncMock(side_effect=RuntimeError("shutdown failed"))

    # mod_b is reversed-first (index 1 shuts down before index 0)
    lifespan = _make_module_lifespan([("mod_a", mock_a), ("mod_b", mock_b)])
    async with lifespan(server=None):
        pass

    # mod_a shutdown must still run despite mod_b raising
    assert "shutdown_a" in call_order


@pytest.mark.asyncio
async def test_lifespan_starts_modules_concurrently() -> None:
    """All modules start in parallel — total elapsed ≈ one sleep unit, not N units."""
    import time

    N = 4
    SLEEP = 0.05  # 50ms; serial would be 200ms

    async def slow_startup():
        await asyncio.sleep(SLEEP)

    module_pairs = []
    for i in range(N):
        m = MagicMock()
        m.startup = slow_startup
        m.shutdown = AsyncMock()
        module_pairs.append((f"mod_{i}", m))

    lifespan = _make_module_lifespan(module_pairs)
    t0 = time.monotonic()
    async with lifespan(server=None):
        pass
    elapsed = time.monotonic() - t0

    assert elapsed < SLEEP * 2, (
        f"startup took {elapsed:.3f}s — expected < {SLEEP * 2:.3f}s "
        f"for parallel startup of {N} modules x {SLEEP}s each"
    )


@pytest.mark.asyncio
async def test_lifespan_parallel_startup_failure_cleans_up_started_modules() -> None:
    """Startup failure is isolated; modules that completed startup concurrently get shutdown()."""
    call_order: list[str] = []
    mod_a_ready = asyncio.Event()
    health = {"mod_a": {"status": "instantiated"}, "mod_b": {"status": "instantiated"}}

    mock_a = MagicMock()

    async def a_startup():
        call_order.append("start_a")
        mod_a_ready.set()

    mock_a.startup = a_startup
    mock_a.shutdown = AsyncMock(side_effect=lambda: call_order.append("shutdown_a"))

    mock_b = MagicMock()

    async def b_startup():
        await mod_a_ready.wait()  # yield until mod_a has started
        raise RuntimeError("b startup failed")

    mock_b.startup = b_startup
    mock_b.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([("mod_a", mock_a), ("mod_b", mock_b)], module_health=health)
    server_entered = False
    async with lifespan(server=None):
        server_entered = True

    assert server_entered
    assert "start_a" in call_order
    assert "shutdown_a" in call_order
    assert health["mod_b"]["status"] == "failed_startup"
    assert health["mod_a"]["status"] == "running"
    mock_b.shutdown.assert_awaited_once()


@pytest.mark.asyncio
async def test_lifespan_updates_health_on_successful_startup() -> None:
    """Successful startup transitions module health from 'instantiated' to 'running'."""
    health = {"mod_a": {"status": "instantiated"}, "mod_b": {"status": "instantiated"}}

    mock_a = MagicMock()
    mock_a.startup = AsyncMock()
    mock_a.shutdown = AsyncMock()

    mock_b = MagicMock()
    mock_b.startup = AsyncMock()
    mock_b.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([("mod_a", mock_a), ("mod_b", mock_b)], module_health=health)
    async with lifespan(server=None):
        pass

    assert health["mod_a"]["status"] == "running"
    assert health["mod_b"]["status"] == "running"


@pytest.mark.asyncio
async def test_health_file_written_via_env_var(tmp_path, monkeypatch) -> None:
    """SCOPED_MCP_HEALTH_FILE receives a JSON health report after startup completes."""
    health_path = tmp_path / "health.json"
    monkeypatch.setenv("SCOPED_MCP_HEALTH_FILE", str(health_path))

    health = {
        "good-mod": {"status": "instantiated"},
        "bad-mod": {"status": "failed_import", "error": "ImportError: missing"},
    }

    mock_good = MagicMock()
    mock_good.startup = AsyncMock()
    mock_good.shutdown = AsyncMock()

    lifespan = _make_module_lifespan([("good-mod", mock_good)], module_health=health)
    async with lifespan(server=None):
        pass

    assert health_path.exists()
    data = json.loads(health_path.read_text())
    assert data["total_count"] == 2
    assert data["failed_count"] == 1
    assert data["healthy"] is False
    assert data["modules"]["good-mod"]["status"] == "running"
    assert data["modules"]["bad-mod"]["status"] == "failed_import"


# ── scoped_mcp_status built-in tool ──────────────────────────────────────────


@pytest.mark.asyncio
async def test_scoped_mcp_status_tool_always_present(agent_ctx: AgentContext) -> None:
    """scoped_mcp_status appears in the tool list regardless of which modules loaded."""
    mock_cls = _mock_module_cls()

    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {"my-mod": {"type": "mock", "config": {}}},
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"mock": mock_cls}, {}),
    ):
        server = build_server(agent_ctx, manifest)

    tools = await server.list_tools()
    assert any(t.name == "scoped_mcp_status" for t in tools)


@pytest.mark.asyncio
async def test_scoped_mcp_status_present_even_when_all_modules_fail(
    agent_ctx: AgentContext,
) -> None:
    """scoped_mcp_status is registered even when every manifest module fails to import."""
    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {"broken": {"type": "broken", "config": {}}},
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({}, {"broken": "ImportError: no module"}),
    ):
        server = build_server(agent_ctx, manifest)

    tools = await server.list_tools()
    assert any(t.name == "scoped_mcp_status" for t in tools)


# ── _register_signing_hook_if_available ───────────────────────────────────────


def test_register_signing_hook_no_keys_does_nothing() -> None:
    from scoped_mcp.hooks import _registry, clear_hooks

    clear_hooks()
    try:
        _register_signing_hook_if_available({}, None)
        assert ("agent-bus", "log_event") not in _registry
    finally:
        clear_hooks()


def test_register_signing_hook_missing_public_key_does_nothing() -> None:
    from scoped_mcp.hooks import _registry, clear_hooks

    clear_hooks()
    try:
        _register_signing_hook_if_available({"signing_private_key": "abc"}, None)
        assert ("agent-bus", "log_event") not in _registry
    finally:
        clear_hooks()


def test_register_signing_hook_with_valid_keys_registers_hook() -> None:
    import base64

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from scoped_mcp.hooks import _registry, clear_hooks

    private_key = Ed25519PrivateKey.generate()
    priv_b64 = base64.b64encode(private_key.private_bytes_raw()).decode()
    pub_b64 = base64.b64encode(private_key.public_key().public_bytes_raw()).decode()

    clear_hooks()
    try:
        import structlog

        ops = structlog.get_logger("ops")
        _register_signing_hook_if_available(
            {"signing_private_key": priv_b64, "signing_public_key": pub_b64},
            ops,
        )
        assert len(_registry.get(("agent-bus", "log_event"), [])) == 1
    finally:
        clear_hooks()


# ── Tool name prefix regression test ─────────────────────────────────────────


@pytest.mark.asyncio
async def test_tool_names_are_single_prefixed(agent_ctx: AgentContext) -> None:
    """Tools must be registered as '{module}_{method}' — not '{module}_{module}_{method}'.

    server.mount(prefix=module_name) applies the prefix, so child.tool() must receive
    the bare method name only. Double-registration caused HITL and rate-limit patterns
    to never match on forge.
    """
    from unittest.mock import patch

    mock_cls = MagicMock()
    mock_cls.required_credentials = []
    mock_cls.optional_credentials = []

    mock_instance = _make_mock(agent_ctx)
    mock_cls.return_value = mock_instance

    manifest = Manifest.model_validate(
        {
            "agent_type": "test",
            "modules": {
                "my-module": {
                    "type": "_test_mock",
                    "mode": "read",
                    "config": {},
                }
            },
        }
    )

    with patch(
        "scoped_mcp.registry._discover_module_classes",
        return_value=({"_test_mock": type(mock_instance)}, {}),
    ):
        server = build_server(agent_ctx, manifest)

    tools = await server.list_tools()
    tool_names = [t.name for t in tools]
    # Exclude built-in tools (scoped_mcp_status has no module namespace prefix).
    module_tools = [n for n in tool_names if not n.startswith("scoped_mcp_")]
    assert module_tools, "expected at least one module tool to be registered"
    for name in module_tools:
        assert not name.startswith("my-module_my-module_"), f"double prefix detected: {name!r}"
        assert name.startswith("my-module_"), f"expected single prefix in: {name!r}"
    # The built-in status tool must be present alongside module tools.
    assert "scoped_mcp_status" in tool_names
